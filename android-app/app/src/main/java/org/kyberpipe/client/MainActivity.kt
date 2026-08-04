package org.kyberpipe.client

import android.content.Intent
import android.os.Build
import android.os.Bundle
import android.widget.Toast
import androidx.activity.ComponentActivity
import androidx.activity.compose.setContent
import androidx.activity.result.contract.ActivityResultContracts
import androidx.compose.runtime.*
import kotlinx.coroutines.*
import org.kyberpipe.client.components.*
import org.kyberpipe.client.crash.CrashLogger
import org.kyberpipe.client.deeplink.DeepLinkHandler
import org.kyberpipe.client.service.PipeService
import org.kyberpipe.client.utils.PermissionHelper
import org.kyberpipe.client.utils.SettingsManager
import org.kyberpipe.client.utils.UriUtils

class MainActivity : ComponentActivity() {

    private lateinit var settingsManager: SettingsManager
    private val mainScope = CoroutineScope(Dispatchers.Main + SupervisorJob())
    private val deepLinkData = mutableStateOf<String?>(null)
    // Audit finding #22: a warning set when the deep link lacks the expected
    // pairing token / cert pin — the UI must surface it before consuming the
    // payload.
    private val deepLinkWarning = mutableStateOf<String?>(null)

    // Image Picker Launcher
    private val pickImageLauncher = registerForActivityResult(
        ActivityResultContracts.GetContent()
    ) { uri ->
        uri?.let {
            val base64 = UriUtils.toBase64(contentResolver, it)
            settingsManager.devicePicture = base64
        }
    }

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        settingsManager = SettingsManager(this)

        CrashLogger.install(this)

        // Restore persisted crypto state across process restarts so a kill does
        // not force a full re-pair (ratchet snapshot + session-key handle).
        restorePersistedCryptoState()

        // Handle initial intent
        val result = DeepLinkHandler.parse(intent)
        if (result.valid && result.data != null) {
            deepLinkData.value = result.data
            deepLinkWarning.value = result.warning
        }

        setContent {
            var themeMode by remember { mutableStateOf(settingsManager.themeMode) }
            var amoledMode by remember { mutableStateOf(settingsManager.amoledMode) }

            KyberpipeTheme(themeMode = themeMode, amoledMode = amoledMode) {
                MainScreen(
                    settings = settingsManager,
                    initialPairingConfig = deepLinkData.value,
                    initialPairingConfigWarning = deepLinkWarning.value,
                    onClearInitialPairingConfig = {
                        deepLinkData.value = null
                        deepLinkWarning.value = null
                    },
                    onAvatarPickerClick = { pickImageLauncher.launch("image/*") },
                    onStartService = { startPipeForegroundService() },
                    onStopService = { stopPipeForegroundService() },
                    onThemeChanged = { mode, amoled ->
                        themeMode = mode
                        amoledMode = amoled
                    }
                )
            }
        }
    }

    override fun onNewIntent(intent: Intent) {
        super.onNewIntent(intent)
        val result = DeepLinkHandler.parse(intent)
        if (result.valid && result.data != null) {
            deepLinkData.value = result.data
            deepLinkWarning.value = result.warning
        }
    }

    /**
     * Restore the ratchet session (from the persisted snapshot) after a process
     * restart. The session-key handle is process-scoped (Rust memory) and the
     * legacy raw-key restore is gone (audit finding F7) — the ratchet snapshot
     * alone is enough to resume.
     *
     * AUDIT FINDING #2 (HIGH): restore is a COLD-START-ONLY, single-flight step.
     * It must never run when a live session already exists in the Rust registry
     * — after a RE-PAIR the fresh session (gen 0, new master secret) lives in
     * Rust while the persisted snapshot is from the OLD pairing; importing it
     * would revert the session to pre-pair key material (silent state rollback
     * presenting as "paired but nothing syncs"). The Rust import guard adds the
     * pairing-epoch watermark as a second line of defense, but the lifecycle
     * gate here is the primary one: on a cold start the registry is empty (the
     * snapshot is the only state), so `ratchetPeerIds()` is empty and the
     * restore proceeds; on a warm activity recreation after re-pairing the
     * registry is non-empty and the restore is skipped.
     */
    private fun restorePersistedCryptoState() {
        // Single-flight gate: never restore over a live session. On a process
        // cold start the Rust registry is empty (nothing survives a kill), so
        // this is the exact signal that distinguishes "cold start, restore the
        // snapshot" from "warm recreation, keep the live session" (audit #2).
        val livePeers = try {
            uniffi.core_crypto.ratchetPeerIds()
        } catch (e: Exception) {
            emptyList()
        }
        if (livePeers.isNotEmpty()) {
            android.util.Log.i(
                "KyberpipeRestore",
                "Ratchet restore skipped: ${livePeers.size} live session(s) in Rust registry (warm start / re-pair) — audit finding #2"
            )
            return
        }
        val peer = settingsManager.peerRatchetIdentity
        if (peer.isNotEmpty()) {
            val snapshot = settingsManager.ratchetSnapshot
            if (snapshot.isNotEmpty()) {
                try {
                    // Audit finding #13: the snapshot is wrapped at rest with an
                    // INDEPENDENT Keystore-backed key (not the session key).
                    // Stored format: Base64("{nonce_hex}:{ciphertext_hex}").
                    val wrapKeyHex = settingsManager.ratchetSnapshotKey
                    if (wrapKeyHex.isNotEmpty()) {
                        val stored =
                            android.util.Base64.decode(snapshot, android.util.Base64.NO_WRAP)
                                .toString(Charsets.UTF_8)
                        val sep = stored.indexOf(':')
                        if (sep > 0) {
                            val nonce = stored.substring(0, sep).hexToByteArraySafe()
                            val ct = stored.substring(sep + 1).hexToByteArraySafe()
                            val wrapKey = wrapKeyHex.hexToByteArraySafe()
                            if (nonce != null && ct != null && wrapKey != null) {
                                val bytes = uniffi.core_crypto.decryptWithRawKey32(
                                    wrapKey, nonce, ct
                                )
                                // AUDIT #2 (follow-up): enforce the same monotonic
                                // rollback bound the desktop store enforces. A
                                // snapshot whose watermark is STRICTLY below the
                                // recorded high-water mark (an older blob restored
                                // from a device backup, or same-user tampering) is
                                // refused — otherwise the send chain rolls back and
                                // derived message keys + nonces are reused for new
                                // plaintext. Equal = the current snapshot, accepted.
                                val snapWm = try {
                                    uniffi.core_crypto.ratchetSnapshotWatermark(bytes)
                                } catch (e: Exception) {
                                    null
                                }
                                if (snapWm != null && org.kyberpipe.client.utils.RatchetWatermarkStore.refuseRollback(
                                        snapWm,
                                        org.kyberpipe.client.utils.RatchetWatermarkStore.read(settingsManager, peer)
                                    )
                                ) {
                                    android.util.Log.w(
                                        "KyberpipeRestore",
                                        "Ratchet restore refused: snapshot watermark is below the recorded high-water mark (rollback) — audit finding #2"
                                    )
                                } else {
                                    uniffi.core_crypto.ratchetImportSession(peer, bytes)
                                    // Record the imported watermark (max with stored)
                                    // so the monotonic bound survives restarts.
                                    snapWm?.let { wm ->
                                        org.kyberpipe.client.utils.RatchetWatermarkStore.update(settingsManager, peer, wm)
                                    }
                                }
                            }
                        }
                    }
                } catch (e: Exception) {
                    android.util.Log.w("KyberpipeRestore", "Ratchet restore failed: ${e.message}")
                }
            }
        }
    }

    fun getLatestCrashLog(): String? = CrashLogger.getLatestCrashLog(this)

    fun shareTextFile(filename: String, content: String) {
        try {
            val intent = Intent(Intent.ACTION_SEND).apply {
                type = "text/plain"
                putExtra(Intent.EXTRA_TITLE, filename)
                putExtra(Intent.EXTRA_TEXT, content)
            }
            startActivity(Intent.createChooser(intent, "Export $filename"))
        } catch (e: Exception) {
            Toast.makeText(this, "Export failed: ${e.message}", Toast.LENGTH_SHORT).show()
        }
    }

    private fun requestInitialPermissions() {
        if (!PermissionHelper.isNotificationListenerEnabled(this)) {
            PermissionHelper.requestNotificationListenerPermission(this)
        }
    }

    private fun startPipeForegroundService() {
        val intent = Intent(this, PipeService::class.java)
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.O) {
            startForegroundService(intent)
        } else {
            startService(intent)
        }
    }

    private fun stopPipeForegroundService() {
        val intent = Intent(this, PipeService::class.java)
        stopService(intent)
    }

    override fun onDestroy() {
        super.onDestroy()
        mainScope.cancel()
    }
}

/** Hex string → byte array, or null on malformed input (audit finding #13). */
private fun String.hexToByteArraySafe(): ByteArray? {
    if (length % 2 != 0) return null
    return try {
        ByteArray(length / 2) { i ->
            ((Character.digit(this[i * 2], 16) shl 4) + Character.digit(this[i * 2 + 1], 16)).toByte()
        }
    } catch (e: Exception) {
        null
    }
}


