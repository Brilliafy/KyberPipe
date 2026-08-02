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
import org.kyberpipe.client.utils.SessionKeyManager
import org.kyberpipe.client.utils.SettingsManager
import org.kyberpipe.client.utils.UriUtils

class MainActivity : ComponentActivity() {

    private lateinit var settingsManager: SettingsManager
    private val mainScope = CoroutineScope(Dispatchers.Main + SupervisorJob())
    private val deepLinkData = mutableStateOf<String?>(null)

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
        }

        setContent {
            var themeMode by remember { mutableStateOf(settingsManager.themeMode) }
            var amoledMode by remember { mutableStateOf(settingsManager.amoledMode) }

            KyberpipeTheme(themeMode = themeMode, amoledMode = amoledMode) {
                MainScreen(
                    settings = settingsManager,
                    initialPairingConfig = deepLinkData.value,
                    onClearInitialPairingConfig = { deepLinkData.value = null },
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
        }
    }

    /**
     * Restore the ratchet session (from the persisted snapshot) and the session
     * key handle after a process restart.
     */
    private fun restorePersistedCryptoState() {
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
                                val bytes = uniffi.core_crypto.decryptPayloadWithHandle(
                                    wrapKey, nonce, ct
                                )
                                uniffi.core_crypto.ratchetImportSession(peer, bytes)
                            }
                        }
                    }
                } catch (e: Exception) {
                    android.util.Log.w("KyberpipeRestore", "Ratchet restore failed: ${e.message}")
                }
            }
        }
        val sessionKey = settingsManager.sessionKey
        if (sessionKey.isNotEmpty()) {
            try {
                SessionKeyManager.initFromHex(sessionKey)
            } catch (e: Exception) {
                android.util.Log.w("KyberpipeRestore", "Session key restore failed: ${e.message}")
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


