package org.kyberpipe.client

import android.content.Intent
import android.os.Build
import android.os.Bundle
import android.widget.Toast
import androidx.activity.compose.setContent
import androidx.activity.result.contract.ActivityResultContracts
import androidx.compose.runtime.*
import androidx.fragment.app.FragmentActivity
import kotlinx.coroutines.*
import org.kyberpipe.client.components.*
import org.kyberpipe.client.crash.CrashLogger
import org.kyberpipe.client.deeplink.DeepLinkHandler
import org.kyberpipe.client.service.PipeService
import org.kyberpipe.client.utils.PermissionHelper
import org.kyberpipe.client.utils.RatchetSessionRestorer
import org.kyberpipe.client.utils.SettingsManager
import org.kyberpipe.client.utils.UriUtils

// FragmentActivity (a ComponentActivity subclass) so the biometric step-up
// prompt (androidx.biometric) can run for the sensitive forwarding opt-ins
// (audit #14 follow-up).
class MainActivity : FragmentActivity() {

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
            // AUDIT #11: the avatar is a potentially LARGE base64 blob and
            // EncryptedSharedPreferences performs AES-GCM on the caller thread —
            // write it off the main thread so the UI never blocks on Keystore.
            mainScope.launch(Dispatchers.IO) {
                settingsManager.devicePicture = base64
            }
        }
    }

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        settingsManager = SettingsManager(this)

        CrashLogger.install(this)

        // Restore persisted crypto state across process restarts so a kill does
        // not force a full re-pair (ratchet snapshot + session-key handle).
        // AUDIT F1: the restore now lives in the lifecycle-agnostic
        // RatchetSessionRestorer, invoked here AND by the background service's
        // poll engine — a process-wide single-flight gate means whichever path
        // fires first imports the snapshot exactly once, so a reboot that never
        // opens the app still resumes sync.
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
     * AUDIT F1 (HIGH): the restore is delegated to the lifecycle-agnostic
     * [RatchetSessionRestorer] — the background service's poll engine also
     * invokes it before its first poll, so a reboot / START_STICKY restart
     * that never opens the activity still imports the AEAD-wrapped snapshot and
     * resumes sync. A process-wide single-flight gate (not registry emptiness)
     * ensures MainActivity and the service can never double-import.
     *
     * AUDIT FINDING #2 (HIGH): the restore is a COLD-START-ONLY, single-flight
     * step. It must never run when a live session already exists in the Rust
     * registry — after a RE-PAIR the fresh session (gen 0, new master secret)
     * lives in Rust while the persisted snapshot is from the OLD pairing;
     * importing it would revert the session to pre-pair key material (silent
     * state rollback presenting as "paired but nothing syncs"). The
     * live-registry check plus the pairing-epoch watermark guard both remain.
     *
     * AUDIT #11: the snapshot restore decodes Base64, AES-GCM-decrypts with
     * the Keystore-backed wrap key, parses the watermark JSON + the full
     * snapshot, then `ratchetImportSession` re-parses the whole snapshot — all
     * of it used to run on the UI thread in onCreate (cold-start jank / ANR
     * risk on low-end hardware with large snapshots + slow Keystore). It runs
     * on the IO dispatcher; the UI stays responsive and shows pairing state
     * immediately.
     */
    private fun restorePersistedCryptoState() {
        mainScope.launch(Dispatchers.IO) {
            RatchetSessionRestorer.restoreIfNeeded(settingsManager)
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


