package org.kyberpipe.client.components

import androidx.compose.foundation.layout.*
import androidx.compose.foundation.rememberScrollState
import androidx.compose.foundation.verticalScroll
import androidx.compose.material3.*
import androidx.compose.runtime.*
import androidx.compose.ui.Modifier
import androidx.compose.ui.platform.LocalContext
import androidx.compose.ui.unit.dp
import org.kyberpipe.client.utils.SettingsManager

@OptIn(ExperimentalMaterial3Api::class)
@Composable
fun SettingsTab(
    settings: SettingsManager,
    keyPairHandle: ULong?,
    pairingConfigInput: String,
    onPairingConfigChange: (String) -> Unit,
    onTriggerHandshake: () -> Unit,
    onAvatarPickerClick: () -> Unit,
    onSaveSettings: () -> Unit,
    lanActive: Boolean,
    wireguardActive: Boolean,
    onLanToggled: (Boolean) -> Unit,
    onWireguardToggled: (Boolean) -> Unit,
    localLogs: List<String> = emptyList(),
    onCopyStacktrace: () -> Unit = {},
    onExportDiagnosticLogs: () -> Unit = {},
    onExportCrashLog: () -> Unit = {},
    hasCrashLog: Boolean = false,
    onPanicTriggered: () -> Unit = {}
) {
    Column(
        modifier = Modifier
            .fillMaxSize()
            .verticalScroll(rememberScrollState())
            .padding(16.dp),
        verticalArrangement = Arrangement.spacedBy(16.dp)
    ) {
        SettingsProfileSection(
            settings = settings,
            onAvatarPickerClick = onAvatarPickerClick,
            onSaveSettings = onSaveSettings
        )
        SettingsThemeSection(
            settings = settings,
            onSaveSettings = onSaveSettings
        )
        SettingsConnectivitySection(
            settings = settings,
            lanActive = lanActive,
            wireguardActive = wireguardActive,
            onLanToggled = onLanToggled,
            onWireguardToggled = onWireguardToggled,
            onSaveSettings = onSaveSettings
        )
        SettingsPairingSection(
            settings = settings,
            pairingConfigInput = pairingConfigInput,
            onPairingConfigChange = onPairingConfigChange,
            onTriggerHandshake = onTriggerHandshake
        )
        SettingsNetworkSection(
            settings = settings,
            onSaveSettings = onSaveSettings
        )
        SettingsKeyVaultSection(keyPairHandle = keyPairHandle)
        // AUDIT #14 (follow-up): the sensitive forwarding opt-ins, gated by
        // Android Keystore biometric confirmation when ENABLED.
        SettingsForwardingSection(
            settings = settings,
            activity = LocalContext.current as androidx.fragment.app.FragmentActivity,
            onSaveSettings = onSaveSettings
        )
        SettingsLogsSection(
            localLogs = localLogs,
            onCopyStacktrace = onCopyStacktrace,
            onExportDiagnosticLogs = onExportDiagnosticLogs,
            onExportCrashLog = onExportCrashLog,
            hasCrashLog = hasCrashLog
        )
        SettingsPanicSection(onPanicTriggered = onPanicTriggered)
    }
}
