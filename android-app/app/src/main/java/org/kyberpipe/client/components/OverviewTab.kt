package org.kyberpipe.client.components

import androidx.compose.runtime.*
import androidx.compose.ui.graphics.Color
import org.kyberpipe.client.utils.SettingsManager


@Composable
fun OverviewTab(
    connectionStatus: String,
    connectionMethod: String,
    connectionColor: Color,
    ambientLux: Float,
    isPaired: Boolean,
    settings: SettingsManager,
    clipboardItems: List<AndroidClipboardRecord>,
    notificationsItems: List<AndroidNotificationRecord>,
    onRetryConnection: () -> Unit,
    onNavigateToFiles: () -> Unit,
    onNavigateToClipboard: () -> Unit,
    onNavigateToNotifications: () -> Unit,
    onNavigateToSettings: () -> Unit,
    onPairMockDevice: (String) -> Unit,
    pairingConfigInput: String = "",
    onPairingConfigChange: (String) -> Unit = {},
    onTriggerHandshake: () -> Unit = {}
) {
    var showNodeMetricsModal by remember { mutableStateOf(false) }

    if (!isPaired) {
        OverviewUnpairedSection(
            pairingConfigInput = pairingConfigInput,
            onPairingConfigChange = onPairingConfigChange,
            onTriggerHandshake = onTriggerHandshake,
            onPairMockDevice = onPairMockDevice
        )
    } else {
        OverviewPairedSection(
            connectionStatus = connectionStatus,
            connectionMethod = connectionMethod,
            connectionColor = connectionColor,
            ambientLux = ambientLux,
            isPaired = isPaired,
            clipboardItems = clipboardItems,
            notificationsItems = notificationsItems,
            onRetryConnection = onRetryConnection,
            onNavigateToFiles = onNavigateToFiles,
            onNavigateToClipboard = onNavigateToClipboard,
            onNavigateToNotifications = onNavigateToNotifications,
            onNavigateToSettings = onNavigateToSettings,
            onOpenNodeMetrics = { showNodeMetricsModal = true }
        )
    }

    // Node Metrics Full-Screen Animated Modal
    NodeMetricsModal(
        isVisible = showNodeMetricsModal,
        onDismiss = { showNodeMetricsModal = false },
        connectionStatus = connectionStatus,
        connectionMethod = connectionMethod,
        connectionColor = connectionColor,
        isPaired = isPaired
    )
}
