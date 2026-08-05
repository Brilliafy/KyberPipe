package org.kyberpipe.client.components

import androidx.compose.foundation.layout.*
import androidx.compose.foundation.shape.RoundedCornerShape
import androidx.compose.material3.*
import androidx.compose.runtime.*
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.unit.dp
import androidx.compose.ui.unit.sp
import org.kyberpipe.client.utils.SettingsManager

@OptIn(ExperimentalMaterial3Api::class)
@Composable
internal fun SettingsConnectivitySection(
    settings: SettingsManager,
    lanActive: Boolean,
    wireguardActive: Boolean,
    onLanToggled: (Boolean) -> Unit,
    onWireguardToggled: (Boolean) -> Unit,
    onSaveSettings: () -> Unit
) {
    val colors = MaterialTheme.colorScheme

    // Connectivity Hierarchy Card
    Card(
        colors = CardDefaults.cardColors(containerColor = colors.surface),
        shape = RoundedCornerShape(16.dp),
        modifier = Modifier.fillMaxWidth()
    ) {
        Column(modifier = Modifier.padding(16.dp)) {
            Text(
                text = "Connectivity hierarchy",
                fontSize = 15.sp,
                fontWeight = FontWeight.Bold,
                color = colors.primary
            )
            Spacer(modifier = Modifier.height(10.dp))
            Text(
                text = "Rearrange pathway priorities. Connection fallback adapts dynamically.",
                fontSize = 11.sp,
                color = colors.onSurface.copy(alpha = 0.6f)
            )
            Spacer(modifier = Modifier.height(12.dp))

            var orderList by remember(settings.pathwayOrder) {
                mutableStateOf(settings.pathwayOrder.split(",").toMutableList())
            }

            val pathwayNames = mapOf(
                "mdns_lan" to "Local Network (mDNS LAN)",
                "wireguard_wan" to "WireGuard WAN Tunnel Overlay"
            )

            val pathwayToggles = mapOf(
                "mdns_lan" to lanActive,
                "wireguard_wan" to wireguardActive
            )

            fun togglePathway(key: String, checked: Boolean) {
                val activeCount = listOf(lanActive, wireguardActive).count { it }
                if (!checked && activeCount <= 1) {
                    return
                }
                when (key) {
                    "mdns_lan" -> onLanToggled(checked)
                    "wireguard_wan" -> onWireguardToggled(checked)
                }
                onSaveSettings()
            }

            orderList.forEachIndexed { index, pathKey ->
                val isActive = pathwayToggles[pathKey] ?: false
                Card(
                    colors = CardDefaults.cardColors(
                        containerColor = if (isActive) colors.surfaceVariant else colors.surface.copy(alpha = 0.5f)
                    ),
                    shape = RoundedCornerShape(12.dp),
                    modifier = Modifier.fillMaxWidth()
                ) {
                    Row(
                        modifier = Modifier
                            .fillMaxWidth()
                            .padding(horizontal = 12.dp, vertical = 8.dp),
                        horizontalArrangement = Arrangement.SpaceBetween,
                        verticalAlignment = Alignment.CenterVertically
                    ) {
                        Column(modifier = Modifier.weight(1f)) {
                            Row(verticalAlignment = Alignment.CenterVertically) {
                                Checkbox(
                                    checked = isActive,
                                    onCheckedChange = { togglePathway(pathKey, it) },
                                    modifier = Modifier.size(24.dp)
                                )
                                Spacer(modifier = Modifier.width(6.dp))
                                Column {
                                    Text(
                                        text = "${index + 1}. ${pathwayNames[pathKey] ?: pathKey}",
                                        fontSize = 13.sp,
                                        fontWeight = if (isActive) FontWeight.Bold else FontWeight.Normal,
                                        color = if (isActive) colors.onSurface else colors.onSurface.copy(alpha = 0.5f)
                                    )
                                }
                            }
                        }
                        Row(horizontalArrangement = Arrangement.spacedBy(4.dp)) {
                            Button(
                                onClick = {
                                    if (index > 0) {
                                        val mutable = orderList.toMutableList()
                                        val temp = mutable[index]
                                        mutable[index] = mutable[index - 1]
                                        mutable[index - 1] = temp
                                        orderList = mutable
                                        settings.pathwayOrder = mutable.joinToString(",")
                                        onSaveSettings()
                                    }
                                },
                                enabled = index > 0,
                                contentPadding = PaddingValues(horizontal = 4.dp, vertical = 2.dp),
                                modifier = Modifier.height(28.dp)
                            ) {
                                Text("▲", fontSize = 10.sp)
                            }
                            Button(
                                onClick = {
                                    if (index < orderList.size - 1) {
                                        val mutable = orderList.toMutableList()
                                        val temp = mutable[index]
                                        mutable[index] = mutable[index + 1]
                                        mutable[index + 1] = temp
                                        orderList = mutable
                                        settings.pathwayOrder = mutable.joinToString(",")
                                        onSaveSettings()
                                    }
                                },
                                enabled = index < orderList.size - 1,
                                contentPadding = PaddingValues(horizontal = 4.dp, vertical = 2.dp),
                                modifier = Modifier.height(28.dp)
                            ) {
                                Text("▼", fontSize = 10.sp)
                            }
                        }
                    }
                }
            }
        }
    }
}
