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
internal fun SettingsNetworkSection(
    settings: SettingsManager,
    onSaveSettings: () -> Unit
) {
    var upnpEnabled by remember { mutableStateOf(settings.enableUpnp) }
    var ddnsEnabled by remember { mutableStateOf(settings.enableDdns) }
    var ddnsHost by remember { mutableStateOf(settings.ddnsHostname) }

    val colors = MaterialTheme.colorScheme

    // Fallbacks toggles: UPnP & DDNS
    Card(
        colors = CardDefaults.cardColors(containerColor = colors.surface),
        shape = RoundedCornerShape(16.dp),
        modifier = Modifier.fillMaxWidth()
    ) {
        Column(modifier = Modifier.padding(16.dp)) {
            Text(
                text = "WAN Fallback Protocols",
                fontSize = 15.sp,
                fontWeight = FontWeight.Bold,
                color = colors.primary
            )
            Spacer(modifier = Modifier.height(12.dp))
            
            Row(
                modifier = Modifier.fillMaxWidth(),
                horizontalArrangement = Arrangement.SpaceBetween,
                verticalAlignment = Alignment.CenterVertically
            ) {
                Text("Enable UPnP IGDP Mapping", fontSize = 13.sp, color = colors.onSurface)
                Switch(
                    checked = upnpEnabled,
                    onCheckedChange = {
                        upnpEnabled = it
                        settings.enableUpnp = it
                        onSaveSettings()
                    }
                )
            }

            Row(
                modifier = Modifier.fillMaxWidth(),
                horizontalArrangement = Arrangement.SpaceBetween,
                verticalAlignment = Alignment.CenterVertically
            ) {
                Text("Enable Dynamic DNS Lookup", fontSize = 13.sp, color = colors.onSurface)
                Switch(
                    checked = ddnsEnabled,
                    onCheckedChange = {
                        ddnsEnabled = it
                        settings.enableDdns = it
                        onSaveSettings()
                    }
                )
            }

            if (ddnsEnabled) {
                Spacer(modifier = Modifier.height(8.dp))
                OutlinedTextField(
                    value = ddnsHost,
                    onValueChange = {
                        ddnsHost = it
                        settings.ddnsHostname = it
                        onSaveSettings()
                    },
                    label = { Text("DDNS Hostname address", fontSize = 11.sp) },
                    colors = OutlinedTextFieldDefaults.colors(
                        focusedTextColor = colors.onSurface,
                        unfocusedTextColor = colors.onSurface,
                        focusedBorderColor = colors.primary,
                        unfocusedBorderColor = colors.onSurface.copy(alpha = 0.2f)
                    ),
                    modifier = Modifier.fillMaxWidth()
                )
            }
        }
    }
}
