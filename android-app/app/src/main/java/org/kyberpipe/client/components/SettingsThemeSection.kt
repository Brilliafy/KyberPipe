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
internal fun SettingsThemeSection(
    settings: SettingsManager,
    onSaveSettings: () -> Unit
) {
    var themeState by remember { mutableStateOf(settings.themeMode) }
    var amoledState by remember { mutableStateOf(settings.amoledMode) }

    val colors = MaterialTheme.colorScheme

    // Theme Visual Properties Card
    Card(
        colors = CardDefaults.cardColors(containerColor = colors.surface),
        shape = RoundedCornerShape(16.dp),
        modifier = Modifier.fillMaxWidth()
    ) {
        Column(modifier = Modifier.padding(16.dp)) {
            Text(
                text = "Theme Visual Properties",
                fontSize = 15.sp,
                fontWeight = FontWeight.Bold,
                color = colors.primary
            )
            Spacer(modifier = Modifier.height(10.dp))
            
            Text("Select Application Theme Mode:", fontSize = 11.sp, color = colors.onSurface.copy(alpha = 0.6f))
            Spacer(modifier = Modifier.height(6.dp))
            Row(
                modifier = Modifier.fillMaxWidth(),
                horizontalArrangement = Arrangement.spacedBy(8.dp)
            ) {
                val themeModes = listOf("light" to "Light", "dark" to "Dark", "auto" to "System Auto")
                themeModes.forEach { (mode, label) ->
                    val selected = themeState == mode
                    Button(
                        onClick = {
                            themeState = mode
                            settings.themeMode = mode
                            onSaveSettings()
                        },
                        colors = ButtonDefaults.buttonColors(
                            containerColor = if (selected) colors.primary else colors.surfaceVariant
                        ),
                        contentPadding = PaddingValues(horizontal = 10.dp, vertical = 2.dp),
                        modifier = Modifier.weight(1f).height(32.dp)
                    ) {
                        Text(label, fontSize = 11.sp, color = if (selected) colors.onPrimary else colors.onSurfaceVariant)
                    }
                }
            }
            
            Spacer(modifier = Modifier.height(12.dp))
            Row(
                modifier = Modifier.fillMaxWidth(),
                horizontalArrangement = Arrangement.SpaceBetween,
                verticalAlignment = Alignment.CenterVertically
            ) {
                Column(modifier = Modifier.weight(1f)) {
                    Text(
                        text = "True AMOLED/OLED Mode",
                        fontSize = 13.sp,
                        fontWeight = FontWeight.Bold,
                        color = colors.onSurface
                    )
                    Text(
                        text = "Enforce pure black backgrounds to optimize power",
                        fontSize = 11.sp,
                        color = colors.onSurface.copy(alpha = 0.6f)
                    )
                }
                Switch(
                    checked = amoledState,
                    onCheckedChange = {
                        amoledState = it
                        settings.amoledMode = it
                        onSaveSettings()
                    }
                )
            }

            Spacer(modifier = Modifier.height(12.dp))
            HorizontalDivider(color = colors.onSurface.copy(alpha = 0.05f))
            Spacer(modifier = Modifier.height(12.dp))

            Text(
                text = "Auto-Purge History",
                fontSize = 13.sp,
                fontWeight = FontWeight.Bold,
                color = colors.onSurface
            )
            Text(
                text = "Purge notifications and logs older than designated days to conserve device storage.",
                fontSize = 11.sp,
                color = colors.onSurface.copy(alpha = 0.6f)
            )
            Spacer(modifier = Modifier.height(6.dp))
            Row(
                modifier = Modifier.fillMaxWidth(),
                horizontalArrangement = Arrangement.spacedBy(8.dp)
            ) {
                val purgeDaysOptions = listOf(3, 7, 14, 30)
                var selectedPurgeDays by remember { mutableStateOf(settings.purgeDays) }
                purgeDaysOptions.forEach { days ->
                    val selected = selectedPurgeDays == days
                    Button(
                        onClick = {
                            selectedPurgeDays = days
                            settings.purgeDays = days
                            onSaveSettings()
                        },
                        colors = ButtonDefaults.buttonColors(
                            containerColor = if (selected) colors.primary else colors.surfaceVariant
                        ),
                        contentPadding = PaddingValues(horizontal = 10.dp, vertical = 2.dp),
                        modifier = Modifier.weight(1f).height(32.dp)
                    ) {
                        Text("$days Days", fontSize = 11.sp, color = if (selected) colors.onPrimary else colors.onSurfaceVariant)
                    }
                }
            }
        }
    }
}
