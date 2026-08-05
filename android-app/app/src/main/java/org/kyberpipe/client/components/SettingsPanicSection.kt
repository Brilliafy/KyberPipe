package org.kyberpipe.client.components

import androidx.compose.foundation.layout.*
import androidx.compose.foundation.shape.RoundedCornerShape
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.filled.Warning
import androidx.compose.material3.*
import androidx.compose.runtime.*
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.unit.dp
import androidx.compose.ui.unit.sp

@OptIn(ExperimentalMaterial3Api::class)
@Composable
internal fun SettingsPanicSection(
    onPanicTriggered: () -> Unit
) {
    val colors = MaterialTheme.colorScheme

    // Emergency Panic Self-Destruct Card (Moved here from Home tab)
    Card(
        colors = CardDefaults.cardColors(containerColor = colors.error.copy(alpha = 0.1f)),
        shape = RoundedCornerShape(16.dp),
        modifier = Modifier.fillMaxWidth()
    ) {
        Column(modifier = Modifier.padding(16.dp)) {
            Row(verticalAlignment = Alignment.CenterVertically) {
                Icon(
                    imageVector = Icons.Default.Warning,
                    contentDescription = null,
                    tint = colors.error,
                    modifier = Modifier.size(20.dp)
                )
                Spacer(modifier = Modifier.width(8.dp))
                Text(
                    text = "Emergency Panic Destruction",
                    fontSize = 16.sp,
                    fontWeight = FontWeight.Bold,
                    color = colors.error
                )
            }
            Spacer(modifier = Modifier.height(4.dp))
            Text(
                text = "Instantly zeroizes active ratchet memory and purges TEE/StrongBox master keys.",
                fontSize = 12.sp,
                color = colors.onErrorContainer
            )
            Spacer(modifier = Modifier.height(12.dp))
            Button(
                onClick = onPanicTriggered,
                colors = ButtonDefaults.buttonColors(containerColor = colors.error),
                modifier = Modifier.fillMaxWidth()
            ) {
                Text("PURGE MASTER KEYS & ZEROIZE RAM", color = colors.onError, fontWeight = FontWeight.Bold)
            }
        }
    }
}
