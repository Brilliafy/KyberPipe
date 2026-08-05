package org.kyberpipe.client.components

import androidx.compose.foundation.background
import androidx.compose.foundation.layout.*
import androidx.compose.foundation.rememberScrollState
import androidx.compose.foundation.shape.RoundedCornerShape
import androidx.compose.foundation.verticalScroll
import androidx.compose.material3.*
import androidx.compose.runtime.*
import androidx.compose.ui.Modifier
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.unit.dp
import androidx.compose.ui.unit.sp

@OptIn(ExperimentalMaterial3Api::class)
@Composable
internal fun SettingsLogsSection(
    localLogs: List<String>,
    onCopyStacktrace: () -> Unit,
    onExportDiagnosticLogs: () -> Unit,
    onExportCrashLog: () -> Unit,
    hasCrashLog: Boolean
) {
    val colors = MaterialTheme.colorScheme

    // Zero-Trust Local Diagnostics & Logs Card
    Card(
        colors = CardDefaults.cardColors(containerColor = colors.surface),
        shape = RoundedCornerShape(16.dp),
        modifier = Modifier.fillMaxWidth()
    ) {
        Column(modifier = Modifier.padding(16.dp)) {
            Text(
                text = "Zero-Trust Local Diagnostics & Logs",
                fontSize = 15.sp,
                fontWeight = FontWeight.Bold,
                color = colors.primary
            )
            Spacer(modifier = Modifier.height(8.dp))
            Text(
                text = "Diagnostic Logs:",
                fontSize = 11.sp,
                color = colors.onSurface.copy(alpha = 0.6f)
            )
            Spacer(modifier = Modifier.height(4.dp))
            Box(
                modifier = Modifier
                    .fillMaxWidth()
                    .height(120.dp)
                    .background(colors.background, shape = RoundedCornerShape(8.dp))
                    .padding(8.dp)
            ) {
                val scrollState = rememberScrollState()
                Column(
                    modifier = Modifier
                        .fillMaxSize()
                        .verticalScroll(scrollState)
                ) {
                    localLogs.forEach { log ->
                        Text(
                            text = log,
                            fontSize = 10.sp,
                            color = Color(0xFF38BDF8),
                            fontFamily = androidx.compose.ui.text.font.FontFamily.Monospace
                        )
                    }
                }
            }
            Spacer(modifier = Modifier.height(12.dp))
            Row(
                modifier = Modifier.fillMaxWidth(),
                horizontalArrangement = Arrangement.spacedBy(8.dp)
            ) {
                Button(
                    onClick = onCopyStacktrace,
                    enabled = hasCrashLog,
                    colors = ButtonDefaults.buttonColors(
                        containerColor = colors.surfaceVariant
                    ),
                    modifier = Modifier.weight(1f).height(36.dp),
                    contentPadding = PaddingValues(horizontal = 4.dp, vertical = 2.dp)
                ) {
                    Text("Copy Stacktrace", fontSize = 10.sp, color = if (hasCrashLog) colors.onSurfaceVariant else colors.onSurfaceVariant.copy(alpha = 0.4f))
                }
                Button(
                    onClick = onExportDiagnosticLogs,
                    colors = ButtonDefaults.buttonColors(
                        containerColor = colors.primary
                    ),
                    modifier = Modifier.weight(1f).height(36.dp),
                    contentPadding = PaddingValues(horizontal = 4.dp, vertical = 2.dp)
                ) {
                    Text("Export Logs", fontSize = 10.sp, color = colors.onPrimary)
                }
                Button(
                    onClick = onExportCrashLog,
                    enabled = hasCrashLog,
                    colors = ButtonDefaults.buttonColors(
                        containerColor = if (hasCrashLog) colors.error else colors.surfaceVariant
                    ),
                    modifier = Modifier.weight(1f).height(36.dp),
                    contentPadding = PaddingValues(horizontal = 4.dp, vertical = 2.dp)
                ) {
                    Text("Export Anon Crash", fontSize = 10.sp, color = if (hasCrashLog) colors.onPrimary else colors.onSurfaceVariant.copy(alpha = 0.4f))
                }
            }
        }
    }
}
