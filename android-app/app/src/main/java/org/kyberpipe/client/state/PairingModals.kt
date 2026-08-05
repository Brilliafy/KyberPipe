package org.kyberpipe.client.state

import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.Spacer
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.height
import androidx.compose.material3.AlertDialog
import androidx.compose.material3.Button
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.OutlinedTextField
import androidx.compose.material3.OutlinedTextFieldDefaults
import androidx.compose.material3.Text
import androidx.compose.material3.TextButton
import androidx.compose.runtime.Composable
import androidx.compose.runtime.rememberCoroutineScope
import androidx.compose.ui.Modifier
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.text.style.TextAlign
import androidx.compose.ui.unit.dp
import androidx.compose.ui.unit.sp

/**
 * The pairing feature's modal surface (audit #8 follow-up): the deep-link
 * confirmation dialog (audit finding #22) and the first-connect SAS modal
 * (audit finding #6 two-phase commit). Rendered by the MainScreen router; all
 * state lives in [PairingState].
 */
@Composable
fun PairingModals(
    state: PairingState,
    initialPairingConfig: String?,
    onClearInitialPairingConfig: () -> Unit,
) {
    // Audit finding #22: pairing data arriving from a LINK must be confirmed by
    // the user before it is consumed. A warning (missing pairing token / cert
    // pin) makes the payload suspicious and is surfaced explicitly.
    if (state.linkPairingPending) {
        AlertDialog(
            onDismissRequest = { state.linkPairingPending = false },
            title = { Text("Pairing initiated from a link") },
            text = {
                Text(
                    (state.linkPairingWarning?.let { "$it\n\n" } ?: "") +
                        "Verify the host identity before continuing. Only proceed if you trust the " +
                        "source of this link and the desktop it points to."
                )
            },
            confirmButton = {
                TextButton(onClick = {
                    state.confirmDeepLink(initialPairingConfig)
                    onClearInitialPairingConfig()
                }) { Text("I trust this link — continue") }
            },
            dismissButton = {
                TextButton(onClick = { state.linkPairingPending = false }) { Text("Cancel") }
            }
        )
    }

    // First Connection Modal (Dynamic profile nickname on connect).
    if (state.showFirstConnectModal) {
        val scope = rememberCoroutineScope()
        AlertDialog(
            onDismissRequest = { state.showFirstConnectModal = false },
            title = { Text("Verify SAS Code") },
            text = {
                Column {
                    Text(
                        "Ensure this SAS code matches the one shown on your PC exactly:",
                        fontSize = 14.sp,
                        fontWeight = FontWeight.SemiBold
                    )
                    Spacer(modifier = Modifier.height(15.dp))
                    Text(
                        // AUDIT P4-1: the 12-character/60-bit SAS is rendered
                        // in 4-char groups for human-typed readability.
                        text = state.formattedSasDisplay,
                        fontSize = 32.sp,
                        fontWeight = FontWeight.Bold,
                        color = MaterialTheme.colorScheme.primary,
                        modifier = Modifier.fillMaxWidth(),
                        textAlign = TextAlign.Center,
                        letterSpacing = 4.sp
                    )
                    Spacer(modifier = Modifier.height(20.dp))
                    Text("Assign a visual nickname for this PC node:", fontSize = 13.sp)
                    Spacer(modifier = Modifier.height(10.dp))
                    OutlinedTextField(
                        value = state.tempPcName,
                        onValueChange = { state.tempPcName = it },
                        label = { Text("Visual Nickname") },
                        colors = OutlinedTextFieldDefaults.colors(
                            focusedTextColor = MaterialTheme.colorScheme.onSurface,
                            unfocusedTextColor = MaterialTheme.colorScheme.onSurface,
                            focusedLabelColor = MaterialTheme.colorScheme.onSurface,
                            unfocusedLabelColor = MaterialTheme.colorScheme.onSurface.copy(alpha = 0.7f),
                            cursorColor = MaterialTheme.colorScheme.onSurface
                        )
                    )
                }
            },
            confirmButton = {
                Button(onClick = { state.confirmSasAndCommit(scope) }) {
                    Text("Verify & Connect")
                }
            },
            dismissButton = {
                TextButton(onClick = { state.showFirstConnectModal = false }) {
                    Text("Reject (Mismatch)", color = MaterialTheme.colorScheme.error)
                }
            }
        )
    }
}
