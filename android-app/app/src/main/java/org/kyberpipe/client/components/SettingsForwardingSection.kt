package org.kyberpipe.client.components

import android.widget.Toast
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.Spacer
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.height
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.shape.RoundedCornerShape
import androidx.compose.material3.Card
import androidx.compose.material3.CardDefaults
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.Switch
import androidx.compose.material3.Text
import androidx.compose.runtime.Composable
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.setValue
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.platform.LocalContext
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.unit.dp
import androidx.compose.ui.unit.sp
import androidx.fragment.app.FragmentActivity
import org.kyberpipe.client.security.BiometricAuthManager
import org.kyberpipe.client.utils.SettingsManager

/**
 * Forwarding consent gates (audit #14 follow-up). The sensitive opt-in toggles
 * (SMS forwarding, notification forwarding, outbound SMS) previously existed
 * as SettingsManager flags that NO UI could enable — so forwarding was dead
 * (default OFF) but also untestable/uncontrollable. They are now exposed as
 * toggles, and ENABLING any of them requires a BIOMETRIC STEP-UP prompt
 * (Android Keystore-backed strong biometric) — the "key the opt-in gates to
 * the Android Keystore biometric confirmation" hardening the audit
 * recommended. Disabling is safe and applies immediately.
 */
@Composable
internal fun SettingsForwardingSection(
    settings: SettingsManager,
    activity: FragmentActivity,
    onSaveSettings: () -> Unit,
) {
    val context = LocalContext.current
    var smsForwarding by remember { mutableStateOf(settings.smsForwardingEnabled) }
    var notifForwarding by remember { mutableStateOf(settings.notificationForwardingEnabled) }
    var outboundSms by remember { mutableStateOf(settings.outboundSmsEnabled) }

    fun requireBiometric(enableLabel: String, onAuthorized: () -> Unit) {
        BiometricAuthManager.authenticateStepUp(
            activity = activity,
            title = "Enable $enableLabel",
            subtitle = "Verify your identity to allow content forwarding to/from your desktop",
            onSuccess = { onAuthorized() },
            onError = { msg ->
                Toast.makeText(context, "Biometric required to enable $enableLabel: $msg", Toast.LENGTH_SHORT).show()
            }
        )
    }

    Card(
        colors = CardDefaults.cardColors(containerColor = MaterialTheme.colorScheme.surface),
        shape = RoundedCornerShape(16.dp),
        modifier = Modifier.fillMaxWidth()
    ) {
        Column(modifier = Modifier.padding(16.dp)) {
            Text(
                text = "Forwarding (opt-in, biometric-gated)",
                fontSize = 13.sp,
                fontWeight = FontWeight.Bold,
                color = MaterialTheme.colorScheme.onSurface
            )
            Spacer(modifier = Modifier.height(4.dp))
            Text(
                text = "All forwarding is OFF by default. Enabling any gate requires biometric confirmation; " +
                    "content is always ratchet-encrypted and sent only to the paired desktop.",
                fontSize = 10.sp,
                color = MaterialTheme.colorScheme.onSurface.copy(alpha = 0.6f)
            )
            Spacer(modifier = Modifier.height(8.dp))

            ToggleRow(
                label = "Forward received SMS",
                description = "Mirror inbound SMS to the paired desktop over QUIC.",
                checked = smsForwarding,
                onCheckedChange = { target ->
                    if (target) {
                        requireBiometric("SMS forwarding") {
                            settings.smsForwardingEnabled = true
                            smsForwarding = true
                            onSaveSettings()
                        }
                    } else {
                        settings.smsForwardingEnabled = false
                        smsForwarding = false
                        onSaveSettings()
                    }
                }
            )
            ToggleRow(
                label = "Forward notifications",
                description = "Mirror media/notification content to the paired desktop.",
                checked = notifForwarding,
                onCheckedChange = { target ->
                    if (target) {
                        requireBiometric("notification forwarding") {
                            settings.notificationForwardingEnabled = true
                            notifForwarding = true
                            onSaveSettings()
                        }
                    } else {
                        settings.notificationForwardingEnabled = false
                        notifForwarding = false
                        onSaveSettings()
                    }
                }
            )
            ToggleRow(
                label = "Allow outbound SMS",
                description = "Let the desktop send SMS through this phone (approval prompt per message).",
                checked = outboundSms,
                onCheckedChange = { target ->
                    if (target) {
                        requireBiometric("outbound SMS") {
                            settings.outboundSmsEnabled = true
                            outboundSms = true
                            onSaveSettings()
                        }
                    } else {
                        settings.outboundSmsEnabled = false
                        outboundSms = false
                        onSaveSettings()
                    }
                }
            )
        }
    }
}

@Composable
private fun ToggleRow(
    label: String,
    description: String,
    checked: Boolean,
    onCheckedChange: (Boolean) -> Unit,
) {
    Row(
        modifier = Modifier
            .fillMaxWidth()
            .padding(vertical = 6.dp),
        verticalAlignment = Alignment.CenterVertically
    ) {
        Column(modifier = Modifier.weight(1f)) {
            Text(text = label, fontSize = 12.sp, color = MaterialTheme.colorScheme.onSurface)
            Text(
                text = description,
                fontSize = 9.sp,
                color = MaterialTheme.colorScheme.onSurface.copy(alpha = 0.6f)
            )
        }
        Switch(checked = checked, onCheckedChange = onCheckedChange)
    }
}
