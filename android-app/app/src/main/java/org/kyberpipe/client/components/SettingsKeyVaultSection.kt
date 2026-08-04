package org.kyberpipe.client.components

import android.util.Log
import androidx.compose.foundation.layout.*
import androidx.compose.foundation.shape.RoundedCornerShape
import androidx.compose.material3.*
import androidx.compose.runtime.*
import androidx.compose.ui.Modifier
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.unit.dp
import androidx.compose.ui.unit.sp
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.withContext
import uniffi.core_crypto.PqPairingPublic

@OptIn(ExperimentalMaterial3Api::class)
@Composable
internal fun SettingsKeyVaultSection(
    keyPairHandle: ULong?
) {
    // Audit finding F7: only the PUBLIC halves of the pairing keypair are shown
    // here, fetched from the Rust handle off the Main thread (audit F9).
    var keyPairPublic by remember { mutableStateOf<PqPairingPublic?>(null) }
    LaunchedEffect(keyPairHandle) {
        keyPairPublic = if (keyPairHandle != null) {
            withContext(Dispatchers.IO) {
                try {
                    uniffi.core_crypto.getPqKeypairPublic(keyPairHandle!!)
                } catch (e: Exception) {
                    Log.e("KyberpipeSettings", "getPqKeypairPublic failed: ${e.message}")
                    null
                }
            }
        } else {
            null
        }
    }

    val colors = MaterialTheme.colorScheme

    // Cryptographic keys vault display card — public halves only, fetched
    // from the Rust keypair handle (audit finding F7).
    keyPairPublic?.let { pub ->
        Card(
            colors = CardDefaults.cardColors(containerColor = colors.surface),
            shape = RoundedCornerShape(16.dp),
            modifier = Modifier.fillMaxWidth()
        ) {
            Column(modifier = Modifier.padding(16.dp)) {
                Text(
                    text = "Companion Key Vault",
                    fontSize = 15.sp,
                    fontWeight = FontWeight.Bold,
                    color = colors.primary
                )
                Spacer(modifier = Modifier.height(10.dp))
                Text("NIST ML-KEM-768 PK (Hex):", fontSize = 11.sp, color = colors.onSurface.copy(alpha = 0.6f))
                Text(
                    text = pub.mlkemPkHex.take(48) + "...",
                    fontSize = 12.sp,
                    fontWeight = FontWeight.Bold,
                    color = Color(0xFFC084FC)
                )
                Spacer(modifier = Modifier.height(10.dp))
                Text("X25519 Ephemeral PK (Hex):", fontSize = 11.sp, color = colors.onSurface.copy(alpha = 0.6f))
                Text(
                    text = pub.x25519PkHex.take(48) + "...",
                    fontSize = 12.sp,
                    fontWeight = FontWeight.Bold,
                    color = Color(0xFFC084FC)
                )
            }
        }
    }
}
