package org.kyberpipe.client.components

import androidx.compose.foundation.background
import androidx.compose.foundation.border
import androidx.compose.foundation.clickable
import androidx.compose.foundation.layout.*
import androidx.compose.foundation.shape.RoundedCornerShape
import androidx.compose.foundation.text.KeyboardOptions
import androidx.compose.material3.*
import androidx.compose.runtime.*
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.focus.FocusRequester
import androidx.compose.ui.focus.focusRequester
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.text.TextStyle
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.text.input.KeyboardType
import androidx.compose.ui.text.style.TextAlign
import androidx.compose.ui.unit.dp
import androidx.compose.ui.unit.sp

@Composable
fun PairingInputSection(
    pairingConfigInput: String,
    onPairingConfigChange: (String) -> Unit,
    onTriggerHandshake: () -> Unit
) {
    var activeTab by remember { mutableStateOf("code") } // "code" or "json"
    val colors = MaterialTheme.colorScheme

    Column(modifier = Modifier.fillMaxWidth()) {
        // Tab Headers
        Row(
            modifier = Modifier
                .fillMaxWidth()
                .background(colors.surfaceVariant.copy(alpha = 0.5f), shape = RoundedCornerShape(8.dp))
                .padding(4.dp)
        ) {
            Box(
                modifier = Modifier
                    .weight(1f)
                    .background(
                        if (activeTab == "code") colors.primary else Color.Transparent,
                        shape = RoundedCornerShape(6.dp)
                    )
                    .clickable { activeTab = "code" }
                    .padding(vertical = 8.dp),
                contentAlignment = Alignment.Center
            ) {
                Text(
                    text = "Pairing Code",
                    color = if (activeTab == "code") colors.onPrimary else colors.onSurface,
                    fontWeight = FontWeight.Bold,
                    fontSize = 12.sp
                )
            }
            Box(
                modifier = Modifier
                    .weight(1f)
                    .background(
                        if (activeTab == "json") colors.primary else Color.Transparent,
                        shape = RoundedCornerShape(6.dp)
                    )
                    .clickable { activeTab = "json" }
                    .padding(vertical = 8.dp),
                contentAlignment = Alignment.Center
            ) {
                Text(
                    text = "JSON Config",
                    color = if (activeTab == "json") colors.onPrimary else colors.onSurface,
                    fontWeight = FontWeight.Bold,
                    fontSize = 12.sp
                )
            }
        }

        Spacer(modifier = Modifier.height(12.dp))

        if (activeTab == "code") {
            Text(
                text = "Enter the 6-digit safe pairing SAS code from your PC:",
                fontSize = 12.sp,
                color = colors.onSurface.copy(alpha = 0.7f),
                textAlign = TextAlign.Center,
                modifier = Modifier.fillMaxWidth()
            )
            Spacer(modifier = Modifier.height(8.dp))
            
            SegmentedPinInput(
                initialValue = if (pairingConfigInput.length == 6 && pairingConfigInput.all { it.isDigit() }) pairingConfigInput else "",
                onCodeComplete = { code ->
                    onPairingConfigChange(code)
                }
            )
        } else {
            OutlinedTextField(
                value = pairingConfigInput,
                onValueChange = onPairingConfigChange,
                label = { Text("Paste PC Pairing Config JSON or Pairing URL", fontSize = 11.sp) },
                colors = OutlinedTextFieldDefaults.colors(
                    focusedTextColor = colors.onSurface,
                    unfocusedTextColor = colors.onSurface,
                    focusedBorderColor = colors.primary,
                    unfocusedBorderColor = colors.onSurface.copy(alpha = 0.2f)
                ),
                modifier = Modifier.fillMaxWidth(),
                minLines = 3,
                maxLines = 5
            )
        }

        Spacer(modifier = Modifier.height(16.dp))

        Button(
            onClick = onTriggerHandshake,
            colors = ButtonDefaults.buttonColors(containerColor = colors.primary),
            modifier = Modifier.fillMaxWidth()
        ) {
            Text("Complete PQC Handshake & Connect")
        }
    }
}

@Composable
fun SegmentedPinInput(
    initialValue: String,
    onCodeComplete: (String) -> Unit
) {
    var part1 by remember { mutableStateOf("") }
    var part2 by remember { mutableStateOf("") }

    val focusRequester1 = remember { FocusRequester() }
    val focusRequester2 = remember { FocusRequester() }

    LaunchedEffect(initialValue) {
        if (initialValue.length == 6) {
            part1 = initialValue.take(3)
            part2 = initialValue.substring(3, 6)
        }
    }

    Row(
        verticalAlignment = Alignment.CenterVertically,
        horizontalArrangement = Arrangement.Center,
        modifier = Modifier
            .fillMaxWidth()
            .padding(vertical = 8.dp)
    ) {
        OutlinedTextField(
            value = part1,
            onValueChange = { input ->
                val digits = input.filter { it.isDigit() }
                if (digits.length >= 6) {
                    part1 = digits.take(3)
                    part2 = digits.substring(3, 6)
                    onCodeComplete(part1 + part2)
                    focusRequester2.requestFocus()
                } else {
                    val clean = digits.take(3)
                    part1 = clean
                    if (clean.length == 3) {
                        focusRequester2.requestFocus()
                    }
                    onCodeComplete(clean + part2)
                }
            },
            keyboardOptions = KeyboardOptions(keyboardType = KeyboardType.Number),
            colors = OutlinedTextFieldDefaults.colors(
                focusedTextColor = Color.White,
                unfocusedTextColor = Color.White,
                focusedBorderColor = MaterialTheme.colorScheme.primary,
                unfocusedBorderColor = MaterialTheme.colorScheme.onSurface.copy(alpha = 0.2f)
            ),
            modifier = Modifier
                .width(80.dp)
                .focusRequester(focusRequester1),
            textStyle = TextStyle(
                fontSize = 20.sp,
                fontWeight = FontWeight.Bold,
                textAlign = TextAlign.Center
            ),
            singleLine = true,
            maxLines = 1
        )

        Text(
            text = "—",
            color = MaterialTheme.colorScheme.onSurface.copy(alpha = 0.5f),
            modifier = Modifier.padding(horizontal = 12.dp),
            fontSize = 20.sp,
            fontWeight = FontWeight.Bold
        )

        OutlinedTextField(
            value = part2,
            onValueChange = { input ->
                val digits = input.filter { it.isDigit() }
                val clean = digits.take(3)
                part2 = clean
                if (clean.isEmpty()) {
                    focusRequester1.requestFocus()
                }
                onCodeComplete(part1 + clean)
            },
            keyboardOptions = KeyboardOptions(keyboardType = KeyboardType.Number),
            colors = OutlinedTextFieldDefaults.colors(
                focusedTextColor = Color.White,
                unfocusedTextColor = Color.White,
                focusedBorderColor = MaterialTheme.colorScheme.primary,
                unfocusedBorderColor = MaterialTheme.colorScheme.onSurface.copy(alpha = 0.2f)
            ),
            modifier = Modifier
                .width(80.dp)
                .focusRequester(focusRequester2),
            textStyle = TextStyle(
                fontSize = 20.sp,
                fontWeight = FontWeight.Bold,
                textAlign = TextAlign.Center
            ),
            singleLine = true,
            maxLines = 1
        )
    }
}
