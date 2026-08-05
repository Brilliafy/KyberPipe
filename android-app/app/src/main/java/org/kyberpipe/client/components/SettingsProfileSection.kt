package org.kyberpipe.client.components

import android.graphics.Bitmap
import android.graphics.BitmapFactory
import android.util.Base64
import androidx.compose.foundation.Image
import androidx.compose.foundation.background
import androidx.compose.foundation.clickable
import androidx.compose.foundation.layout.*
import androidx.compose.foundation.shape.RoundedCornerShape
import androidx.compose.material3.*
import androidx.compose.runtime.*
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.graphics.asImageBitmap
import androidx.compose.ui.layout.ContentScale
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.unit.dp
import androidx.compose.ui.unit.sp
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.filled.CameraAlt
import org.kyberpipe.client.utils.SettingsManager

@OptIn(ExperimentalMaterial3Api::class)
@Composable
internal fun SettingsProfileSection(
    settings: SettingsManager,
    onAvatarPickerClick: () -> Unit,
    onSaveSettings: () -> Unit
) {
    var devName by remember { mutableStateOf(settings.deviceName) }

    val colors = MaterialTheme.colorScheme

    // Local Device Profile Nickname & Avatar Picker card
    Card(
        colors = CardDefaults.cardColors(containerColor = colors.surface),
        shape = RoundedCornerShape(16.dp),
        modifier = Modifier.fillMaxWidth()
    ) {
        Column(modifier = Modifier.padding(16.dp)) {
            Text(
                text = "Local Companion Profile",
                fontSize = 15.sp,
                fontWeight = FontWeight.Bold,
                color = colors.primary
            )
            Spacer(modifier = Modifier.height(12.dp))
            Row(
                verticalAlignment = Alignment.CenterVertically,
                horizontalArrangement = Arrangement.spacedBy(16.dp)
            ) {
                Box(
                    modifier = Modifier
                        .size(70.dp)
                        .background(colors.onSurface.copy(alpha = 0.1f), shape = RoundedCornerShape(35.dp))
                        .clickable { onAvatarPickerClick() },
                    contentAlignment = Alignment.Center
                ) {
                    val bitmap = remember(settings.devicePicture) {
                        decodeBase64ToBitmap(settings.devicePicture)
                    }
                    if (bitmap != null) {
                        Image(
                            bitmap = bitmap.asImageBitmap(),
                            contentDescription = "Avatar",
                            modifier = Modifier.size(70.dp).background(Color.Transparent, shape = RoundedCornerShape(35.dp)),
                            contentScale = ContentScale.Crop
                        )
                    } else {
                        Icon(
                            imageVector = Icons.Default.CameraAlt,
                            contentDescription = "Select Avatar",
                            tint = colors.onSurface,
                            modifier = Modifier.size(24.dp)
                        )
                    }
                }

                Column(modifier = Modifier.weight(1f)) {
                    OutlinedTextField(
                        value = devName,
                        onValueChange = {
                            devName = it
                            settings.deviceName = it
                            onSaveSettings()
                        },
                        label = { Text("Device Name", fontSize = 11.sp) },
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
}

private fun decodeBase64ToBitmap(base64Str: String): Bitmap? {
    if (base64Str.isEmpty()) return null
    return try {
        val pureBase64 = if (base64Str.contains(",")) base64Str.substringAfter(",") else base64Str
        val decodedBytes = Base64.decode(pureBase64, Base64.DEFAULT)
        BitmapFactory.decodeByteArray(decodedBytes, 0, decodedBytes.size)
    } catch (e: Exception) {
        null
    }
}
