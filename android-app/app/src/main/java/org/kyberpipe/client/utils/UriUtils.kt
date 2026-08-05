package org.kyberpipe.client.utils

import android.content.ContentResolver
import android.net.Uri
import android.util.Base64

object UriUtils {
    fun toBase64(contentResolver: ContentResolver, uri: Uri): String {
        return try {
            val inputStream = contentResolver.openInputStream(uri)
            val bytes = inputStream?.readBytes()
            inputStream?.close()
            if (bytes != null) {
                "data:image/jpeg;base64," + Base64.encodeToString(bytes, Base64.NO_WRAP)
            } else ""
        } catch (e: Exception) {
            ""
        }
    }
}
