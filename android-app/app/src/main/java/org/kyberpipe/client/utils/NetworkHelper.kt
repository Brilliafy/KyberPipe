package org.kyberpipe.client.utils

import android.net.Uri
import android.util.Log
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.launch
import java.net.HttpURLConnection
import java.net.URL

fun sendPostRequestAsync(urlStr: String, jsonBody: String) {
    CoroutineScope(Dispatchers.IO).launch {
        var conn: HttpURLConnection? = null
        try {
            val url = URL(urlStr)
            conn = url.openConnection() as HttpURLConnection
            conn.requestMethod = "POST"
            conn.setRequestProperty("Content-Type", "application/json")
            conn.setRequestProperty("Accept", "application/json")
            conn.doOutput = true
            conn.connectTimeout = 3000
            conn.readTimeout = 3000

            conn.outputStream.use { os ->
                val input = jsonBody.toByteArray(charset("utf-8"))
                os.write(input, 0, input.size)
            }

            val responseCode = conn.responseCode
            Log.d("KyberPipeNetwork", "POST to $urlStr returned status $responseCode")
            
            // Read response body to release resources
            val bodyText = conn.inputStream.bufferedReader().use { it.readText() }
            Log.d("KyberPipeNetwork", "Response body: $bodyText")
        } catch (e: Exception) {
            Log.e("KyberPipeNetwork", "Failed to send POST to $urlStr: ${e.message}")
        } finally {
            conn?.disconnect()
        }
    }
}
