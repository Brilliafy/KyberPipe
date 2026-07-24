package org.kyberpipe.client.service

import android.util.Log
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.Job
import kotlinx.coroutines.launch
import org.json.JSONObject
import java.net.ServerSocket
import java.net.Socket

class ReverseSyncServer(
    private val scope: CoroutineScope,
    private val onPairRequest: (String) -> Unit = {},
    private val onClipboard: (String) -> Unit = {}
) {
    private val tag = "KyberpipeRevSync"
    private var serverJob: Job? = null
    private var serverSocket: ServerSocket? = null
    var localPort: Int = 0
        private set

    fun start() {
        serverJob?.cancel()
        serverJob = scope.launch(Dispatchers.IO) {
            try {
                serverSocket = ServerSocket(0).also {
                    localPort = it.localPort
                    it.soTimeout = 5000
                }
                Log.d(tag, "Reverse sync server on port $localPort")

                while (true) {
                    try {
                        val client = serverSocket?.accept() ?: break
                        handleClient(client)
                    } catch (_: java.net.SocketTimeoutException) {
                        continue
                    }
                }
            } catch (e: Exception) {
                Log.e(tag, "Server error: ${e.message}")
            }
        }
    }

    private fun handleClient(client: Socket) {
        scope.launch(Dispatchers.IO) {
            try {
                // Read header first to determine Content-Length
                val headerBuf = ByteArray(8192)
                var headerBytesRead = 0

                // Read until we find \r\n\r\n (end of headers)
                while (headerBytesRead < headerBuf.size) {
                    val n = client.inputStream.read(headerBuf, headerBytesRead, headerBuf.size - headerBytesRead)
                    if (n <= 0) return@launch
                    headerBytesRead += n
                    val headerStr = String(headerBuf, 0, headerBytesRead)
                    if (headerStr.contains("\r\n\r\n")) {
                        break
                    }
                }

                val headerStr = String(headerBuf, 0, headerBytesRead)
                val headerEnd = headerStr.indexOf("\r\n\r\n")
                if (headerEnd == -1) return@launch

                // Parse Content-Length
                var contentLength = 0
                for (line in headerStr.substring(0, headerEnd).lines()) {
                    if (line.lowercase().startsWith("content-length:")) {
                        contentLength = line.substringAfter(":").trim().toIntOrNull() ?: 0
                    }
                }

                // Read the body with proper Content-Length handling
                val bodyStart = headerEnd + 4
                var bodyBytesRead = if (bodyStart < headerBytesRead) headerBytesRead - bodyStart else 0
                val body = ByteArray(contentLength)
                // Copy what we already read from the header buffer
                if (bodyBytesRead > 0) {
                    System.arraycopy(headerBuf, bodyStart, body, 0, bodyBytesRead)
                }
                // Read remaining body bytes
                while (bodyBytesRead < contentLength) {
                    val n = client.inputStream.read(body, bodyBytesRead, contentLength - bodyBytesRead)
                    if (n <= 0) break
                    bodyBytesRead += n
                }

                val req = headerStr.substring(0, headerEnd) + "\r\n\r\n" + String(body, 0, bodyBytesRead)
                Log.d(tag, "Request: ${req.take(200)}")

                val resp = when {
                    req.contains("POST /api/pair") -> {
                        val jsonBody = String(body, 0, bodyBytesRead)
                        onPairRequest(jsonBody)
                        "HTTP/1.1 200 OK\r\nContent-Length: 17\r\n\r\n{\"status\":\"paired\"}"
                    }
                    req.contains("POST /api/clipboard") -> {
                        val jsonBody = String(body, 0, bodyBytesRead)
                        onClipboard(jsonBody)
                        "HTTP/1.1 200 OK\r\nContent-Length: 18\r\n\r\n{\"status\":\"synced\"}"
                    }
                    req.contains("GET /api/poll") -> {
                        "HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\n{}"
                    }
                    else -> "HTTP/1.1 404\r\nContent-Length: 0\r\n\r\n"
                }
                client.outputStream.write(resp.toByteArray())
                client.outputStream.flush()
            } catch (e: Exception) {
                Log.e(tag, "Client handler error: ${e.message}")
            } finally {
                try { client.close() } catch (_: Exception) {}
            }
        }
    }

    fun stop() {
        try { serverSocket?.close() } catch (_: Exception) {}
        serverJob?.cancel()
        serverJob = null
        Log.d(tag, "Reverse sync server stopped")
    }
}
