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
                val buf = ByteArray(4096)
                val n = client.inputStream.read(buf)
                if (n <= 0) return@launch
                val req = String(buf, 0, n)
                Log.d(tag, "Request: ${req.take(200)}")

                val resp = when {
                    req.contains("POST /api/pair") -> {
                        if (req.contains("\r\n\r\n")) {
                            val body = req.substringAfter("\r\n\r\n")
                            onPairRequest(body)
                        }
                        "HTTP/1.1 200 OK\r\nContent-Length: 17\r\n\r\n{\"status\":\"paired\"}"
                    }
                    req.contains("POST /api/clipboard") -> {
                        if (req.contains("\r\n\r\n")) {
                            val body = req.substringAfter("\r\n\r\n")
                            onClipboard(body)
                        }
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
