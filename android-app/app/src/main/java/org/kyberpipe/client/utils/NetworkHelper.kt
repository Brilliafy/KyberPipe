package org.kyberpipe.client.utils

import android.net.ConnectivityManager
import android.net.Network
import android.net.NetworkCapabilities
import android.net.NetworkRequest
import android.util.Log
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.launch
import java.net.ConnectException
import java.net.HttpURLConnection
import java.net.SocketTimeoutException
import java.net.URL

object WifiNetworkHolder {
    var wifiNetwork: Network? = null
}

var onFirewallDropDetected: (() -> Unit)? = null

fun bindToWifiNetwork(connectivityManager: ConnectivityManager) {
    val request = NetworkRequest.Builder()
        .addTransportType(NetworkCapabilities.TRANSPORT_WIFI)
        .addCapability(NetworkCapabilities.NET_CAPABILITY_INTERNET)
        .build()

    connectivityManager.registerNetworkCallback(request, object : ConnectivityManager.NetworkCallback() {
        override fun onAvailable(network: Network) {
            WifiNetworkHolder.wifiNetwork = network
            Log.d("KyberPipeNetwork", "WiFi network available: $network")
        }
        override fun onLost(network: Network) {
            if (WifiNetworkHolder.wifiNetwork == network) {
                WifiNetworkHolder.wifiNetwork = null
            }
            Log.d("KyberPipeNetwork", "WiFi network lost: $network")
        }
    })

    // Also try to bind the process to WiFi network for all connections
    val wifiNetwork = connectivityManager.allNetworks.find { net ->
        val caps = connectivityManager.getNetworkCapabilities(net)
        caps?.hasTransport(NetworkCapabilities.TRANSPORT_WIFI) == true &&
        caps?.hasCapability(NetworkCapabilities.NET_CAPABILITY_INTERNET) == true
    }
    if (wifiNetwork != null) {
        WifiNetworkHolder.wifiNetwork = wifiNetwork
        Log.d("KyberPipeNetwork", "Found existing WiFi network: $wifiNetwork")
    }
}

fun sendPostRequestAsync(urlStr: String, jsonBody: String) {
    CoroutineScope(Dispatchers.IO).launch {
        var conn: HttpURLConnection? = null
        try {
            val url = URL(urlStr)
            val wifiNet = WifiNetworkHolder.wifiNetwork
            conn = if (wifiNet != null) {
                wifiNet.openConnection(url) as HttpURLConnection
            } else {
                url.openConnection() as HttpURLConnection
            }
            conn.requestMethod = "POST"
            conn.setRequestProperty("Content-Type", "application/json")
            conn.setRequestProperty("Accept", "application/json")
            conn.doOutput = true
            conn.connectTimeout = 3000
            conn.readTimeout = 3000

            conn.outputStream.use { os ->
                val input = jsonBody.toByteArray(charset("utf-8"))
                os.write(input, 0, input.size)
                os.flush()
            }

            val responseCode = conn.responseCode
            Log.d("KyberPipeNetwork", "POST to $urlStr returned status $responseCode")

            val stream = if (responseCode in 200..299) conn.inputStream else conn.errorStream
            val bodyText = stream?.bufferedReader()?.use { it.readText() } ?: ""
            Log.d("KyberPipeNetwork", "Response body: $bodyText")

        } catch (e: Exception) {
            val msg = e.message ?: ""
            Log.e("KyberPipeNetwork", "Failed to send POST to $urlStr: $msg")
            if (e is SocketTimeoutException || msg.contains("timeout") || msg.contains("timed out")) {
                Log.w("KyberPipeNetwork", "FIREWALL DROP DETECTED: connection timed out (packet dropped)")
                onFirewallDropDetected?.invoke()
            }
        } finally {
            conn?.disconnect()
        }
    }
}
