package org.kyberpipe.client.service

import android.annotation.SuppressLint
import android.content.BroadcastReceiver
import android.content.Context
import android.content.Intent
import android.content.IntentFilter
import android.net.wifi.WifiManager
import android.net.wifi.p2p.WifiP2pConfig
import android.net.wifi.p2p.WifiP2pDevice
import android.net.wifi.p2p.WifiP2pDeviceList
import android.net.wifi.p2p.WifiP2pInfo
import android.net.wifi.p2p.WifiP2pManager
import android.os.Build
import android.util.Log
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.Dispatchers

data class P2pConnectionState(
    val isConnected: Boolean = false,
    val groupOwnerIp: String = "",
    val isGroupOwner: Boolean = false,
    val peerMac: String = ""
)

@SuppressLint("MissingPermission")
class WifiDirectManager(private val context: Context) {

    private val tag = "KyberpipeP2P"
    private val manager: WifiP2pManager? by lazy {
        context.getSystemService(Context.WIFI_P2P_SERVICE) as? WifiP2pManager
    }
    private var channel: WifiP2pManager.Channel? = null
    private var onStateChange: ((P2pConnectionState) -> Unit)? = null
    private var onPeersFound: ((List<String>) -> Unit)? = null

    private var currentState = P2pConnectionState()
    private val scope = CoroutineScope(Dispatchers.Main)

    private val receiver = object : BroadcastReceiver() {
        override fun onReceive(ctx: Context, intent: Intent) {
            when (intent.action) {
                WifiP2pManager.WIFI_P2P_PEERS_CHANGED_ACTION -> {
                    manager?.requestPeers(channel) { peers ->
                        val macs = peers?.deviceList?.map { it.deviceAddress } ?: emptyList()
                        Log.d(tag, "Peers changed: ${macs.size} devices found")
                        onPeersFound?.invoke(macs)
                    }
                }
                WifiP2pManager.WIFI_P2P_CONNECTION_CHANGED_ACTION -> {
                    val info = intent.getParcelableExtra<WifiP2pInfo>(
                        WifiP2pManager.EXTRA_WIFI_P2P_INFO
                    )
                    if (info != null) {
                        val groupOwnerIp = info.groupOwnerAddress?.hostAddress ?: ""
                        currentState = currentState.copy(
                            isConnected = info.groupFormed,
                            groupOwnerIp = groupOwnerIp,
                            isGroupOwner = info.isGroupOwner
                        )
                        Log.d(tag, "Connection changed: formed=${info.groupFormed} go=${
                            info.isGroupOwner
                        } goIp=$groupOwnerIp")
                        onStateChange?.invoke(currentState)
                    }
                }
                WifiP2pManager.WIFI_P2P_THIS_DEVICE_CHANGED_ACTION -> {
                    val device = intent.getParcelableExtra<WifiP2pDevice>(
                        WifiP2pManager.EXTRA_WIFI_P2P_DEVICE
                    )
                    if (device != null) {
                        currentState = currentState.copy(
                            peerMac = device.deviceAddress
                        )
                    }
                }
                WifiP2pManager.WIFI_P2P_DISCOVERY_CHANGED_ACTION -> {
                    val state = intent.getIntExtra(WifiP2pManager.EXTRA_DISCOVERY_STATE, -1)
                    Log.d(tag, "Discovery state: ${if (state == WifiP2pManager.WIFI_P2P_DISCOVERY_STARTED) "STARTED" else "STOPPED"}")
                }
            }
        }
    }

    fun initialize(
        onState: ((P2pConnectionState) -> Unit)? = null,
        onPeers: ((List<String>) -> Unit)? = null
    ) {
        onStateChange = onState
        onPeersFound = onPeers
        channel = manager?.initialize(context, context.mainLooper, null)

        val filter = IntentFilter().apply {
            addAction(WifiP2pManager.WIFI_P2P_PEERS_CHANGED_ACTION)
            addAction(WifiP2pManager.WIFI_P2P_CONNECTION_CHANGED_ACTION)
            addAction(WifiP2pManager.WIFI_P2P_THIS_DEVICE_CHANGED_ACTION)
            addAction(WifiP2pManager.WIFI_P2P_DISCOVERY_CHANGED_ACTION)
        }
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.TIRAMISU) {
            context.registerReceiver(receiver, filter, Context.RECEIVER_EXPORTED)
        } else {
            context.registerReceiver(receiver, filter)
        }

        Log.d(tag, "WifiDirectManager initialized")
    }

    @SuppressLint("MissingPermission")
    fun discoverPeers() {
        manager?.discoverPeers(channel, object : WifiP2pManager.ActionListener {
            override fun onSuccess() {
                Log.d(tag, "Peer discovery started")
            }
            override fun onFailure(reason: Int) {
                Log.e(tag, "Peer discovery failed: reason=$reason")
            }
        })
    }

    fun findAndConnect(targetMac: String) {
        val normalizedTarget = targetMac.uppercase()
        Log.d(tag, "Searching for peer: $normalizedTarget")

        val existingOnPeers = onPeersFound
        onPeersFound = { macs ->
            existingOnPeers?.invoke(macs)
            val targetMacs = macs.filter { it.uppercase() == normalizedTarget }
            if (targetMacs.isNotEmpty()) {
                Log.d(tag, "Found target peer: $normalizedTarget, connecting...")
                manager?.requestPeers(channel) { peers ->
                    val match = peers?.deviceList?.find {
                        it.deviceAddress.uppercase() == normalizedTarget
                    }
                    if (match != null) {
                        connectToPeer(match)
                        onPeersFound = existingOnPeers
                    }
                }
            }
        }
        discoverPeers()
    }

    private fun connectToPeer(device: WifiP2pDevice) {
        @Suppress("DEPRECATION")
        val config = WifiP2pConfig().apply {
            deviceAddress = device.deviceAddress
            groupOwnerIntent = 1
        }
        manager?.connect(channel, config, object : WifiP2pManager.ActionListener {
            override fun onSuccess() {
                Log.d(tag, "P2P connect request sent to ${device.deviceAddress}")
            }
            override fun onFailure(reason: Int) {
                Log.e(tag, "P2P connect failed to ${device.deviceAddress}: reason=$reason")
            }
        })
    }

    fun disconnect() {
        manager?.removeGroup(channel, object : WifiP2pManager.ActionListener {
            override fun onSuccess() {
                Log.d(tag, "P2P group removed")
            }
            override fun onFailure(reason: Int) {
                Log.e(tag, "P2P group removal failed: reason=$reason")
            }
        })
    }

    fun getWifiDirectIp(): String {
        val wifiManager = context.getSystemService(Context.WIFI_SERVICE) as? WifiManager
        val wifiInfo = wifiManager?.connectionInfo
        return wifiInfo?.ipAddress?.let {
            String.format("%d.%d.%d.%d", it and 0xff, it shr 8 and 0xff, it shr 16 and 0xff, it shr 24 and 0xff)
        } ?: ""
    }

    fun destroy() {
        try {
            context.unregisterReceiver(receiver)
        } catch (_: Exception) {}
        channel?.close()
    }
}
