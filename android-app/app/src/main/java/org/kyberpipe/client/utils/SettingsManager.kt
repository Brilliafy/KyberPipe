package org.kyberpipe.client.utils

import android.content.Context
import android.content.SharedPreferences

class SettingsManager(context: Context) {
    private val prefs: SharedPreferences = context.getSharedPreferences("kyberpipe_prefs", Context.MODE_PRIVATE)

    var deviceName: String
        get() = prefs.getString("device_name", "Android Companion") ?: "Android Companion"
        set(value) = prefs.edit().putString("device_name", value).apply()

    var devicePicture: String
        get() = prefs.getString("device_picture", "") ?: ""
        set(value) = prefs.edit().putString("device_picture", value).apply()

    var pairedDeviceName: String
        get() = prefs.getString("paired_device_name", "") ?: ""
        set(value) = prefs.edit().putString("paired_device_name", value).apply()

    var pairedDevicePicture: String
        get() = prefs.getString("paired_device_picture", "") ?: ""
        set(value) = prefs.edit().putString("paired_device_picture", value).apply()

    var ddnsHostname: String
        get() = prefs.getString("ddns_hostname", "") ?: ""
        set(value) = prefs.edit().putString("ddns_hostname", value).apply()

    var enableUpnp: Boolean
        get() = prefs.getBoolean("enable_upnp", false)
        set(value) = prefs.edit().putBoolean("enable_upnp", value).apply()

    var enableDdns: Boolean
        get() = prefs.getBoolean("enable_ddns", false)
        set(value) = prefs.edit().putBoolean("enable_ddns", value).apply()

    var isPaired: Boolean
        get() = prefs.getBoolean("is_paired", false)
        set(value) = prefs.edit().putBoolean("is_paired", value).apply()

    var fileAccessGrantedPhone: Boolean
        get() = prefs.getBoolean("file_access_granted_phone", false)
        set(value) = prefs.edit().putBoolean("file_access_granted_phone", value).apply()

    var fileAccessGrantedDesktop: Boolean
        get() = prefs.getBoolean("file_access_granted_desktop", false)
        set(value) = prefs.edit().putBoolean("file_access_granted_desktop", value).apply()

    var themeMode: String
        get() = prefs.getString("theme_mode", "auto") ?: "auto"
        set(value) = prefs.edit().putString("theme_mode", value).apply()

    var amoledMode: Boolean
        get() {
            if (!prefs.contains("amoled_mode")) {
                val manufacturer = android.os.Build.MANUFACTURER.lowercase()
                val isOled = manufacturer.contains("samsung") || 
                             manufacturer.contains("google") || 
                             manufacturer.contains("oneplus") || 
                             manufacturer.contains("xiaomi") || 
                             manufacturer.contains("oppo") || 
                             manufacturer.contains("vivo") || 
                             manufacturer.contains("sony") || 
                             manufacturer.contains("huawei") || 
                             manufacturer.contains("motorola") ||
                             manufacturer.contains("nothing") ||
                             manufacturer.contains("asus")
                prefs.edit().putBoolean("amoled_mode", isOled).apply()
                return isOled
            }
            return prefs.getBoolean("amoled_mode", false)
        }
        set(value) = prefs.edit().putBoolean("amoled_mode", value).apply()

    var pathwayOrder: String
        get() = prefs.getString("pathway_order", "wifi_direct,mdns_lan,wireguard_wan") ?: "wifi_direct,mdns_lan,wireguard_wan"
        set(value) = prefs.edit().putString("pathway_order", value).apply()

    var purgeDays: Int
        get() = prefs.getInt("purge_days", 7)
        set(value) = prefs.edit().putInt("purge_days", value).apply()
}
