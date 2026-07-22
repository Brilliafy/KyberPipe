package org.kyberpipe.client.utils

import android.Manifest
import android.app.Activity
import android.content.Context
import android.content.Intent
import android.content.pm.PackageManager
import android.net.Uri
import android.os.Build
import android.os.Environment
import android.provider.Settings
import androidx.core.app.ActivityCompat
import androidx.core.content.ContextCompat

object PermissionHelper {
    const val REQUEST_CODE_PERMISSIONS = 101

    fun hasSmsPermissions(context: Context): Boolean {
        val receive = ContextCompat.checkSelfPermission(context, Manifest.permission.RECEIVE_SMS)
        val send = ContextCompat.checkSelfPermission(context, Manifest.permission.SEND_SMS)
        return receive == PackageManager.PERMISSION_GRANTED && send == PackageManager.PERMISSION_GRANTED
    }

    fun requestSmsPermissions(activity: Activity) {
        ActivityCompat.requestPermissions(
            activity,
            arrayOf(Manifest.permission.RECEIVE_SMS, Manifest.permission.SEND_SMS),
            REQUEST_CODE_PERMISSIONS
        )
    }

    fun hasStoragePermissions(context: Context): Boolean {
        return if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.R) {
            Environment.isExternalStorageManager()
        } else {
            val read = ContextCompat.checkSelfPermission(context, Manifest.permission.READ_EXTERNAL_STORAGE)
            val write = ContextCompat.checkSelfPermission(context, Manifest.permission.WRITE_EXTERNAL_STORAGE)
            read == PackageManager.PERMISSION_GRANTED && write == PackageManager.PERMISSION_GRANTED
        }
    }

    fun requestStoragePermissions(activity: Activity) {
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.R) {
            try {
                val intent = Intent(Settings.ACTION_MANAGE_APP_ALL_FILES_ACCESS_PERMISSION).apply {
                    data = Uri.parse("package:${activity.packageName}")
                }
                activity.startActivity(intent)
            } catch (e: Exception) {
                val intent = Intent(Settings.ACTION_MANAGE_ALL_FILES_ACCESS_PERMISSION)
                activity.startActivity(intent)
            }
        } else {
            ActivityCompat.requestPermissions(
                activity,
                arrayOf(Manifest.permission.READ_EXTERNAL_STORAGE, Manifest.permission.WRITE_EXTERNAL_STORAGE),
                REQUEST_CODE_PERMISSIONS
            )
        }
    }

    fun isNotificationListenerEnabled(context: Context): Boolean {
        val cn = Settings.Secure.getString(context.contentResolver, "enabled_notification_listeners")
        return cn != null && cn.contains(context.packageName)
    }

    fun requestNotificationListenerPermission(activity: Activity) {
        val intent = Intent(Settings.ACTION_NOTIFICATION_LISTENER_SETTINGS)
        activity.startActivity(intent)
    }
}
