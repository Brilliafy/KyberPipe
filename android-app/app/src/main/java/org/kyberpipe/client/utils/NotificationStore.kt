package org.kyberpipe.client.utils

import android.content.Context
import org.json.JSONArray
import org.json.JSONObject
import org.kyberpipe.client.components.AndroidNotificationRecord
import java.io.File

class NotificationStore(private val context: Context) {
    private val file = File(context.filesDir, "notifications.json")

    fun loadNotifications(): MutableList<AndroidNotificationRecord> {
        val list = mutableListOf<AndroidNotificationRecord>()
        if (!file.exists()) return list
        try {
            val jsonStr = file.readText()
            val array = JSONArray(jsonStr)
            for (i in 0 until array.length()) {
                val obj = array.getJSONObject(i)
                list.add(
                    AndroidNotificationRecord(
                        id = obj.getString("id"),
                        title = obj.getString("title"),
                        text = obj.getString("text"),
                        appPackage = obj.getString("appPackage"),
                        timestamp = obj.getLong("timestamp"),
                        type = obj.getString("type"),
                        isDismissed = obj.optBoolean("isDismissed", false),
                        updatedAt = obj.optLong("updatedAt", obj.getLong("timestamp"))
                    )
                )
            }
        } catch (e: Exception) {
            e.printStackTrace()
        }
        return list
    }

    fun saveNotifications(list: List<AndroidNotificationRecord>) {
        try {
            val array = JSONArray()
            for (item in list) {
                val obj = JSONObject().apply {
                    put("id", item.id)
                    put("title", item.title)
                    put("text", item.text)
                    put("appPackage", item.appPackage)
                    put("timestamp", item.timestamp)
                    put("type", item.type)
                    put("isDismissed", item.isDismissed)
                    put("updatedAt", item.updatedAt)
                }
                array.put(obj)
            }
            file.writeText(array.toString())
        } catch (e: Exception) {
            e.printStackTrace()
        }
    }

    fun purgeOldRecords(purgeDays: Int, list: MutableList<AndroidNotificationRecord>) {
        if (purgeDays <= 0) return
        val cutoffTime = System.currentTimeMillis() - (purgeDays * 24L * 3600L * 1000L)
        val iterator = list.iterator()
        var changed = false
        while (iterator.hasNext()) {
            val item = iterator.next()
            if (item.timestamp < cutoffTime) {
                iterator.remove()
                changed = true
            }
        }
        if (changed) {
            saveNotifications(list)
        }
    }

    fun mergeSync(localList: MutableList<AndroidNotificationRecord>, remoteList: List<AndroidNotificationRecord>): Boolean {
        var changed = false
        val localMap = localList.associateBy { it.id }.toMutableMap()
        
        for (remoteItem in remoteList) {
            val localItem = localMap[remoteItem.id]
            if (localItem == null) {
                localMap[remoteItem.id] = remoteItem
                changed = true
            } else {
                if (remoteItem.updatedAt > localItem.updatedAt) {
                    localMap[remoteItem.id] = remoteItem
                    changed = true
                }
            }
        }
        
        if (changed) {
            localList.clear()
            localList.addAll(localMap.values.sortedByDescending { it.timestamp })
            saveNotifications(localList)
        }
        return changed
    }
}
