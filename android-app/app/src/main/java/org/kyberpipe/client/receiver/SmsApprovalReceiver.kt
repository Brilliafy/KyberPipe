package org.kyberpipe.client.receiver

import android.content.BroadcastReceiver
import android.content.Context
import android.content.Intent
import android.telephony.SmsManager
import android.util.Log

class SmsApprovalReceiver : BroadcastReceiver() {
    override fun onReceive(context: Context, intent: Intent) {
        if (intent.action == "APPROVE_SMS") {
            val recipient = intent.getStringExtra("recipient") ?: return
            val body = intent.getStringExtra("body") ?: return
            try {
                val smsManager = SmsManager.getDefault()
                smsManager.sendTextMessage(recipient, null, body, null, null)
                Log.i("KyberpipeSms", "Approved SMS sent to $recipient")
            } catch (e: Exception) {
                Log.e("KyberpipeSms", "Failed to send SMS: ${e.message}")
            }
        }
    }
}
