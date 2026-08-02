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
            // Audit finding #14: reject non-E.164 recipients — never send to an
            // unvalidated number, even if an approval notification was shown.
            if (!isValidE164Number(recipient)) {
                Log.w("KyberpipeSms", "Approved SMS rejected: invalid E.164 recipient \"$recipient\" (audit finding #14)")
                return
            }
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
