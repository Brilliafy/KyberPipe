package org.kyberpipe.client.receiver

import android.content.BroadcastReceiver
import android.content.Context
import android.content.Intent
import android.telephony.SmsMessage
import android.util.Log

class SmsReceiver : BroadcastReceiver() {

    override fun onReceive(context: Context?, intent: Intent?) {
        if (intent?.action != "android.provider.Telephony.SMS_RECEIVED") return

        val bundle = intent.extras ?: return
        val pdus = bundle.get("pdus") as? Array<*> ?: return
        val format = bundle.getString("format")

        for (pdu in pdus) {
            val bytes = pdu as? ByteArray ?: continue
            val sms = if (android.os.Build.VERSION.SDK_INT >= android.os.Build.VERSION_CODES.M) {
                SmsMessage.createFromPdu(bytes, format)
            } else {
                @Suppress("DEPRECATION")
                SmsMessage.createFromPdu(bytes)
            }

            val sender = sms.originatingAddress ?: "Unknown"
            val body = sms.messageBody ?: ""
            val timestamp = sms.timestampMillis

            Log.i("KyberpipeSmsReceiver", "Intercepted SMS from $sender: $body")

            // Format SMS packet via UniFFI wrapper
            try {
                val jsonPacket = uniffi.kyberpipe.createSmsPacket(sender, body, timestamp.toULong())
                Log.d("KyberpipeSmsReceiver", "Serialized SMS packet: $jsonPacket")
                // Enqueue or transmit packet over active PipeService QUIC pipeline
            } catch (e: Exception) {
                Log.e("KyberpipeSmsReceiver", "Failed to create SMS packet: ${e.message}")
            }
        }
    }
}
