package org.kyberpipe.client.receiver

import android.content.BroadcastReceiver
import android.content.Context
import android.content.Intent
import android.telephony.SmsManager
import android.telephony.SmsMessage
import android.util.Log
import android.app.Notification
import android.app.NotificationChannel
import android.app.NotificationManager
import android.app.PendingIntent

class SmsReceiver : BroadcastReceiver() {

    override fun onReceive(context: Context?, intent: Intent?) {
        if (intent?.action != "android.provider.Telephony.SMS_RECEIVED") return
        val ctx = context ?: return

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

            Log.i("KyberpipeSmsReceiver", "Intercepted SMS from $sender (${body.length} chars)")

            try {
                val jsonPacket = uniffi.core_crypto.createSmsPacket(sender, body, timestamp.toULong())
                Log.d("KyberpipeSmsReceiver", "SMS packet created (${body.length} chars)")

                // Forward the packet to the paired desktop over the encrypted
                // QUIC stream (STREAM_SMS = 0x07), wrapped with the session key.
                // All SMS forwarding is SERIALIZED through a single-thread
                // executor — never a raw thread per SMS (audit finding #11: an
                // SMS flood or dead peer previously spawned an unbounded
                // thread/connection storm).
                val settings = org.kyberpipe.client.utils.SettingsManager(ctx)
                if (settings.isPaired) {
                    val encrypted = org.kyberpipe.client.utils.SessionKeyManager.encrypt(jsonPacket)
                    if (encrypted != null) {
                        val payload = org.json.JSONObject().put("encrypted", org.json.JSONObject()
                            .put("nonce_hex", encrypted.nonce.toHex())
                            .put("ciphertext_hex", encrypted.ciphertext.toHex())
                        ).toString()
                        SmsForwarder.enqueue(ctx, payload)
                    }
                }
            } catch (e: Exception) {
                Log.e("KyberpipeSmsReceiver", "Failed to create SMS packet: ${e.message}")
            }
        }
    }

    companion object {
        /// Dispatch outbound SMS from Desktop command via Android SmsManager
        fun sendOutboundSms(context: Context, recipient: String, body: String) {
            // Create approval notification instead of sending directly
            val notificationManager = context.getSystemService(Context.NOTIFICATION_SERVICE) as NotificationManager
            val channelId = "sms_approval"
            if (android.os.Build.VERSION.SDK_INT >= android.os.Build.VERSION_CODES.O) {
                notificationManager.createNotificationChannel(
                    NotificationChannel(channelId, "SMS Approval", NotificationManager.IMPORTANCE_HIGH)
                )
            }
            val approveIntent = Intent(context, SmsApprovalReceiver::class.java).apply {
                action = "APPROVE_SMS"
                putExtra("recipient", recipient)
                putExtra("body", body)
            }
            val denyIntent = Intent(context, SmsApprovalReceiver::class.java).apply {
                action = "DENY_SMS"
            }
            val notification = Notification.Builder(context, channelId)
                .setContentTitle("Send SMS to $recipient?")
                .setContentText(body.take(100))
                .setSmallIcon(android.R.drawable.ic_dialog_info)
                .addAction(Notification.Action.Builder(
                    null, "Approve", PendingIntent.getBroadcast(context, 0, approveIntent, PendingIntent.FLAG_IMMUTABLE)
                ).build())
                .addAction(Notification.Action.Builder(
                    null, "Deny", PendingIntent.getBroadcast(context, 1, denyIntent, PendingIntent.FLAG_IMMUTABLE)
                ).build())
                .build()
            notificationManager.notify(recipient.hashCode(), notification)
        }
    }
}

/// Single-threaded SMS forwarder (audit finding #11). Serializes every
/// STREAM_SMS send so an SMS burst or an unreachable desktop cannot spawn an
/// unbounded thread/connection storm. Applies exponential backoff (1s→30s) on
/// persistent failures and kills-and-respawns the QUIC bridge on failure.
object SmsForwarder {
    private const val TAG = "KyberpipeSmsForwarder"
    private val executor: java.util.concurrent.ExecutorService =
        java.util.concurrent.Executors.newSingleThreadExecutor { r ->
            Thread(r, "kyberpipe-sms-sender").apply { isDaemon = true }
        }
    private val lock = Object()

    fun enqueue(context: android.content.Context, payload: String) {
        executor.execute {
            var backoffMs = 1000L
            var attempt = 0
            var forwarded = false
            while (attempt < 4 && !forwarded) {
                try {
                    val settings = org.kyberpipe.client.utils.SettingsManager(context)
                    val hostIp = settings.pairedHostIp
                    if (hostIp.isNotEmpty()) {
                        try {
                            val ok = org.kyberpipe.client.PairingManager.connectWithIdentity(
                                hostIp, 9876.toUShort(), settings.serverCertPin, context
                            )
                            if (!ok) {
                                try {
                                    uniffi.core_crypto.quicConnect(hostIp, 9876.toUShort(), settings.serverCertPin)
                                } catch (_: Exception) {}
                            }
                        } catch (_: Exception) {}
                    }
                    synchronized(lock) {
                        uniffi.core_crypto.quicSendAndRecv(0x07.toUByte(), payload)
                    }
                    Log.i(TAG, "SMS forwarded via QUIC")
                    forwarded = true
                } catch (e: Exception) {
                    Log.e(TAG, "SMS QUIC forward failed (attempt $attempt): ${e.message}")
                    attempt++
                    if (attempt >= 4) break
                    try {
                        Thread.sleep(backoffMs)
                    } catch (_: InterruptedException) {
                        break
                    }
                    backoffMs = (backoffMs * 2).coerceAtMost(30_000L)
                }
            }
        }
    }
}

/** Byte array → lowercase hex. */
private fun ByteArray.toHex(): String = joinToString("") { "%02x".format(it) }
