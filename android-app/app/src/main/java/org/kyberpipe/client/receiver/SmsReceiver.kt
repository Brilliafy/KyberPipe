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
            val rawBody = sms.messageBody ?: ""
            val timestamp = sms.timestampMillis

            // Cap forwarded SMS body length (audit finding #14): never push
            // oversized content over QUIC.
            val body = if (rawBody.length > MAX_FORWARDED_BODY_CHARS) {
                Log.d("KyberpipeSmsReceiver", "Truncating SMS body from ${rawBody.length} to $MAX_FORWARDED_BODY_CHARS chars (audit finding #14)")
                rawBody.take(MAX_FORWARDED_BODY_CHARS)
            } else {
                rawBody
            }

            Log.i("KyberpipeSmsReceiver", "Intercepted SMS from $sender (${body.length} chars)")

            try {
                val jsonPacket = uniffi.core_crypto.createSmsPacket(sender, body, timestamp.toULong())
                Log.d("KyberpipeSmsReceiver", "SMS packet created (${body.length} chars)")

                // Forward the packet to the paired desktop over the encrypted
                // QUIC stream (STREAM_SMS = 0x07), wrapped with the ratchet
                // (binary TLV). The legacy session-key wire path is gone (audit
                // F7/F17) — no raw key bytes ever touch this process. All SMS
                // forwarding is SERIALIZED through a single-thread executor —
                // never a raw thread per SMS (audit finding #11: an SMS flood
                // or dead peer previously spawned an unbounded thread/connection
                // storm).
                //
                // AUDIT FINDING #12: `onReceive` runs on the MAIN thread (~10s
                // ANR budget). The ratchet ENCRYPT (which at a rekey boundary
                // runs an ML-KEM encapsulate inside the session Mutex — tens of
                // ms of CPU) must therefore NOT happen here: it is deferred to
                // the SmsForwarder's single background worker, which encrypts
                // AND sends. The main thread only does the cheap packet
                // construction above.
                val settings = org.kyberpipe.client.utils.SettingsManager(ctx)
                val peer = settings.peerRatchetIdentity
                // Forward only when paired AND the user has explicitly enabled
                // SMS forwarding (audit finding #14 — opt-in, default OFF).
                if (settings.isPaired && settings.smsForwardingEnabled && peer.isNotEmpty()) {
                    SmsForwarder.enqueueEncryptAndSend(ctx, peer, jsonPacket.toByteArray())
                }
            } catch (e: Exception) {
                Log.e("KyberpipeSmsReceiver", "Failed to create SMS packet: ${e.message}")
            }
        }
    }

    companion object {
        /// Maximum forwarded SMS body length in chars (audit finding #14).
        private const val MAX_FORWARDED_BODY_CHARS = 4096

        /// Dispatch outbound SMS from Desktop command via Android SmsManager
        fun sendOutboundSms(context: Context, recipient: String, body: String) {
            // Audit finding #14: outbound SMS is opt-in AND the recipient must
            // be a valid E.164 number — never prompt for (or send to) an
            // unvalidated recipient.
            val settings = org.kyberpipe.client.utils.SettingsManager(context)
            if (!settings.outboundSmsEnabled) {
                Log.w("KyberpipeSmsReceiver", "Outbound SMS dropped: outboundSmsEnabled is false (audit finding #14)")
                return
            }
            if (!isValidE164Number(recipient)) {
                Log.w("KyberpipeSmsReceiver", "Outbound SMS dropped: invalid E.164 recipient \"$recipient\" (audit finding #14)")
                return
            }
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
            // The approval prompt MUST show the exact number and the message
            // body before the user approves (audit finding #14): the title
            // displays the full recipient, the content previews the body.
            // SmsApprovalReceiver re-validates the number as E.164 before
            // actually sending.
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

/// Single-threaded SMS forwarder (audit finding #11 + #7). Serializes every
/// STREAM_SMS send so an SMS burst or an unreachable desktop cannot spawn an
/// unbounded thread/connection storm. Audit finding #7 fixes:
///  - BOUNDED queue: ArrayBlockingQueue(64) + DiscardOldestPolicy — no
///    unbounded growth; the OLDEST queued SMS is dropped in favor of the newest
///    (SMS content is ephemeral; the newest message is the most relevant).
///  - At most 2 attempts per task (initial + one retry after 1s) — no
///    4-attempt blocking backoff loop; a dead desktop is detected by the
///    poll loop (quicConnect in the task body), not by piling up blocked tasks.
///  - 30s outage coalescing gate: while a task recently failed, new SMS are
///    dropped instead of queued, so the bounded queue cannot accumulate.
///  - 60/min rate limit (audit finding #14) — excess forwards are dropped.
object SmsForwarder {
    private const val TAG = "KyberpipeSmsForwarder"

    /// Bounded single-thread executor (audit finding #7). One daemon worker
    /// thread; at most 64 tasks may wait. When the queue is full,
    /// DiscardOldestPolicy drops the oldest queued SMS and enqueues the new
    /// one — the queue can never grow past 64 + 1 running.
    private val executor: java.util.concurrent.ThreadPoolExecutor =
        java.util.concurrent.ThreadPoolExecutor(
            1,
            1,
            0L,
            java.util.concurrent.TimeUnit.MILLISECONDS,
            java.util.concurrent.ArrayBlockingQueue(64),
            java.util.concurrent.ThreadFactory { r ->
                Thread(r, "kyberpipe-sms-sender").apply { isDaemon = true }
            },
            java.util.concurrent.ThreadPoolExecutor.DiscardOldestPolicy()
        )

    /// AUDIT F5: serialization with the poll engine's QUIC round-trip now
    /// happens through the SHARED per-peer gate in
    /// [org.kyberpipe.client.service.KyberPipePollEngine.withPeerRoundTrip] —
    /// only one QUIC round-trip per peer can exist at a time by construction,
    /// so the SMS no longer loses to a mid-flight poll at the Rust in-flight
    /// gate. The single-threaded executor still serializes the ratchet
    /// encrypt calls against each other (audit finding #7/#12).

    /// Static outage gate (audit finding #7): timestamp of the most recent
    /// failed task. While the desktop looks unreachable, new SMS are dropped
    /// instead of enqueued so the bounded queue cannot accumulate during an
    /// outage. The poll loop keeps the connection warm and detects recovery.
    @Volatile
    private var lastFailureAt: Long = 0L

    /// Failure cooldown: skip enqueuing for 30s after a failure.
    private const val FAILURE_COOLDOWN_MS = 30_000L

    /// Simple sliding-window rate limiter (audit finding #14): at most
    /// MAX_FORWARDS_PER_MINUTE forwards per 60s window; excess is dropped.
    private const val MAX_FORWARDS_PER_MINUTE = 60
    private const val RATE_WINDOW_MS = 60_000L
    private val rateLock = Object()
    private val forwardTimestamps = ArrayDeque<Long>()

    private fun desktopRecentlyFailed(): Boolean =
        System.currentTimeMillis() - lastFailureAt < FAILURE_COOLDOWN_MS

    /// Returns true if the forward is within the per-minute budget, recording
    /// the current timestamp under the window counter.
    private fun allowForward(): Boolean = synchronized(rateLock) {
        val now = System.currentTimeMillis()
        while (forwardTimestamps.isNotEmpty() && now - forwardTimestamps.first() >= RATE_WINDOW_MS) {
            forwardTimestamps.removeFirst()
        }
        if (forwardTimestamps.size >= MAX_FORWARDS_PER_MINUTE) {
            false
        } else {
            forwardTimestamps.addLast(now)
            true
        }
    }

    fun enqueue(context: android.content.Context, payload: String) {
        // Coalesce during outages (audit finding #7): don't queue work for a
        // desktop that recently failed.
        if (desktopRecentlyFailed()) {
            Log.d(TAG, "Dropping SMS: desktop recently unreachable (audit finding #7)")
            return
        }
        // Rate limit (audit finding #14).
        if (!allowForward()) {
            Log.d(TAG, "Dropping SMS: forward rate limit ($MAX_FORWARDS_PER_MINUTE/min) exceeded (audit finding #14)")
            return
        }
        executor.execute { sendWithRetry(context, payload) }
    }

    /// AUDIT FINDING #12: ratchet-encrypt + forward entirely on the background
    /// worker. The caller (an SMS broadcast receiver, main thread) must NEVER
    /// run `ratchetEncryptMessageBinary` — at a rekey boundary it performs an
    /// ML-KEM encapsulate inside the session Mutex (tens of ms of CPU) and the
    /// receiver has a ~10s ANR budget. The single-threaded executor also
    /// serializes the encrypt against the poll engine's own native calls,
    /// eliminating session-Mutex contention between poll/SMS/media.
    fun enqueueEncryptAndSend(
        context: android.content.Context,
        peer: String,
        plaintext: ByteArray,
    ) {
        if (desktopRecentlyFailed()) {
            Log.d(TAG, "Dropping SMS: desktop recently unreachable (audit finding #7)")
            return
        }
        if (!allowForward()) {
            Log.d(TAG, "Dropping SMS: forward rate limit ($MAX_FORWARDS_PER_MINUTE/min) exceeded (audit finding #14)")
            return
        }
        executor.execute {
            val tlv = try {
                uniffi.core_crypto.ratchetEncryptMessageBinary(peer, plaintext)
            } catch (e: Exception) {
                Log.e(TAG, "Ratchet encrypt failed on worker: ${e.message}")
                return@execute
            }
            val payload = org.json.JSONObject()
                .put("encrypted_ratchet", org.json.JSONObject()
                    .put("tlv_b64", android.util.Base64.encodeToString(tlv, android.util.Base64.NO_WRAP))
                )
                .toString()
            sendWithRetry(context, payload)
        }
    }

    /// The shared bounded send loop (audit finding #7): at most 2 attempts per
    /// task (initial + one retry after 1s). No unbounded blocking backoff — a
    /// stuck task must not pile up behind a dead desktop.
    private fun sendWithRetry(context: android.content.Context, payload: String) {
        // At most 2 attempts per task (audit finding #7): initial send +
        // one retry after 1s. No unbounded blocking backoff — a stuck task
        // must not pile up behind a dead desktop.
        var attempt = 0
        var forwarded = false
        while (attempt < 2 && !forwarded) {
            try {
                val settings = org.kyberpipe.client.utils.SettingsManager(context)
                val hostIp = settings.pairedHostIp
                // AUDIT F5: the same per-peer peer key the poll engine routes
                // by (cert pin, falling back to the ratchet identity) — the SMS
                // round-trip must hit the SAME connection/gate as the poll in a
                // multi-peer mesh instead of the legacy ACTIVE_PEER API.
                val peerKey = settings.serverCertPin.takeIf { it.isNotEmpty() }
                    ?: settings.peerRatchetIdentity
                // AUDIT F5: the ENTIRE connect + round-trip runs under the
                // poll engine's shared per-peer gate. Only one QUIC round-trip
                // per peer can exist at a time by construction, so the SMS no
                // longer burns its retry budget on the Rust in-flight gate's
                // bounded wait while a poll is mid-flight — it waits its turn
                // and then sends. The gate is a plain (non-suspend) lock; this
                // worker thread is the right place to block on it.
                val ok = org.kyberpipe.client.service.KyberPipePollEngine.withPeerRoundTrip {
                    if (hostIp.isNotEmpty()) {
                        var connected = false
                        try {
                            connected = org.kyberpipe.client.PairingManager.connectWithIdentity(
                                hostIp, 9876.toUShort(), settings.serverCertPin, context
                            )
                        } catch (_: Exception) {}
                        if (!connected) {
                            try {
                                connected = uniffi.core_crypto.quicConnect(
                                    hostIp, 9876.toUShort(), settings.serverCertPin
                                )
                            } catch (_: Exception) {}
                        }
                    }
                    // `quicSendAndRecvTo` reconnects internally via the peer's
                    // registered connection / candidate set, so a failed
                    // explicit connect above does not prevent the send.
                    if (peerKey.isNotEmpty()) {
                        uniffi.core_crypto.quicSendAndRecvTo(peerKey, 0x07.toUByte(), payload)
                    } else {
                        uniffi.core_crypto.quicSendAndRecv(0x07.toUByte(), payload)
                    }
                }
                Log.i(TAG, "SMS forwarded via QUIC")
                forwarded = true
            } catch (e: Exception) {
                Log.e(TAG, "SMS QUIC forward failed (attempt $attempt): ${e.message}")
                attempt++
                if (attempt >= 2) {
                    lastFailureAt = System.currentTimeMillis()
                    break
                }
                try {
                    Thread.sleep(1_000L)
                } catch (_: InterruptedException) {
                    lastFailureAt = System.currentTimeMillis()
                    break
                }
            }
        }
    }
}

/// E.164 phone-number validation (audit finding #14), shared by
/// SmsReceiver.sendOutboundSms and SmsApprovalReceiver: optional leading '+',
/// first digit 1-9, then 6-14 digits.
internal fun isValidE164Number(recipient: String): Boolean =
    Regex("^\\+?[1-9][0-9]{6,14}$").matches(recipient)
