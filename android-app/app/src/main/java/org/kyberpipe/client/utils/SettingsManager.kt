package org.kyberpipe.client.utils

import android.content.Context
import android.content.SharedPreferences
import androidx.security.crypto.EncryptedSharedPreferences
import androidx.security.crypto.MasterKey

/**
 * Split settings storage: security-critical values use EncryptedSharedPreferences
 * (Android Keystore-backed AES-256-GCM), while non-sensitive UI prefs use plain storage.
 */
class SettingsManager(context: Context) : org.kyberpipe.client.service.PollSettings {
    // Encrypted prefs for security-critical data (session key, paired state)
    private val securePrefs: SharedPreferences = run {
        val masterKey = MasterKey.Builder(context)
            .setKeyScheme(MasterKey.KeyScheme.AES256_GCM)
            .build()
        EncryptedSharedPreferences.create(
            context,
            "kyberpipe_secure_prefs",
            masterKey,
            EncryptedSharedPreferences.PrefKeyEncryptionScheme.AES256_SIV,
            EncryptedSharedPreferences.PrefValueEncryptionScheme.AES256_GCM
        )
    }

    // Plain prefs for non-sensitive UI settings
    private val prefs: SharedPreferences = context.getSharedPreferences("kyberpipe_prefs", Context.MODE_PRIVATE)

    // ── Security-critical settings (encrypted) ──

    /// Opaque Rust-side session-key handle (ULong stored as Long; 0 = none).
    /// Raw session key bytes NEVER touch the JVM heap or this prefs file — the
    /// key lives in Rust zeroizing memory and is reached only via the handle
    /// (audit finding F7). Handles are process-scoped: after a process restart
    /// the ratchet is restored from the AEAD-wrapped snapshot instead.
    var sessionKeyHandle: Long
        get() = securePrefs.getLong("session_key_handle", 0L)
        set(value) = securePrefs.edit().putLong("session_key_handle", value).apply()

    /// Opaque Rust-side hybrid keypair handle (0 = none). Zeroized via
    /// destroyPqKeypairHandle on unpair/self-destruct (audit finding F7).
    var keypairHandle: Long
        get() = securePrefs.getLong("keypair_handle", 0L)
        set(value) = securePrefs.edit().putLong("keypair_handle", value).apply()

    /// Opaque Rust-side KEM shared-secret handle (0 = none). Zeroized via
    /// destroyKemHandle on unpair/self-destruct (audit finding F7).
    var kemHandleId: Long
        get() = securePrefs.getLong("kem_handle_id", 0L)
        set(value) = securePrefs.edit().putLong("kem_handle_id", value).apply()

    override var isPaired: Boolean
        get() = securePrefs.getBoolean("is_paired", false)
        set(value) = securePrefs.edit().putBoolean("is_paired", value).apply()

    var pairedHostIp: String
        get() = securePrefs.getString("paired_host_ip", "") ?: ""
        set(value) = securePrefs.edit().putString("paired_host_ip", value).apply()
    var peerRatchetIdentity: String
        get() = securePrefs.getString("peer_ratchet_identity", "") ?: ""
        set(value) = securePrefs.edit().putString("peer_ratchet_identity", value).apply()

    /// The PAIRED desktop's ML-DSA beacon signing public key (hex), persisted
    /// from the QR at pairing (audit finding #5). The mDNS listener rejects any
    /// LAN beacon whose embedded signing key is not this key, so an attacker
    /// cannot forge a beacon that looks like the paired desktop. Empty when the
    /// QR predates the field (beacons are then hints only — never applied).
    var pairedBeaconSigningKey: String
        get() = securePrefs.getString("paired_beacon_signing_key", "") ?: ""
        set(value) = securePrefs.edit().putString("paired_beacon_signing_key", value).apply()

    /// Server TLS certificate pin (64-char hex SHA-256). Stored ONLY after the
    /// user confirms the SAS out-of-band — never on first connect (TOFU MitM
    /// hazard).
    var serverCertPin: String
        get() = securePrefs.getString("server_cert_pin", "") ?: ""
        set(value) = securePrefs.edit().putString("server_cert_pin", value).apply()

    /// Base64-encoded encrypted ratchet snapshot for persistence across restarts
    /// (exported via ratchetExportSession and wrapped by the app).
    var ratchetSnapshot: String
        get() = securePrefs.getString("ratchet_snapshot", "") ?: ""
        set(value) = securePrefs.edit().putString("ratchet_snapshot", value).apply()

    /// Independent at-rest wrap key (hex, 32 random bytes) used to AEAD-wrap the
    /// ratchet snapshot before Base64 persistence (audit finding #13). Kept
    /// separate from the session key in EncryptedSharedPreferences.
    var ratchetSnapshotKey: String
        get() = securePrefs.getString("ratchet_snapshot_key", "") ?: ""
        set(value) = securePrefs.edit().putString("ratchet_snapshot_key", value).apply()

    /// Monotonic ratchet rollback high-water mark, one entry per peer
    /// (audit #2 follow-up). JSON shape: `{ "<peer>": [epoch, gen, send, recv] }`
    /// mirroring the core-crypto `RatchetWatermark` record. Kept in
    /// EncryptedSharedPreferences (Android Keystore-backed) so a same-user
    /// process that restores an OLD wrapped snapshot blob cannot regress it —
    /// the restore path refuses any snapshot whose watermark is strictly below
    /// this recorded value (the same monotonic bound the desktop store enforces
    /// with its keyring watermark). Only ever moves forward.
    var ratchetWatermarkJson: String
        get() = securePrefs.getString("ratchet_watermark_json", "") ?: ""
        set(value) = securePrefs.edit().putString("ratchet_watermark_json", value).apply()

    /// Per-install client identity certificate (DER, base64) generated at
    /// pairing time. Presented on every post-pairing QUIC connection so the
    /// desktop authorizes this device by certificate hash — never by IP
    /// (audit finding #8).
    var clientIdentityCert: String
        get() = securePrefs.getString("client_identity_cert", "") ?: ""
        set(value) = securePrefs.edit().putString("client_identity_cert", value).apply()

    /// Per-install client identity private key (DER PKCS#8, base64). Stored in
    /// EncryptedSharedPreferences (Android Keystore-backed AES-256-GCM).
    var clientIdentityKey: String
        get() = securePrefs.getString("client_identity_key", "") ?: ""
        set(value) = securePrefs.edit().putString("client_identity_key", value).apply()

    /// SHA-256 (hex) fingerprint of the client identity certificate — the
    /// value echoed to the desktop during pairing so it pins OUR identity.
    var clientIdentityCertHash: String
        get() = securePrefs.getString("client_identity_cert_hash", "") ?: ""
        set(value) = securePrefs.edit().putString("client_identity_cert_hash", value).apply()

    /// The QR pairing nonce issued by the desktop for THIS pairing attempt.
    /// Echoed in the pairing payload so the server can reject blind races from
    /// arbitrary LAN peers (audit finding #20).
    var pendingPairingNonce: String
        get() = securePrefs.getString("pending_pairing_nonce", "") ?: ""
        set(value) = securePrefs.edit().putString("pending_pairing_nonce", value).apply()

    /// True while the phone awaits the desktop's SAS confirmation before
    /// committing `isPaired`. Gates the two-phase pairing commit (audit finding
    /// #6): the phone must not claim "paired" while the desktop may still reject
    /// the SAS code or time out.
    override var pendingPairingConfirmation: Boolean
        get() = securePrefs.getBoolean("pending_pairing_confirmation", false)
        set(value) = securePrefs.edit().putBoolean("pending_pairing_confirmation", value).apply()

    /// Server cert hash bound to the pairing QR (audit finding #15). Prefer it
    /// over runtime capture when the QR carries it; bootstrap QUIC connects use
    /// it to pin the server certificate during pairing.
    var pendingServerCertHash: String
        get() = securePrefs.getString("pending_server_cert_hash", "") ?: ""
        set(value) = securePrefs.edit().putString("pending_server_cert_hash", value).apply()


    // ── Forwarding consent gates (encrypted; audit finding #14) ──
    // ALL DEFAULT FALSE: forwarding stays disabled until the user explicitly
    // opts in. Each gate is checked by the corresponding sender before any
    // content leaves the device (SmsReceiver / NotificationHook / outbound SMS).

    /// Master consent for forwarding received SMS to the paired desktop.
    var smsForwardingEnabled: Boolean
        get() = securePrefs.getBoolean("sms_forwarding_enabled", false)
        set(value) = securePrefs.edit().putBoolean("sms_forwarding_enabled", value).apply()

    /// Master consent for forwarding notification (media) content to the
    /// paired desktop over QUIC.
    var notificationForwardingEnabled: Boolean
        get() = securePrefs.getBoolean("notification_forwarding_enabled", false)
        set(value) = securePrefs.edit().putBoolean("notification_forwarding_enabled", value).apply()

    /// Consent for sending OUTBOUND SMS from the paired desktop (delivered via
    /// the approval notification in SmsReceiver.sendOutboundSms).
    var outboundSmsEnabled: Boolean
        get() = securePrefs.getBoolean("outbound_sms_enabled", false)
        set(value) = securePrefs.edit().putBoolean("outbound_sms_enabled", value).apply()


    // ── Non-sensitive UI settings (plain) ──

    var deviceName: String
        get() = prefs.getString("device_name", "Android Companion") ?: "Android Companion"
        set(value) = prefs.edit().putString("device_name", value).apply()

    var devicePicture: String
        get() = prefs.getString("device_picture", "") ?: ""
        set(value) = prefs.edit().putString("device_picture", value).apply()

    override var pairedDeviceName: String
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
        get() = prefs.getString("pathway_order", "mdns_lan,wireguard_wan") ?: "mdns_lan,wireguard_wan"
        set(value) = prefs.edit().putString("pathway_order", value).apply()

    var purgeDays: Int
        get() = prefs.getInt("purge_days", 7)
        set(value) = prefs.edit().putInt("purge_days", value).apply()

    var notificationPermissionShown: Boolean
        get() = prefs.getBoolean("notification_permission_shown", false)
        set(value) = prefs.edit().putBoolean("notification_permission_shown", value).apply()
}
