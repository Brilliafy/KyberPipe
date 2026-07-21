Kyberpipe: Post-Quantum Local & Remote Connectivity Pipeline

Master Technical Specification & AI Co-Pilot Implementation Manual

Kyberpipe is an ultra-secure, decentralized, high-performance connectivity platform designed to seamlessly bridge a Linux desktop (Fedora native/Flatpak) and an Android companion mobile device.

The architecture implements a hybrid proximity-based/WAN networking paradigm secured via NIST-approved Post-Quantum Cryptography (PQC). This document serves as the absolute, authoritative guide for code generation, architectural hierarchy, and API orchestration.

1. Project Directory Architecture

Kyberpipe is managed as a unified monorepo divided into three highly specialized nodes to separate the low-overhead cryptographic runtime from the presentation and system layers:

kyberpipe/
├── Cargo.toml            # Monorepo Workspace configuration
├── README.md             # This design blueprint
├── core-crypto/          # Shared Rust engine (PQC, QUIC networking, state machine)
│   ├── Cargo.toml
│   ├── src/
│   │   ├── lib.rs        # Main library entrypoint and UniFFI interface definition
│   │   ├── crypto.rs     # ML-KEM-768, ChaCha20-Poly1305, and handshakes
│   │   └── network.rs    # Quinn QUIC server/client implementations
│   └── kyberpipe.udl     # UniFFI interface specification file
├── desktop-app/          # Tauri v2 Desktop Client (Rust backend + Web interface)
│   ├── src-tauri/
│   │   ├── Cargo.toml
│   │   └── src/
│   │       ├── main.rs   # Tauri entrypoint, ashpd bridge, script executor
│   │       └── portal.rs # Clipboard, notifications, file managers via XDG Portals
│   └── src/              # Frontend UI Canvas (React/Vue/Svelte + TypeScript)
├── android-app/          # Native Android Client
│   └── app/
│       ├── build.gradle.kts
│       └── src/main/java/org/kyberpipe/client/
│           ├── MainActivity.kt   # Jetpack Compose UI layout
│           ├── service/
│           │   ├── PipeService.kt # Permanent foreground service loop
│           │   └── SensorDriver.kt# Hardware ambient light polling engine
│           └── receiver/
│               ├── SmsReceiver.kt # BroadcastReceiver for real-time text parsing
│               └── NotificationHook.kt # NotificationListenerService implementation
└── flatpak/
    └── org.kyberpipe.Kyberpipe.yaml # Secure Sandbox manifest


2. Low-Level Networking & P2P Topology

The connection engine must maintain an active state machine that dynamically switches between two transport routes to preserve the connection without user intervention.

                  +-----------------------------------------+
                  |            Connection Manager           |
                  +-----------------------------------------+
                                       |
                  Is Peer Local? (NSD Beacon Discovery)
                  /                                         \
               [Yes]                                        [No]
                /                                             \
  +----------------------------+                 +----------------------------+
  |  Wi-Fi Direct P2P Link     |                 |  WireGuard / WAN Tunnel    |
  |  - Raw Socket Connection   |                 |  - Fallback Remote Route   |
  |  - No shared router needed |                 |  - Public/Private Overlay  |
  +----------------------------+                 +----------------------------+
                \                                             /
                 \                                           /
                  +-----------------------------------------+
                  |         Multiplexed QUIC Engine         |
                  |         - Secure ML-KEM Handshake       |
                  |         - Symmetric ChaCha20 Channels   |
                  +-----------------------------------------+


A. Proximity Wi-Fi Direct (P2P) via Service Discovery

The Problem: Modern mobile and desktop operating systems rotate hardware MAC addresses dynamically for privacy. Traditional static MAC pairing will fail.

The Solution: The Android client uses WifiP2pManager to register a local Wi-Fi P2P service. It broadcasts a unique cryptographically generated service token using Network Service Discovery (NSD) over Wi-Fi P2P:

val serviceInfo = hashMapOf(
    "txtRecordVersion" to "1",
    "peer_identity" to CRYPTO_FINGERPRINT_HEX
)
val serviceRequest = WifiP2pDnsSdServiceInfo.newInstance(
    "_kyberpipe", "_tcp", serviceInfo
)
p2pManager.addLocalService(channel, serviceRequest, ...)


The Desktop Side: The desktop daemon uses local network socket broadcasting or reads wpa_supplicant DBus control interfaces (when running natively) to scan for the _kyberpipe._tcp service. When a matching handshake beacon is detected, the peer initiates connection routing without requiring them to inhabit the same traditional Wi-Fi local area network.

B. QUIC Transport Protocol (quinn)

All data streams—whether routed via local Wi-Fi P2P or WAN—must be multiplexed over QUIC via the quinn crate.

Trust Establishment (No Public CA): Because this is a direct P2P pipeline, standard TLS certificate authorities cannot validate connections. The system must implement a custom rustls::client::danger::ServerCertVerifier and rustls::server::danger::ClientCertVerifier.

Safe Pair Handshake: During initial pairing (established out-of-band via QR code scanning), the devices exchange and pin their raw public keys. During the QUIC handshake, the custom verifiers extract the peer's certificate public key, generate an SHA-256 hash, and match it against the pinned pairing database. Any mismatch must immediately drop the socket.

3. Cryptographic Specification

The crypto-engine must never use experimental or customized cryptographic implementations. It must wrap proven, production-grade Rust primitives.

       [ Client A ]                                              [ Client B ]
            |                                                         |
            | ------------ Ephemeral ML-KEM-768 Public Key ---------> | (Encapsulate)
            |                                                         |
            | <----------- Ciphertext Response (Encapsulated) ------- | (Decapsulate)
            |                                                         |
            +=========================================================+
            |      Both derive identical symmetric Key Material       |
            |      K = HKDF-SHA256(Shared Secret)                     |
            +=========================================================+
            |                                                         |
            | <============ Encrypted Streams (ChaCha20) ===========> |


A. Key Encapsulation (PQC)

Primitive: ML-KEM-768 (NIST FIPS 203 standard, implemented via the pqcrypto-mlkem crate).

Handshake Lifecycle:

Upon establishing the initial raw UDP/QUIC connection, Client A generates an ephemeral ML-KEM-768 keypair $(pk, sk)$.

Client A transmits $pk$ over an initial unencrypted QUIC stream.

Client B receives $pk$, runs the encapsulation algorithm to generate ciphertext $c$ and a shared secret $SS$, and transmits $c$ back to Client A.

Client A decapsulates $c$ using $sk$ to derive the identical shared secret $SS$.

Both clients feed $SS$ through an HKDF-SHA256 function to stretch the key material into a cryptographically strong symmetric session key.

B. Symmetric Payload Encryption

Primitive: ChaCha20-Poly1305 (AEAD, via chacha20poly1305 crate).

All subsequent QUIC data streams are encrypted using this symmetric session key. Huge file payloads must be chunked into uniform blocks of size $S = 64\text{ KB}$. Each chunk is encrypted independently with an incrementing 96-bit nonce to ensure memory-efficient processing and recovery in case of stream drop.

4. Deep Feature Implementations

A. Ambient Light Polling & Secure Dynamic Execution

Mobile Engine: A background SensorEventListener polls the ambient light sensor (Sensor.TYPE_LIGHT) at a user-defined interval $T_{\text{poll}}$ seconds.

To prevent battery drain, the service uses delta-compression: it only transmits a packet if the light level shifts by more than a user-configured lux threshold $\Delta L$:


$$\lvert L_{\text{new}} - L_{\text{last}} \rvert \ge \Delta L$$


The payload is wrapped into a secure JSON packet: {"lux": L_value, "timestamp": unix_time}.

Desktop Execution Engine: When the desktop application receives this packet, it executes a script.

Secure GUI Event Handler Interface (Sandbox Isolation):
To allow the user to modify custom script code directly inside the Tauri GUI editor safely without running risky dynamic raw shell evaluations (which invite shell injection attacks), Kyberpipe implements two strict isolation modes:

 [ GUI Code Editor ] ---> Save String ---> [ Local Sandboxed JS Engine (Boa) ]
                                             - Isolated VM state
                                             - No direct shell/disk access
                                             - Secure API Hooks (console, system alerts)


Isolated JS VM (Recommended Default): The desktop app embeds the boa engine (a pure-Rust JavaScript interpreter). The user's GUI script runs inside this in-memory VM. The VM has absolutely no access to the host file system, network, or process execution space. The Rust backend populates the VM context with the current light value:

// Custom GUI User Code Example
if (ambientLight < 10) {
    system.notify("It is dark! Adjusting screen temperature.");
}


Strict Argument-Passed Subprocess (Fallback): If the user selects a native shell script path, the system forbids dynamic string execution. The Rust backend writes the user's custom script to a localized, non-user-writable file path, sets strict file permissions (0700), and executes it using std::process::Command with the data passed strictly via hardcoded command-line arguments and environment variables:

// SECURE EXECUTION PATTERN - NO SHELL EXPANSION
let status = Command::new("/path/to/user_script.sh")
    .arg("--light")
    .arg(light_value.to_string())
    .env("KYBERPIPE_LUX", light_value.to_string())
    .stdout(Stdio::null())
    .stderr(Stdio::null())
    .status();


B. Bidirectional Clipboard Synchronization

Dynamic Loop Mitigation: When Client A updates its clipboard, it pushes the change to Client B. Client B updates its local system clipboard. This local update triggers Client B's native listener, which would normally try to send the update back to Client A, creating an infinite synchronization loop.

Mitigation Algorithm: Maintain a rolling cryptographically secure hash of the last three synced clipboard states ($H_0, H_1, H_2$). Before transmitting or applying any clipboard payload, verify the SHA-256 hash of the content against this list. If a match occurs, drop the sync cycle immediately.

Tauri Flatpak Portals: Inside Flatpak, the app cannot access the raw X11/Wayland clipboard directly. It must hook into XDG Desktop Portals via ashpd::desktop::clipboard.

C. SMS & Notification Mirroring

SMS Interception: On Android, a BroadcastReceiver captures android.provider.Telephony.SMS_RECEIVED events.

Permissions Required: RECEIVE_SMS, READ_SMS.

Payload: Extracts the sender address and body, wraps them in a PQC-encrypted JSON frame, and streams them over QUIC.

Notification Interception: An Android NotificationListenerService hooks into the system tray. When onNotificationPosted triggers, it filters out persistent system notifications, serializes active media notifications (title, text, app package name, and icon converted to a PNG byte array), and routes them to the desktop.

Desktop Rendering: The desktop application receives these packets and fires native desktop system notifications via ashpd::desktop::notification::Notification.

5. Sandboxing & Runtime Permissions

A. Flatpak vs. Native (Dynamic Environment Handling)

The desktop application must compile to a single binary that automatically detects if it is running in a sandbox by searching for the file /.flatpak-info at launch.

API / Action

Native Mode (.rpm)

Flatpak Mode (.flatpak)

System Notifications

Direct D-Bus call to org.freedesktop.Notifications

ashpd::desktop::notification

Clipboard Access

Direct access to window server buffers (X11/Wayland)

ashpd::desktop::clipboard

File Save / Read

Direct access to $HOME/Downloads

XDG FileChooser Portal (ashpd::desktop::file_chooser)

B. Android Foreground Architecture

To prevent Android 16/17 from shutting down the background synchronization engine, all network hooks, sensor polling, and notification traps must be bound to a persistent Android Foreground Service with explicit system type declarations.

<!-- AndroidManifest.xml Configuration -->
<service
    android:name=".service.PipeService"
    android:foregroundServiceType="connectedDevice|specialUse"
    android:exported="false">
</service>


6. Development & Cross-Compilation Workflow

To bundle and execute the post-quantum cryptographic core seamlessly inside the Android environment, we use UniFFI to generate Kotlin-compatible binders around our Rust library.

+-------------------------------------------------------------+
|                         core-crypto                         |
|  - Rust implementations of QUIC & ML-KEM                     |
+-------------------------------------------------------------+
                               |
                               | (cargo ndk compile)
                               v
+-------------------------------------------------------------+
|                        UniFFI Engine                        |
|  - Binds Rust types into Java/Kotlin interfaces             |
|  - Compiles cross-platform dynamic libraries (.so files)     |
+-------------------------------------------------------------+
                               |
                               v
+-------------------------------------------------------------+
|                         android-app                         |
|  - Android Service executes compiled Rust logic             |
+-------------------------------------------------------------+


Steps for AI Compilation setup:

Write the Interface Definition File (kyberpipe.udl):

namespace kyberpipe {
    [Throws=KyberError]
    void initialize_pq_handshake();

    [Throws=KyberError]
    string encrypt_payload(string data);
};


Build with target architecture cross-compilers:

cargo ndk --target aarch64-linux-android --android-ndk $ANDROID_NDK_HOME build --release


Include the resulting .so targets inside your Android project’s jniLibs folder and initialize the auto-generated Kotlin glue classes.

7. AI Code-Generation Phase Roadmap

When programming Kyberpipe, execute the workspace components in this strict chronological order to avoid compilation loop issues:

Phase 1: Cryptographic core engine (core-crypto): Compile the standalone Rust modules for key generation, encryption schemas, and verify them via cargo unit testing environments.

Phase 2: Mobile Interface Bridge (UniFFI): Verify that your Kotlin bindings compiling engine runs cleanly and exports functional JNI code interfaces.

Phase 3: The Android Foreground Core (android-app): Build out the background service framework, hardware light polling integration, and SMS/Notification interceptors.

Phase 4: The Desktop System Bridge (desktop-app): Construct the Tauri v2 backend, portal hooks via ashpd, sandbox-safe interpreter integrations, and package layouts.

Phase 5: Unification & Presentation Layer: Code the beautiful frontend configuration control panel and link up communication streams.
