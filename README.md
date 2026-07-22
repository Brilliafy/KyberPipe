# KyberPipe

KyberPipe is a zero-trust, post-quantum cryptography (PQC) peer-to-peer (P2P) synchronization and companion portal engine for Linux and Android. It provides secure, decentralized clipboard synchronization, notification mirroring, file transfers, and sandboxed automation handlers.

## 🚀 Key Features

*   **Post-Quantum Hybrid Security**: Combines NIST-approved **ML-KEM-768** key encapsulation with classical **X25519** elliptic curve Diffie-Hellman (ECDH) keys for hybrid key exchange.
*   **3-Tier Connection Hierarchy**: Automatic failover between ultra-low-latency **Wi-Fi Direct**, **Local LAN (mDNS)**, and encrypted **WireGuard WAN tunnels**.
*   **Zero-Trust Local Diagnostics**: Bypasses centralized error logging (Firebase/Sentry) with an entirely local, anonymized crash reporting and diagnostics pipeline.
*   **Sandboxed Automation Engine**: Executes lightweight JavaScript scripts inside a secure, resource-limited **Boa engine** sandbox triggered by local events (e.g. ambient light changes).

---

## 📂 Project Structure

```
kyberpipe/
├── android-app/      # Kotlin/Jetpack Compose Android companion application
├── desktop-app/      # Tauri + Vue 3 Desktop frontend & Rust orchestrator
├── core-crypto/      # Core Rust cryptographic and networking engine
├── docs/             # Documentation Hub & GitHub Pages site
└── LICENSE.txt       # GNU Affero General Public License v3
```

---

## 🛠️ Getting Started

### Prerequisites

*   **Rust (stable)**: For desktop backend and cryptographic library compilation.
*   **NodeJS (v18+)** & **pnpm**: For desktop frontend dependency management.
*   **Android Studio (with SDK 34 & NDK 28.2.13676358)**: For Android compilation.

### Building Locally

#### 1. Core Crypto Engine
```bash
cd core-crypto
cargo build --release
```

#### 2. Desktop Application (Tauri + Vue 3)
```bash
cd desktop-app
pnpm install
pnpm tauri dev
```

#### 3. Android Companion Application
```bash
cd android-app
./gradlew assembleDebug
```

---

## 🔒 Zero-Trust Diagnostics Policy

All diagnostic logs and stacktraces are kept strictly on the host device. There is no telemetry transmitted to external endpoints.
*   **Log Files**: System logs are loaded to an in-memory ring buffer of 100 entries.
*   **Crash Reports**: Panics generate an anonymized `crash_log.txt` scrubbed of home directories, usernames, and IP addresses.
*   **Exports**: Export logs or crash reports to local text files on demand via the UI.

---

## 📄 License

Licensed under the **GNU Affero General Public License v3 (AGPL-3.0)**. See [LICENSE.txt](file:///home/Aelfwif/Downloads/kyberpipe/LICENSE.txt) for details.
