# KyberPipe Cryptographic & Protocol Core

`core-crypto` is the underlying engine written in Rust that powers secure peer-to-peer tunnels, key exchange protocols, and cryptographic primitives.

## 🔑 Security Architecture

*   **Hybrid KEM Protocol**:
    *   **NIST ML-KEM-768**: Quantum-resistant Key Encapsulation Mechanism.
    *   **X25519**: Classical ECDH exchange acting as a safety fallback.
*   **Symmetric Encryption Layer**:
    *   Once the shared secret is derived using **HKDF-SHA256**, messages are encrypted using **ChaCha20-Poly1305** for high-speed local throughput.
*   **UniFFI Bindings**:
    *   Exposes secure wrappers to compile bindings for Kotlin/Android natively.

---

## ⚙️ Compilation

To build `core-crypto` standalone:
```bash
cargo build --release
```

To compile/generate UniFFI Kotlin bindings for the Android app:
```bash
cargo run --bin uniffi-bindgen generate --library target/release/libcore_crypto.so --language kotlin --out-dir ../android-app/app/src/main/java/
```
