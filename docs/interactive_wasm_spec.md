# Kyberpipe Interactive WASM Playground & Documentation Architecture

This specification outlines the integration of `core-crypto` compiled to WebAssembly (via `wasm-pack`) to enable live, client-side, post-quantum key exchange and double-ratchet encryption demos directly in the browser.

---

## 1. WebAssembly Integration Specs

### Compiling to WASM (`wasm-pack`)
To target the browser, compile `core-crypto` with the `wasm` attribute enabled:
```bash
wasm-pack build --target web --out-dir ../docs/wasm-assets
```

### JS/WASM API Bindings (`core-crypto/src/wasm.rs`)
Expose the key exchange and ratcheting operations via Rust `wasm-bindgen` bindings:
```rust
use wasm_bindgen::prelude::*;

#[wasm_bindgen]
pub struct WasmSession {
    state: core_crypto::crypto::DoubleRatchetState,
}

#[wasm_bindgen]
impl WasmSession {
    #[wasm_bindgen(constructor)]
    pub fn new() -> Result<WasmSession, JsValue> {
        let (state, _) = core_crypto::crypto::DoubleRatchetState::new_initiator()?;
        Ok(WasmSession { state })
    }

    pub fn encrypt_payload(&mut self, data: &[u8]) -> Result<Vec<u8>, JsValue> {
        let ciphertext = self.state.encrypt_next(data)?;
        Ok(ciphertext)
    }

    pub fn decrypt_payload(&mut self, ciphertext: &[u8]) -> Result<Vec<u8>, JsValue> {
        let plaintext = self.state.decrypt_next(ciphertext)?;
        Ok(plaintext)
    }
}
```

---

## 2. Interactive Browser Showcase

Recruiters and developers can play with the cryptographic pipeline instantly on the live site:

```
               +--------------------------------------+
               |          Plaintext Input Box         |
               |  "Sovereign communications rule!"    |
               +--------------------------------------+
                                  |
                                  v
                   [ WASM Client-Side Encryption ]
                 (NIST ML-KEM-768 + ChaCha20-Poly1305)
                                  |
                                  v
               +--------------------------------------+
               |         Hex Ciphertext Output        |
               |  0x5f81ae89a0b127... (Fenced)       |
               +--------------------------------------+
```

---

## 3. i18n & Accessibility Compliance

- **Multi-Language Support (i18n)**: Locale files (`en.json`, `de.json`, `el.json`) localize all visual UI widgets.
- **a11y Compliance**: Fully compatible with WCAG 2.1 AA screen-reader standards utilizing semantic HTML, key focus states, and aria attributes.
