package org.kyberpipe.client.security

/**
 * REMOVED: ZeroizingString is fundamentally incompatible with the JVM memory model.
 *
 * Kotlin String is immutable and JVM-managed — the underlying char[] is never
 * exposed outside the String, so no explicit zeroization is possible. Every
 * constructor call creates a String copy on the caller's stack that escapes
 * zeroization, and every access to `value` creates yet another String.
 *
 * For Android, the only reliable approaches are:
 * 1. Keep secrets in native Rust memory via UniFFI and expose handles/IDs
 *    to Kotlin — never the raw bytes.
 * 2. Use ByteArray and explicitly fill() after use (best-effort; GC copies
 *    may persist).
 * 3. Accept that Java heap secrets are not zeroizable within the JVM.
 *
 * See audit issue #9 (FFI/cross-boundary contract drift).
 */
@Deprecated("Cannot zeroize within JVM. Use native Rust handles instead.")
class ZeroizingString
