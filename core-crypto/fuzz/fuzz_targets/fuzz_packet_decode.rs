#![no_main]

use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    // Guarantees parser NEVER panics on arbitrary untrusted bytes
    let _ = core_crypto::packets::safe_decode_packet(data);
});
