use std::io::{self, Write};

use jni::objects::{JByteArray, JClass};
use jni::sys::{jint, jstring};
use jni::JNIEnv;

fn debug(msg: &str) {
    let _ = writeln!(&mut io::stderr(), "[qr_scanner] {msg}");
}

/// AUDIT F11 (LOW): single-pass rotation helpers. The legacy 180°/270°
/// variants composed `rotate_90` calls, allocating an intermediate full-frame
/// buffer per step (up to 3 allocations for one rotation). Each of these
/// rotates directly into the caller-provided scratch buffer.
fn rotate_90_into(luma: &[u8], w: usize, h: usize, out: &mut [u8]) {
    // Output is H×W (h columns, w rows).
    for y in 0..h {
        for x in 0..w {
            out[x * h + (h - 1 - y)] = luma[y * w + x];
        }
    }
}

#[cfg(test)]
fn rotate_90(luma: &[u8], w: usize, h: usize) -> Vec<u8> {
    let mut out = vec![0u8; w * h];
    rotate_90_into(luma, w, h, &mut out);
    out
}

fn rotate_180_into(luma: &[u8], w: usize, h: usize, out: &mut [u8]) {
    // Output is W×H. Single pass — no intermediate allocation.
    for y in 0..h {
        for x in 0..w {
            out[(h - 1 - y) * w + (w - 1 - x)] = luma[y * w + x];
        }
    }
}

#[cfg(test)]
fn rotate_180(luma: &[u8], w: usize, h: usize) -> Vec<u8> {
    let mut out = vec![0u8; w * h];
    rotate_180_into(luma, w, h, &mut out);
    out
}

fn rotate_270_into(luma: &[u8], w: usize, h: usize, out: &mut [u8]) {
    // Output is H×W (270° clockwise = 90° counter-clockwise). Single pass.
    for y in 0..w {
        for x in 0..h {
            out[y * h + x] = luma[x * w + (w - 1 - y)];
        }
    }
}

#[cfg(test)]
fn rotate_270(luma: &[u8], w: usize, h: usize) -> Vec<u8> {
    let mut out = vec![0u8; w * h];
    rotate_270_into(luma, w, h, &mut out);
    out
}

fn try_decode(luma: &[u8], w: usize, h: usize) -> Option<String> {
    let mut img = rqrr::PreparedImage::prepare_from_greyscale(w, h, |x, y| luma[y * w + x]);
    let grids = img.detect_grids();
    debug(&format!("detect_grids: {} found", grids.len()));
    for g in &grids {
        match g.decode() {
            Ok((_meta, content)) => {
                if !content.is_empty() {
                    debug(&format!("decoded {} chars", content.len()));
                    return Some(content);
                }
            }
            Err(e) => debug(&format!("grid decode error: {e:?}")),
        }
    }
    None
}

#[no_mangle]
#[allow(non_snake_case)]
pub extern "system" fn Java_org_kyberpipe_client_QrNative_decodeQrCode<'local>(
    env: JNIEnv<'local>,
    _class: JClass<'local>,
    y_bytes: JByteArray<'local>,
    width: jint,
    height: jint,
    stride: jint,
    rotation: jint,
) -> jstring {
    // Audit finding #13/#17: a panic must NEVER unwind across the JNI boundary
    // (undefined behavior). The release profile is `panic = "unwind"`, so
    // `catch_unwind` is the containment mechanism — a panic inside the decoder
    // is converted to a null return instead of aborting the process. The
    // caller (QrCodeScannerView) treats null as "no code detected".
    let outcome = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
        let w = width as usize;
        let h = height as usize;
        let stride = if stride <= 0 { w } else { stride as usize };

        // AUDIT #2 (follow-up, LOW): the dimensions come from the untrusted
        // JNI boundary. A panic from OOB indexing is contained by catch_unwind,
        // but a huge allocation (e.g. 46341x46341 ~ 2 GiB) triggers an
        // ALLOCATION failure which is NOT unwindable — it ABORTS the whole
        // app (memory-pressure DoS). Validate every dimension against
        // stride/overflow/cap and the actual buffer length BEFORE any
        // allocation or indexing.
        if w == 0 || h == 0 {
            debug("decodeQrCode: zero dimensions");
            return None;
        }
        if stride < w {
            debug("decodeQrCode: stride < width");
            return None;
        }
        // Overflow check + per-frame pixel cap (4 MP). Keeps every rotation
        // allocation bounded regardless of caller-supplied dimensions.
        let pixels = match w.checked_mul(h) {
            Some(p) if p <= 4_000_000 => p,
            _ => {
                debug("decodeQrCode: dimension overflow / over 4 MP cap");
                return None;
            }
        };

        debug(&format!(
            "decodeQrCode: {}x{} stride={} rot={}",
            w, h, stride, rotation
        ));

        let bytes = match env.convert_byte_array(&y_bytes) {
            Ok(b) => b,
            Err(_) => {
                debug("convert_byte_array FAILED");
                return None;
            }
        };

        debug(&format!("y_bytes len={}", bytes.len()));

        // The framed buffer must actually be large enough for every row
        // (`stride*(h-1) + w`, overflow-checked). Else the row extraction below
        // silently drops rows — a sign the caller passed inconsistent dims.
        let needed = stride
            .checked_mul(h.saturating_sub(1))
            .and_then(|n| n.checked_add(w));
        match needed {
            Some(n) if n <= bytes.len() => {}
            _ => {
                debug("decodeQrCode: y_bytes too small for stride+width");
                return None;
            }
        }

        // strip stride padding
        let luma: Vec<u8> = if stride == w {
            bytes
        } else {
            let mut clean = Vec::with_capacity(pixels);
            for row in 0..h {
                let start = row * stride;
                if start + w <= bytes.len() {
                    clean.extend_from_slice(&bytes[start..start + w]);
                }
            }
            clean
        };

        // AUDIT F11 (LOW): decode the UNROTATED frame FIRST — the common case
        // is a single decode of the buffer the JNI layer already handed over
        // (ZERO full-frame copies). Only on failure are the rotations
        // attempted, and all of them share ONE scratch buffer (a single
        // full-frame allocation instead of up to four per camera frame). The
        // camera's rotation hint only reorders the FALLBACK attempts so a
        // genuinely-rotated frame is found right after the first (failed)
        // unrotated decode.
        let mut result = try_decode(&luma, w, h);
        if result.is_none() {
            let mut scratch = vec![0u8; pixels];
            type RotFn = fn(&[u8], usize, usize, &mut [u8]);
            // (rotation function, output width, output height)
            let order: [(RotFn, usize, usize); 3] = match rotation {
                90 => [
                    (rotate_90_into, h, w),
                    (rotate_180_into, w, h),
                    (rotate_270_into, h, w),
                ],
                180 => [
                    (rotate_180_into, w, h),
                    (rotate_90_into, h, w),
                    (rotate_270_into, h, w),
                ],
                270 => [
                    (rotate_270_into, h, w),
                    (rotate_90_into, h, w),
                    (rotate_180_into, w, h),
                ],
                _ => [
                    (rotate_90_into, h, w),
                    (rotate_180_into, w, h),
                    (rotate_270_into, h, w),
                ],
            };
            for (rot, ow, oh) in order {
                rot(&luma, w, h, &mut scratch);
                result = try_decode(&scratch, ow, oh);
                if result.is_some() {
                    break;
                }
            }
        }

        match result {
            Some(text) => match env.new_string(&text) {
                Ok(s) => Some(s.into_raw()),
                Err(_) => {
                    debug("new_string FAILED");
                    None
                }
            },
            None => {
                debug("all attempts failed");
                None
            }
        }
    }));
    match outcome {
        Ok(Some(raw)) => raw,
        _ => {
            debug("QR decode contained by panic catch_unwind — returning null");
            std::ptr::null_mut()
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_rotations() {
        let w = 4;
        let h = 3;
        let luma = vec![1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12];
        let r90 = rotate_90(&luma, w, h);
        assert_eq!(r90.len(), 12);
        let r180 = rotate_180(&luma, w, h);
        assert_eq!(r180.len(), 12);
        let r270 = rotate_270(&luma, w, h);
        let r360 = rotate_90(&r270, h, w);
        assert_eq!(luma, r360);
    }
}
