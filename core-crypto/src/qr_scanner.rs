use std::io::{self, Write};

use jni::objects::{JByteArray, JClass};
use jni::sys::{jint, jstring};
use jni::JNIEnv;

fn debug(msg: &str) {
    let _ = writeln!(&mut io::stderr(), "[qr_scanner] {msg}");
}

fn rotate_90(luma: &[u8], w: usize, h: usize) -> Vec<u8> {
    let mut out = vec![0u8; w * h];
    for y in 0..h {
        for x in 0..w {
            out[x * h + (h - 1 - y)] = luma[y * w + x];
        }
    }
    out
}

fn rotate_180(luma: &[u8], w: usize, h: usize) -> Vec<u8> {
    let r1 = rotate_90(luma, w, h);
    rotate_90(&r1, h, w)
}

fn rotate_270(luma: &[u8], w: usize, h: usize) -> Vec<u8> {
    let r1 = rotate_90(luma, w, h);
    let r2 = rotate_90(&r1, h, w);
    rotate_90(&r2, w, h)
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
    let w = width as usize;
    let h = height as usize;
    let stride = if stride <= 0 { w } else { stride as usize };

    debug(&format!(
        "decodeQrCode: {}x{} stride={} rot={}",
        w, h, stride, rotation
    ));

    let bytes = match env.convert_byte_array(&y_bytes) {
        Ok(b) => b,
        Err(_) => {
            debug("convert_byte_array FAILED");
            return std::ptr::null_mut();
        }
    };

    debug(&format!("y_bytes len={}", bytes.len()));

    // strip stride padding
    let luma: Vec<u8> = if stride == w {
        bytes
    } else {
        let mut clean = Vec::with_capacity(w * h);
        for row in 0..h {
            let start = row * stride;
            if start + w <= bytes.len() {
                clean.extend_from_slice(&bytes[start..start + w]);
            }
        }
        clean
    };

    let result = match rotation {
        90 => try_decode(&rotate_90(&luma, w, h), h, w)
            .or_else(|| try_decode(&luma, w, h))
            .or_else(|| try_decode(&rotate_180(&luma, w, h), w, h))
            .or_else(|| try_decode(&rotate_270(&luma, w, h), h, w)),
        180 => try_decode(&rotate_180(&luma, w, h), w, h)
            .or_else(|| try_decode(&luma, w, h))
            .or_else(|| try_decode(&rotate_90(&luma, w, h), h, w))
            .or_else(|| try_decode(&rotate_270(&luma, w, h), h, w)),
        270 => try_decode(&rotate_270(&luma, w, h), h, w)
            .or_else(|| try_decode(&luma, w, h))
            .or_else(|| try_decode(&rotate_90(&luma, w, h), h, w))
            .or_else(|| try_decode(&rotate_180(&luma, w, h), w, h)),
        _ => try_decode(&luma, w, h)
            .or_else(|| try_decode(&rotate_90(&luma, w, h), h, w))
            .or_else(|| try_decode(&rotate_180(&luma, w, h), w, h))
            .or_else(|| try_decode(&rotate_270(&luma, w, h), h, w)),
    };

    match result {
        Some(text) => match env.new_string(&text) {
            Ok(s) => s.into_raw(),
            Err(_) => {
                debug("new_string FAILED");
                std::ptr::null_mut()
            }
        },
        None => {
            debug("all attempts failed");
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
