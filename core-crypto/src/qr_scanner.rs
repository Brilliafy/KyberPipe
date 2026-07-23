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
            clean.extend_from_slice(&bytes[start..start + w]);
        }
        clean
    };

    let result = if rotation == 90 || rotation == 270 {
        debug("trying rotated 90°");
        let rotated = rotate_90(&luma, w, h);
        try_decode(&rotated, h, w).or_else(|| {
            debug("rotated failed, trying original");
            try_decode(&luma, w, h)
        })
    } else if rotation == 180 {
        debug("trying rotated 180°");
        let r1 = rotate_90(&luma, w, h);
        let r2 = rotate_90(&r1, h, w);
        try_decode(&r2, w, h).or_else(|| {
            debug("rotated failed, trying original");
            try_decode(&luma, w, h)
        })
    } else {
        try_decode(&luma, w, h)
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
