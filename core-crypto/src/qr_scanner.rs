use std::collections::HashSet;
use std::io::{self, Write};

use jni::objects::{JByteArray, JClass};
use jni::sys::{jint, jstring};
use jni::JNIEnv;
use rxing::common::{GlobalHistogramBinarizer, HybridBinarizer};
use rxing::qrcode::QRCodeReader;
use rxing::{BarcodeFormat, BinaryBitmap, DecodeHints, Luma8LuminanceSource, RXingResult, Reader};

fn debug(msg: &str) {
    let _ = writeln!(&mut io::stderr(), "[qr_scanner] {msg}");
}

fn strip_stride(y_bytes: &[u8], width: usize, height: usize, stride: usize) -> Vec<u8> {
    if stride == width {
        return y_bytes.to_vec();
    }
    let mut clean = Vec::with_capacity(width * height);
    for row in 0..height {
        let start = row * stride;
        clean.extend_from_slice(&y_bytes[start..start + width]);
    }
    clean
}

fn rotate_90(luma: &[u8], w: usize, h: usize) -> Vec<u8> {
    let mut rotated = vec![0u8; w * h];
    for y in 0..h {
        for x in 0..w {
            rotated[x * h + (h - 1 - y)] = luma[y * w + x];
        }
    }
    debug(&format!("rotate_90: {}x{} -> {}x{}", w, h, h, w));
    rotated
}

fn decode_luma(luma: &[u8], w: usize, h: usize) -> Option<RXingResult> {
    debug(&format!("decode_luma: {}x{} ({} bytes)", w, h, luma.len()));
    let hints = DecodeHints {
        TryHarder: Some(true),
        PossibleFormats: Some(HashSet::from([BarcodeFormat::QR_CODE])),
        ..Default::default()
    };
    let src = Luma8LuminanceSource::new(luma.to_vec(), w as u32, h as u32);
    let mut bitmap = BinaryBitmap::new(HybridBinarizer::new(src));
    let mut reader = QRCodeReader::default();
    match reader.decode_with_hints(&mut bitmap, &hints) {
        Ok(r) => {
            debug("HybridBinarizer OK");
            return Some(r);
        }
        Err(e) => debug(&format!("HybridBinarizer fail: {e:?}")),
    }
    let src2 = Luma8LuminanceSource::new(luma.to_vec(), w as u32, h as u32);
    let mut bitmap2 = BinaryBitmap::new(GlobalHistogramBinarizer::new(src2));
    match reader.decode_with_hints(&mut bitmap2, &hints) {
        Ok(r) => {
            debug("GlobalHistogramBinarizer OK");
            return Some(r);
        }
        Err(e) => debug(&format!("GlobalHistogramBinarizer fail: {e:?}")),
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
    let luma = strip_stride(&bytes, w, h, stride);
    debug(&format!("stripped luma len={}", luma.len()));

    let result = if rotation == 90 || rotation == 270 {
        let rotated = rotate_90(&luma, w, h);
        let r = decode_luma(&rotated, h, w);
        if r.is_some() {
            r
        } else {
            debug("rotated failed, trying unrotated");
            decode_luma(&luma, w, h)
        }
    } else if rotation == 180 {
        let rotated = rotate_90(&rotate_90(&luma, w, h), w, h);
        let r = decode_luma(&rotated, w, h);
        if r.is_some() {
            r
        } else {
            debug("rotated180 failed, trying unrotated");
            decode_luma(&luma, w, h)
        }
    } else {
        decode_luma(&luma, w, h)
    };

    match result {
        Some(r) => {
            let text = r.getText();
            let len = text.len();
            debug(&format!("SUCCESS: {} chars", len));
            if !text.is_empty() {
                match env.new_string(text) {
                    Ok(output) => return output.into_raw(),
                    Err(_) => {
                        debug("new_string FAILED");
                        return std::ptr::null_mut();
                    }
                }
            }
            debug("text is empty");
            std::ptr::null_mut()
        }
        None => {
            debug("all decoders returned None");
            std::ptr::null_mut()
        }
    }
}
