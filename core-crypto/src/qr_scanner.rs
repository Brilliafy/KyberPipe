use std::collections::HashSet;

use jni::objects::{JByteArray, JClass};
use jni::sys::{jint, jstring};
use jni::JNIEnv;
use rxing::common::{GlobalHistogramBinarizer, HybridBinarizer};
use rxing::qrcode::QRCodeReader;
use rxing::{BarcodeFormat, BinaryBitmap, DecodeHints, Luma8LuminanceSource, RXingResult, Reader};

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
    rotated
}

fn decode_luma(luma: &[u8], w: usize, h: usize) -> Option<RXingResult> {
    let hints = DecodeHints {
        TryHarder: Some(true),
        PossibleFormats: Some(HashSet::from([BarcodeFormat::QR_CODE])),
        ..Default::default()
    };
    let src = Luma8LuminanceSource::new(luma.to_vec(), w as u32, h as u32);
    let mut bitmap = BinaryBitmap::new(HybridBinarizer::new(src));
    let mut reader = QRCodeReader::default();
    if let Ok(r) = reader.decode_with_hints(&mut bitmap, &hints) {
        return Some(r);
    }
    let src2 = Luma8LuminanceSource::new(luma.to_vec(), w as u32, h as u32);
    let mut bitmap2 = BinaryBitmap::new(GlobalHistogramBinarizer::new(src2));
    if let Ok(r) = reader.decode_with_hints(&mut bitmap2, &hints) {
        return Some(r);
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

    let bytes = match env.convert_byte_array(&y_bytes) {
        Ok(b) => b,
        Err(_) => return std::ptr::null_mut(),
    };

    let luma = strip_stride(&bytes, w, h, stride);

    let result = if rotation == 90 || rotation == 270 {
        let rotated = rotate_90(&luma, w, h);
        decode_luma(&rotated, h, w).or_else(|| decode_luma(&luma, w, h))
    } else if rotation == 180 {
        let rotated = rotate_90(&rotate_90(&luma, w, h), w, h);
        decode_luma(&rotated, w, h).or_else(|| decode_luma(&luma, w, h))
    } else {
        decode_luma(&luma, w, h)
    };

    match result {
        Some(r) => {
            let text = r.getText();
            if !text.is_empty() {
                if let Ok(output) = env.new_string(text) {
                    return output.into_raw();
                }
            }
            std::ptr::null_mut()
        }
        None => std::ptr::null_mut(),
    }
}
