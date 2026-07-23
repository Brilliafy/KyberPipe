use std::io::{self, Write};

use jni::objects::{JByteArray, JClass};
use jni::sys::{jint, jstring};
use jni::JNIEnv;
use zxingcpp::{read, BarcodeFormat, ImageFormat, ImageView};

fn debug(msg: &str) {
    let _ = writeln!(&mut io::stderr(), "[qr_scanner] {msg}");
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
    _rotation: jint,
) -> jstring {
    let w = width as u32;
    let h = height as u32;
    let row_stride = if stride <= 0 { w as i32 } else { stride };

    debug(&format!("decodeQrCode: {}x{} stride={}", w, h, row_stride));

    let bytes = match env.convert_byte_array(&y_bytes) {
        Ok(b) => b,
        Err(_) => {
            debug("convert_byte_array FAILED");
            return std::ptr::null_mut();
        }
    };

    debug(&format!("y_bytes len={}", bytes.len()));

    let image = unsafe {
        match ImageView::from_ptr(bytes.as_ptr(), w, h, ImageFormat::Lum, row_stride, 1) {
            Ok(img) => img,
            Err(e) => {
                debug(&format!("ImageView::from_ptr FAILED: {e:?}"));
                return std::ptr::null_mut();
            }
        }
    };

    let reader = read()
        .formats(&[BarcodeFormat::QRCode])
        .try_harder(true)
        .try_rotate(true);

    let barcodes = match reader.from(&image) {
        Ok(b) => b,
        Err(e) => {
            debug(&format!("reader.from FAILED: {e:?}"));
            return std::ptr::null_mut();
        }
    };

    if barcodes.is_empty() {
        debug("no barcodes found");
        return std::ptr::null_mut();
    }

    for barcode in &barcodes {
        debug(&format!(
            "barcode: format={:?} valid={} text_len={}",
            barcode.format(),
            barcode.is_valid(),
            barcode.text().len()
        ));
    }

    if let Some(barcode) = barcodes.into_iter().next() {
        if barcode.is_valid() {
            let text = barcode.text();
            debug(&format!("SUCCESS: {} chars", text.len()));
            match env.new_string(text) {
                Ok(output) => return output.into_raw(),
                Err(_) => {
                    debug("new_string FAILED");
                    return std::ptr::null_mut();
                }
            }
        }
    }

    debug("no valid barcode found");
    std::ptr::null_mut()
}
