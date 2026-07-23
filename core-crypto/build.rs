fn main() {
    let target = std::env::var("TARGET").unwrap_or_default();
    if target.contains("android") {
        if let Ok(ndk_home) = std::env::var("ANDROID_NDK_HOME") {
            let lib_dir = format!(
                "{}/toolchains/llvm/prebuilt/linux-x86_64/sysroot/usr/lib/aarch64-linux-android",
                ndk_home
            );
            println!("cargo:rustc-link-search=native={}", lib_dir);
            println!("cargo:rustc-link-lib=static=c++_static");
        }
    }
}
