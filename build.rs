fn main() {
    let target_os = std::env::var("CARGO_CFG_TARGET_OS").unwrap();
    println!("cargo:rustc-link-search=native=sdk");
    if target_os == "windows" {
        println!("cargo:rustc-link-lib=static=VMProtectSDK64");
    } else if target_os == "linux" {
        println!("cargo:rustc-link-lib=dylib=VMProtectSDK64");
    }
}