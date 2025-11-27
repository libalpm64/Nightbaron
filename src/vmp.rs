/*
  VMProtect SDK Rust Bindings
*/
use std::ffi::{CStr, CString};
use std::os::raw::c_char;

#[link(name = "VMProtectSDK64")]
unsafe extern "C" {
    fn VMProtectBegin(name: *const c_char);
    fn VMProtectEnd();
    fn VMProtectBeginVirtualization(name: *const c_char);
    fn VMProtectBeginMutation(name: *const c_char);
    fn VMProtectBeginUltra(name: *const c_char);
    fn VMProtectDecryptStringA(value: *const c_char) -> *const c_char;
    fn VMProtectDecryptStringW(value: *const u16) -> *const u16;
    fn VMProtectFreeString(value: *const std::ffi::c_void);
}

pub fn begin_protection(name: &str) {
    let c_name = CString::new(name).unwrap();
    unsafe { VMProtectBegin(c_name.as_ptr()) };
}

pub fn end_protection() {
    unsafe { VMProtectEnd() };
}

pub fn begin_virtualization(name: &str) {
    let c_name = CString::new(name).unwrap();
    unsafe { VMProtectBeginVirtualization(c_name.as_ptr()) };
}

pub fn begin_mutation(name: &str) {
    let c_name = CString::new(name).unwrap();
    unsafe { VMProtectBeginMutation(c_name.as_ptr()) };
}

pub fn begin_ultra(name: &str) {
    let c_name = CString::new(name).unwrap();
    unsafe { VMProtectBeginUltra(c_name.as_ptr()) };
}

pub fn decrypt_string_a(encrypted: &[u8]) -> String {
    let c_str = unsafe { CStr::from_bytes_with_nul_unchecked(encrypted) };
    let decrypted_ptr = unsafe { VMProtectDecryptStringA(c_str.as_ptr()) };
    let decrypted = unsafe { CStr::from_ptr(decrypted_ptr) }.to_string_lossy().into_owned();
    unsafe { VMProtectFreeString(decrypted_ptr as *mut std::ffi::c_void) };
    decrypted
}

pub fn decrypt_string_w(encrypted: &[u16]) -> String {
    let decrypted_ptr = unsafe { VMProtectDecryptStringW(encrypted.as_ptr()) };
    let mut len = 0;
    while unsafe { *decrypted_ptr.add(len) } != 0 { len += 1; }
    let slice = unsafe { std::slice::from_raw_parts(decrypted_ptr, len) };
    let s = String::from_utf16_lossy(slice);
    unsafe { VMProtectFreeString(decrypted_ptr as *mut std::ffi::c_void) };
    s
}

#[macro_export]
macro_rules! vmp_protect {
    ($name:expr, $code:block) => {{
        $crate::vmp::begin_protection($name);
        let result = $code;
        $crate::vmp::end_protection();
        result
    }};
}

#[macro_export]
macro_rules! vmp_virtualize {
    ($name:expr, $code:block) => {{
        $crate::vmp::begin_virtualization($name);
        let result = $code;
        $crate::vmp::end_protection();
        result
    }};
}

const ENCRYPTED_NIGHTBARON: &[u8] = b"NIGHTBARON\0"; // Placeholder - replace with encrypted
const ENCRYPTED_FILE_ENCRYPTION_SYSTEM: &[u8] = b"File Encryption System\0";
const ENCRYPTED_SELECT_FOLDER: &[u8] = b"Select a folder to encrypt:\0";
const ENCRYPTED_PASSWORD: &[u8] = b"Password:\0";
const ENCRYPTED_ENCRYPT: &[u8] = b"ENCRYPT\0";
const ENCRYPTED_SELECT_FILE: &[u8] = b"Select a .nightbaron file to decrypt:\0";
const ENCRYPTED_DECRYPT: &[u8] = b"DECRYPT\0";

pub fn decrypt_ui_string(encrypted: &[u8]) -> String {
    decrypt_string_a(encrypted)
}

pub fn ui_str_nightbaron() -> String {
    decrypt_ui_string(ENCRYPTED_NIGHTBARON)
}

pub fn ui_str_file_encryption_system() -> String {
    decrypt_ui_string(ENCRYPTED_FILE_ENCRYPTION_SYSTEM)
}

pub fn ui_str_select_folder() -> String {
    decrypt_ui_string(ENCRYPTED_SELECT_FOLDER)
}

pub fn ui_str_password() -> String {
    decrypt_ui_string(ENCRYPTED_PASSWORD)
}

pub fn ui_str_encrypt() -> String {
    decrypt_ui_string(ENCRYPTED_ENCRYPT)
}

pub fn ui_str_select_file() -> String {
    decrypt_ui_string(ENCRYPTED_SELECT_FILE)
}

pub fn ui_str_decrypt() -> String {
    decrypt_ui_string(ENCRYPTED_DECRYPT)
}

#[macro_export]
macro_rules! vmp_mutate {
    ($name:expr, $code:block) => {{
        $crate::vmp::begin_mutation($name);
        let result = $code;
        $crate::vmp::end_protection();
        result
    }};
}

#[macro_export]
macro_rules! vmp_ultra {
    ($name:expr, $code:block) => {{
        $crate::vmp::begin_ultra($name);
        let result = $code;
        $crate::vmp::end_protection();
        result
    }};
}