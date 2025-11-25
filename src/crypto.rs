use argon2::{Argon2, Params, Algorithm, Version};
use chacha20poly1305::{
    aead::{Aead, KeyInit},
    ChaCha20Poly1305, Key, Nonce
};
use rand::RngCore;
use std::fs::{self, File};
use std::io::{self, Read, Write, BufReader, BufWriter};
use std::path::Path;

use tar::Builder;
use zeroize::{Zeroize, ZeroizeOnDrop};


#[cfg(unix)]
use libc::{mlock, munlock};

#[cfg(windows)]
use windows_sys::Win32::System::Memory::{VirtualLock, VirtualUnlock};

const CHUNK_SIZE: usize = 64 * 1024 * 1024;
const SALT_LEN: usize = 16;
const NONCE_LEN: usize = 12;

#[derive(Zeroize, ZeroizeOnDrop)]
struct SensitiveData(Vec<u8>);

fn pin_memory(data: &mut [u8]) -> Result<(), String> {
    if data.is_empty() {
        return Ok(());
    }
    let ptr = data.as_mut_ptr() as *mut std::ffi::c_void;
    let len = data.len();
    #[cfg(unix)]
    {
        if unsafe { mlock(ptr, len) } != 0 {
            return Err("Failed to mlock".to_string());
        }
        Ok(())
    }
    #[cfg(windows)]
    {
        if unsafe { VirtualLock(ptr, len) } == 0 {
            return Err("Failed to VirtualLock".to_string());
        }
        Ok(())
    }
    #[cfg(not(any(unix, windows)))]
    Err("Unsupported platform".to_string())
}

fn unpin_memory(data: &mut [u8]) -> Result<(), String> {
    if data.is_empty() {
        return Ok(());
    }
    let ptr = data.as_mut_ptr() as *mut std::ffi::c_void;
    let len = data.len();
    #[cfg(unix)]
    {
        if unsafe { munlock(ptr, len) } != 0 {
            return Err("Failed to munlock".to_string());
        }
        Ok(())
    }
    #[cfg(windows)]
    {
        if unsafe { VirtualUnlock(ptr, len) } == 0 {
            return Err("Failed to VirtualUnlock".to_string());
        }
        Ok(())
    }
    #[cfg(not(any(unix, windows)))]
    Err("Unsupported platform".to_string())
}

pub struct EncryptionOptions {
    pub custom_salt: Option<String>,
    pub delete_original: bool,
}

pub fn derive_key(secret_input: &[u8], salt: &[u8]) -> [u8; 32] {
    let memory_kib = 8 * 1024 * 1024;
    let time_cost = 3;
    let parallelism = 1;
    let output_len = Some(32);

    let params = Params::new(memory_kib, time_cost, parallelism, output_len)
        .expect("Invalid Argon2 parameters");

    let argon = Argon2::new(Algorithm::Argon2id, Version::V0x13, params);

    let mut out = [0u8; 32];
    argon.hash_password_into(secret_input, salt, &mut out)
        .expect("Argon2id hashing failed");
    out
}

pub fn encrypt_folder(folder_path: &str, password: &str, options: EncryptionOptions) -> io::Result<String> {
    let path = Path::new(folder_path);
    if !path.exists() || !path.is_dir() {
        return Err(io::Error::new(io::ErrorKind::NotFound, "Folder not found"));
    }

    let folder_name = path.file_name().unwrap().to_str().unwrap();
    let tar_filename = format!("{}.tar", folder_name);
    let output_filename = format!("{}.nightbaron", folder_name);

    {
        let tar_file = File::create(&tar_filename)?;
        let mut tar_builder = Builder::new(tar_file);
        tar_builder.append_dir_all(folder_name, folder_path)?;
        tar_builder.finish()?;
    }

    let mut salt = [0u8; SALT_LEN];
    if let Some(custom) = options.custom_salt {
        let bytes = custom.as_bytes();
        if bytes.len() >= SALT_LEN {
            salt.copy_from_slice(&bytes[..SALT_LEN]);
        } else {
            salt[..bytes.len()].copy_from_slice(bytes);
            rand::thread_rng().fill_bytes(&mut salt[bytes.len()..]);
        }
    } else {
        rand::thread_rng().fill_bytes(&mut salt);
    }
    
    let mut key_bytes = SensitiveData(derive_key(password.as_bytes(), &salt).to_vec());
    pin_memory(&mut key_bytes.0).map_err(|e| io::Error::new(io::ErrorKind::Other, e))?;
    pin_memory(&mut key_bytes.0).map_err(|e| io::Error::new(io::ErrorKind::Other, e))?;
    let key = Key::from_slice(&key_bytes.0);
    let cipher = ChaCha20Poly1305::new(key);

    let input_file = File::open(&tar_filename)?;
    let mut reader = BufReader::new(input_file);
    let output_file = File::create(&output_filename)?;
    let mut writer = BufWriter::new(output_file);

    writer.write_all(&salt)?;

    let mut buffer = SensitiveData(vec![0u8; CHUNK_SIZE]);
    
    loop {
        let bytes_read = reader.read(&mut buffer.0)?;
        if bytes_read == 0 { break; }

        let mut nonce_bytes = [0u8; NONCE_LEN];
        rand::thread_rng().fill_bytes(&mut nonce_bytes);
        let nonce = Nonce::from_slice(&nonce_bytes);

        let ciphertext = cipher.encrypt(nonce, &buffer.0[..bytes_read])
            .map_err(|e| io::Error::new(io::ErrorKind::Other, e.to_string()))?;

        writer.write_all(&nonce_bytes)?;
        let len = ciphertext.len() as u32;
        writer.write_all(&len.to_le_bytes())?;
        writer.write_all(&ciphertext)?;
    }

    let _ = unpin_memory(&mut key_bytes.0);
let _ = unpin_memory(&mut key_bytes.0);
key_bytes.zeroize();
    buffer.zeroize();

    fs::remove_file(&tar_filename)?;

    if options.delete_original {
        fs::remove_dir_all(path)?;
    }

    Ok(output_filename)
}

pub fn decrypt_file(file_path: &str, password: &str) -> io::Result<String> {
    let input_file = File::open(file_path)?;
    let mut reader = BufReader::new(input_file);

    let mut salt = [0u8; SALT_LEN];
    reader.read_exact(&mut salt)?;

    let mut key_bytes = SensitiveData(derive_key(password.as_bytes(), &salt).to_vec());
    let key = Key::from_slice(&key_bytes.0);
    let cipher = ChaCha20Poly1305::new(key);

    let output_tar = file_path.replace(".nightbaron", ".tar");
    
    {
        let output_file = File::create(&output_tar)?;
        let mut writer = BufWriter::new(output_file);

        loop {
            let mut nonce_bytes = [0u8; NONCE_LEN];
            match reader.read_exact(&mut nonce_bytes) {
                Ok(_) => {},
                Err(ref e) if e.kind() == io::ErrorKind::UnexpectedEof => break,
                Err(e) => return Err(e),
            }
            let nonce = Nonce::from_slice(&nonce_bytes);

            let mut len_bytes = [0u8; 4];
            reader.read_exact(&mut len_bytes)?;
            let len = u32::from_le_bytes(len_bytes) as usize;

            let mut ciphertext = vec![0u8; len];
            reader.read_exact(&mut ciphertext)?;

            let mut plaintext = SensitiveData(
                cipher.decrypt(nonce, ciphertext.as_ref())
                    .map_err(|e| io::Error::new(io::ErrorKind::Other, format!("Decryption failed: {}", e)))?
            );

            writer.write_all(&plaintext.0)?;
            plaintext.zeroize();
        }
        writer.flush()?;
    }

    key_bytes.zeroize();

    let tar_file = File::open(&output_tar)?;
    let mut archive = tar::Archive::new(tar_file);
    archive.unpack(".")?;
    
    fs::remove_file(&output_tar)?;
    Ok("Done!".to_string())
}