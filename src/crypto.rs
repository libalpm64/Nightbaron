use argon2::{Argon2, Params, Algorithm, Version};
use chacha20poly1305::{
    aead::{Aead, KeyInit},
    ChaCha20Poly1305, Key, Nonce
};
use rand::RngCore;
use std::ffi::OsStr;
use std::fs::{self, File};
use std::io::{self, Read, Write, BufReader, BufWriter, Cursor};
use std::path::{Path, PathBuf};
use walkdir::WalkDir;

use tar::Builder;
use zeroize::{Zeroize, ZeroizeOnDrop};
use xz2::write::XzEncoder; 
use xz2::read::XzDecoder;
use zstd::stream::write::Encoder as ZstdEncoder;
use zstd::stream::read::Decoder as ZstdDecoder;

const SALT_LEN: usize = 16;
const NONCE_LEN: usize = 12;

#[derive(Zeroize, ZeroizeOnDrop)]
struct SensitiveData(Vec<u8>);

#[derive(Debug, Clone, Copy, PartialEq)]
pub enum Argon2Difficulty {
    Light,
    Low,
    Medium,
    Hard,
    Paranoid,
}

#[derive(Debug, Clone, Copy, PartialEq)]
pub enum CompressionMethod {
    Xz,
    Zstd,
}

pub struct EncryptionOptions {
    pub custom_salt: Option<String>,
    pub delete_original: bool,
    pub difficulty: Argon2Difficulty,
    pub compression_method: CompressionMethod,
    pub compression_level: u32, // 0-9 for XZ, 1-21 for ZSTD (though we might map 0-9 to decent zstd levels)
    pub split_size: Option<usize>,
    pub block_size: usize,
}

fn is_already_compressed(path: &Path) -> bool {
    let skip_extensions = [
        "jpg", "jpeg", "png", "gif", "webp", "heic",
        "mp4", "mkv", "avi", "mov", "webm",
        "mp3", "aac", "wav", "flac", "ogg",
        "zip", "7z", "rar", "gz", "zst", "xz",
        "gpg", "enc"
    ];

    if let Some(ext) = path.extension().and_then(OsStr::to_str) {
        let ext_lower = ext.to_lowercase();
        return skip_extensions.contains(&ext_lower.as_str());
    }

    false
}

pub fn should_compress<F>(folder_path: &str, report_progress: F) -> bool 
where F: Fn(String) {
    let mut compressed_size: u64 = 0;
    let mut total_size: u64 = 0;
    let mut file_count = 0;

    for entry in WalkDir::new(folder_path).into_iter().filter_map(|e| e.ok()) {
        if entry.file_type().is_file() {
            file_count += 1;
            if file_count % 100 == 0 {
                report_progress(format!("Analyzing file {}...", file_count));
            }
            
            let size = entry.metadata().map(|m| m.len()).unwrap_or(0);
            total_size += size;
            if is_already_compressed(entry.path()) {
                compressed_size += size;
            }
        }
    }

    if total_size == 0 {
        return true;
    }

    (compressed_size as f64 / total_size as f64) < 0.5
}

pub fn derive_key(secret_input: &[u8], salt: &[u8], difficulty: Argon2Difficulty) -> [u8; 32] {
    let memory_kib = match difficulty {
        Argon2Difficulty::Light => 64 * 1024,
        Argon2Difficulty::Low => 1024 * 1024,
        Argon2Difficulty::Medium => 2 * 1024 * 1024,
        Argon2Difficulty::Hard => 4 * 1024 * 1024,
        Argon2Difficulty::Paranoid => 8 * 1024 * 1024,
    };
    
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

struct SplitWriter {
    base_path: PathBuf,
    split_size: Option<u64>,
    current_size: u64,
    current_part: usize,
    current_file: BufWriter<File>,
}

impl SplitWriter {
    fn new(base_path: PathBuf, split_size: Option<usize>) -> io::Result<Self> {
        let file = File::create(&base_path)?;
        Ok(Self {
            base_path,
            split_size: split_size.map(|s| s as u64),
            current_size: 0,
            current_part: 0,
            current_file: BufWriter::new(file),
        })
    }
}

impl Write for SplitWriter {
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        let mut written_total = 0;
        let mut slice = buf;

        while !slice.is_empty() {
            if let Some(limit) = self.split_size {
                if self.current_size >= limit {
                    self.current_file.flush()?;
                    self.current_part += 1;
                    
                    let file_name = self.base_path.file_name().unwrap().to_str().unwrap();
                    let parent = self.base_path.parent().unwrap_or(Path::new("."));
                    let new_name = format!("{}.{:03}", file_name, self.current_part + 1);
                    let new_path = parent.join(new_name);
                    
                    let file = File::create(new_path)?;
                    self.current_file = BufWriter::new(file);
                    self.current_size = 0;
                }
            }

            let max_write = if let Some(limit) = self.split_size {
                (limit - self.current_size) as usize
            } else {
                slice.len()
            };
            
            let bytes_to_write = std::cmp::min(max_write, slice.len());
            let n = self.current_file.write(&slice[..bytes_to_write])?;
            
            self.current_size += n as u64;
            written_total += n;
            slice = &slice[n..];
        }
        Ok(written_total)
    }

    fn flush(&mut self) -> io::Result<()> {
        self.current_file.flush()
    }
}

struct EncryptingWriter<W: Write> {
    inner: W,
    cipher: ChaCha20Poly1305,
    buffer: Vec<u8>,
    block_size: usize,
}

impl<W: Write> EncryptingWriter<W> {
    fn new(inner: W, key: Key, block_size: usize) -> Self {
        Self {
            inner,
            cipher: ChaCha20Poly1305::new(&key),
            buffer: Vec::with_capacity(block_size),
            block_size,
        }
    }

    fn flush_buffer(&mut self) -> io::Result<()> {
        if self.buffer.is_empty() {
            return Ok(());
        }

        let mut nonce_bytes = [0u8; NONCE_LEN];
        rand::thread_rng().fill_bytes(&mut nonce_bytes);
        let nonce = Nonce::from_slice(&nonce_bytes);

        let ciphertext = self.cipher.encrypt(nonce, self.buffer.as_slice())
            .map_err(|e| io::Error::new(io::ErrorKind::Other, e.to_string()))?;

        // Format: Nonce(12) + Length(4) + Ciphertext
        self.inner.write_all(&nonce_bytes)?;
        let len = ciphertext.len() as u32;
        self.inner.write_all(&len.to_le_bytes())?;
        self.inner.write_all(&ciphertext)?;

        self.buffer.clear();
        Ok(())
    }
}

impl<W: Write> Write for EncryptingWriter<W> {
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        let mut total_written = 0;
        let mut input = buf;

        while !input.is_empty() {
             let space = self.block_size - self.buffer.len();
             if input.len() <= space {
                 self.buffer.extend_from_slice(input);
                 total_written += input.len();
                 break;
             } else {
                 self.buffer.extend_from_slice(&input[..space]);
                 self.flush_buffer()?;
                 total_written += space;
                 input = &input[space..];
             }
        }
        Ok(total_written)
    }

    fn flush(&mut self) -> io::Result<()> {
        self.flush_buffer()?;
        self.inner.flush()
    }
}

impl<W: Write> Drop for EncryptingWriter<W> {
    fn drop(&mut self) {
        let _ = self.flush_buffer();
    }
}

struct DecryptingReader<R: Read> {
    inner: R,
    cipher: ChaCha20Poly1305,
    buffer: Vec<u8>,
    pos: usize,
    eof: bool,
}

impl<R: Read> DecryptingReader<R> {
    fn new(inner: R, key: Key) -> Self {
        Self {
            inner,
            cipher: ChaCha20Poly1305::new(&key),
            buffer: Vec::new(),
            pos: 0,
            eof: false,
        }
    }

    fn fill_buffer(&mut self) -> io::Result<bool> {
        if self.eof { return Ok(false); }

        let mut nonce_bytes = [0u8; NONCE_LEN];
        match self.inner.read_exact(&mut nonce_bytes) {
            Ok(_) => {},
            Err(ref e) if e.kind() == io::ErrorKind::UnexpectedEof => {
                self.eof = true;
                return Ok(false);
            },
            Err(e) => return Err(e),
        }
        let nonce = Nonce::from_slice(&nonce_bytes);

        let mut len_bytes = [0u8; 4];
        self.inner.read_exact(&mut len_bytes)?;
        let len = u32::from_le_bytes(len_bytes) as usize;

        let mut ciphertext = vec![0u8; len];
        self.inner.read_exact(&mut ciphertext)?;

        let plaintext = self.cipher.decrypt(nonce, ciphertext.as_ref())
             .map_err(|e| io::Error::new(io::ErrorKind::Other, format!("Decryption failed: {}", e)))?;
        
        self.buffer = plaintext;
        self.pos = 0;
        Ok(true)
    }
}

impl<R: Read> Read for DecryptingReader<R> {
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        if self.pos >= self.buffer.len() {
             if !self.fill_buffer()? {
                 return Ok(0); // EOF
             }
        }

        let available = self.buffer.len() - self.pos;
        let read_len = std::cmp::min(available, buf.len());
        
        buf[..read_len].copy_from_slice(&self.buffer[self.pos..self.pos + read_len]);
        self.pos += read_len;
        
        Ok(read_len)
    }
}


pub fn encrypt_folder<F>(folder_path: &str, password: &str, options: EncryptionOptions, report_progress: F) -> io::Result<String>
where F: Fn(String) {
    let path = Path::new(folder_path);
    if !path.exists() || !path.is_dir() {
        return Err(io::Error::new(io::ErrorKind::NotFound, "Folder not found"));
    }

    let folder_name = path.file_name().unwrap().to_str().unwrap();
    let parent_dir = path.parent().unwrap_or(Path::new("."));
    let output_filename = parent_dir.join(format!("{}.nightbaron", folder_name));
    
    let mut use_zstd = false;
    let mut use_xz = false;

    if should_compress(folder_path, &report_progress) {
        match options.compression_method {
            CompressionMethod::Zstd => use_zstd = true,
            CompressionMethod::Xz => use_xz = true,
        }
    } else {
        report_progress("Skipping compression (files already compressed)".to_string());
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
    
    report_progress("Deriving keys...".to_string());
    let mut key_bytes = SensitiveData(derive_key(password.as_bytes(), &salt, options.difficulty).to_vec());
    let key = *Key::from_slice(&key_bytes.0);

    let mut split_writer = SplitWriter::new(PathBuf::from(&output_filename), options.split_size)?;
    
    split_writer.write_all(&salt)?;
    let difficulty_byte = match options.difficulty {
        Argon2Difficulty::Light => 1u8,
        Argon2Difficulty::Low => 2u8,
        Argon2Difficulty::Medium => 3u8,
        Argon2Difficulty::Hard => 4u8,
        Argon2Difficulty::Paranoid => 5u8,
    };
    split_writer.write_all(&[difficulty_byte])?; 

    let method_byte = if use_zstd { 2u8 } else if use_xz { 1u8 } else { 0u8 };
    split_writer.write_all(&[method_byte])?;

    report_progress("Encrypting (Streaming)...".to_string());
    let block_size = if options.block_size == 0 { 64 * 1024 * 1024 } else { options.block_size };    
    let encrypting_writer = EncryptingWriter::new(split_writer, key, block_size);
    
    if use_zstd {
        let level = if options.compression_level > 0 { options.compression_level as i32 } else { 3 };
        let mut zstd_enc = ZstdEncoder::new(encrypting_writer, level)?;
        {
            let mut tar = Builder::new(&mut zstd_enc);
            tar.append_dir_all(folder_name, folder_path)?;
            tar.finish()?;
        }
        zstd_enc.finish()?;
    } else if use_xz {
        let level = if options.compression_level > 9 { 6 } else { options.compression_level };
        let mut xz_enc = XzEncoder::new(encrypting_writer, level);
        {
             let mut tar = Builder::new(&mut xz_enc);
             tar.append_dir_all(folder_name, folder_path)?;
             tar.finish()?;
        }
        xz_enc.finish()?;
    } else {
        // No compression
        let mut tar = Builder::new(encrypting_writer);
        tar.append_dir_all(folder_name, folder_path)?;
        tar.finish()?;
    }

    key_bytes.zeroize();
    
    if options.delete_original {
        fs::remove_dir_all(path)?;
    }

    Ok(output_filename.to_string_lossy().into_owned())
}

struct MultiPartReader {
    base_path: PathBuf,
    current_part: usize,
    current_file: BufReader<File>,
}

impl MultiPartReader {
    fn open(path: &str) -> io::Result<Self> {
        let file = File::open(path)?;
        Ok(Self {
            base_path: PathBuf::from(path),
            current_part: 1, 
            current_file: BufReader::new(file),
        })
    }
    
    fn try_next_part(&mut self) -> io::Result<bool> {
        let file_name = self.base_path.file_name().unwrap().to_str().unwrap();
        let next_part_name = format!("{}.{:03}", file_name, self.current_part + 1);
        let next_part_path = self.base_path.with_file_name(next_part_name);
        
        if next_part_path.exists() {
            self.current_part += 1;
            let file = File::open(next_part_path)?;
            self.current_file = BufReader::new(file);
            Ok(true)
        } else {
            Ok(false)
        }
    }
}

impl Read for MultiPartReader {
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        let read = self.current_file.read(buf)?;
        if read == 0 {
            if self.try_next_part()? {
                return self.current_file.read(buf);
            }
        }
        Ok(read)
    }
}

pub fn decrypt_file<F>(file_path: &str, password: &str, report_progress: F) -> io::Result<String>
where F: Fn(String) {
    if let Ok(res) = try_decrypt_v2(file_path, password, &report_progress) {
        return Ok(res);
    }
    
    report_progress("V2 failed, attempting legacy V1 decryption...".to_string());
    decrypt_v1(file_path, password, &report_progress)
}

fn try_decrypt_v2<F>(file_path: &str, password: &str, report_progress: F) -> io::Result<String>
where F: Fn(String) {
    let mut reader = MultiPartReader::open(file_path)?;
    let mut salt = [0u8; SALT_LEN];
    reader.read_exact(&mut salt)?;
    
    let mut diff_byte = [0u8; 1];
    reader.read_exact(&mut diff_byte)?;
    
    let mut method_byte = [0u8; 1];
    reader.read_exact(&mut method_byte)?;

    let difficulty = match diff_byte[0] {
        1 => Argon2Difficulty::Light,
        2 => Argon2Difficulty::Low,
        3 => Argon2Difficulty::Medium,
        4 => Argon2Difficulty::Hard,
        5 => Argon2Difficulty::Paranoid,
        _ => Argon2Difficulty::Medium,
    };
    
    let method = match method_byte[0] {
        1 => CompressionMethod::Xz,
        2 => CompressionMethod::Zstd,
        _ => return Err(io::Error::new(io::ErrorKind::InvalidData, "Unknown compression method, possibly V1")),
    };
    
    report_progress("Deriving keys (V2)...".to_string());
    let mut key_bytes = SensitiveData(derive_key(password.as_bytes(), &salt, difficulty).to_vec());
    let key = Key::from_slice(&key_bytes.0);
    
    report_progress("Decrypting & Extracting (V2)...".to_string());
    
    let decrypt_stream = DecryptingReader::new(reader, *key);
    let p = Path::new(file_path);
    let parent = p.parent().unwrap_or(Path::new("."));

    if method == CompressionMethod::Zstd {
         let decoder = ZstdDecoder::new(decrypt_stream)?;
         let mut archive = tar::Archive::new(decoder);
         archive.unpack(parent)?;
    } else {
         let decoder = XzDecoder::new(decrypt_stream);
         let mut archive = tar::Archive::new(decoder);
         archive.unpack(parent)?;
    }
    
    key_bytes.zeroize();
    Ok("Decryption Successful".to_string())
}

fn decrypt_v1<F>(file_path: &str, password: &str, report_progress: F) -> io::Result<String>
where F: Fn(String) {
    let mut reader = MultiPartReader::open(file_path)?;

    let mut salt = [0u8; SALT_LEN];
    reader.read_exact(&mut salt)?;
    
    let mut diff_byte = [0u8; 1];
    reader.read_exact(&mut diff_byte)?;
    
    // V1 has NO method byte (backwards compatibility)
    
    let difficulty = match diff_byte[0] {
        1 => Argon2Difficulty::Light,
        2 => Argon2Difficulty::Low,
        3 => Argon2Difficulty::Medium,
        4 => Argon2Difficulty::Hard,
        5 => Argon2Difficulty::Paranoid,
        _ => Argon2Difficulty::Medium,
    };
    
    report_progress("Deriving keys (V1)...".to_string());
    let mut key_bytes = SensitiveData(derive_key(password.as_bytes(), &salt, difficulty).to_vec());
    let key = Key::from_slice(&key_bytes.0);
    
    report_progress("Decrypting & Extracting (V1)...".to_string());
    
    let mut decrypt_stream = DecryptingReader::new(reader, *key);
    
    // Detetct magic inside decrypted stream by peeking
    let mut magic = [0u8; 6];
    if decrypt_stream.read(&mut magic)? < 6 {
         return Err(io::Error::new(io::ErrorKind::UnexpectedEof, "File too short"));
    }
    
    let is_xz = magic == [0xFD, 0x37, 0x7A, 0x58, 0x5A, 0x00];
    let stream = Cursor::new(magic).chain(decrypt_stream);
    
    let p = Path::new(file_path);
    let parent = p.parent().unwrap_or(Path::new("."));

    if is_xz {
        let decoder = XzDecoder::new(stream);
        let mut archive = tar::Archive::new(decoder);
        archive.unpack(parent)?;
    } else {
        let mut archive = tar::Archive::new(stream);
        archive.unpack(parent)?;
    }
    
    key_bytes.zeroize();
    Ok("Decryption Successful (V1)".to_string())

}
