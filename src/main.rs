#![cfg_attr(not(debug_assertions), windows_subsystem = "windows")]

use eframe::egui;
use std::sync::mpsc::{channel, Receiver, Sender};
use std::thread;
use std::path::Path;
use std::time::{SystemTime, UNIX_EPOCH};
use zeroize::Zeroize;

#[derive(Clone)]
struct SecureString {
    data: Vec<u8>,
    obfuscation_key: [u8; 16],
}

impl SecureString {
    fn new() -> Self {
        let data = Vec::new();
        let mut obfuscation_key = [0u8; 16];
        
        use rand::Rng;
        let mut rng = rand::thread_rng();
        rng.fill(&mut obfuscation_key);
        
        Self { data, obfuscation_key }
    }
    
    fn allocate_secure(capacity: usize) -> Vec<u8> {
        Vec::with_capacity(capacity)
    }
    
    fn obfuscate_data(&mut self) {
        for (i, byte) in self.data.iter_mut().enumerate() {
            *byte ^= self.obfuscation_key[i % self.obfuscation_key.len()];
        }
    }
    
    fn as_str(&self) -> String {
        let mut temp_data = self.data.clone();
        for (i, byte) in temp_data.iter_mut().enumerate() {
            *byte ^= self.obfuscation_key[i % self.obfuscation_key.len()];
        }
        String::from_utf8(temp_data).unwrap_or_else(|_| String::new())
    }
    
    fn is_empty(&self) -> bool {
        self.data.is_empty()
    }
    
    fn clear(&mut self) {
        self.data.zeroize();
        self.data.clear();
    }
    
    fn zeroize(&mut self) {
        self.data.zeroize();
    }
    
    fn update_from_buffer(&mut self, buffer: &mut String) {
        self.data.zeroize();
        self.data.clear();
        self.data.extend_from_slice(buffer.as_bytes());
        self.obfuscate_data();
        buffer.zeroize();
        buffer.clear();
    }
}

impl Drop for SecureString {
    fn drop(&mut self) {
        self.data.zeroize();
    }
}

mod crypto;
use crypto::Argon2Difficulty;

enum AppMessage {
    EncryptStart,
    EncryptComplete(String),
    EncryptError(String),
    DecryptStart,
    DecryptComplete(String),
    DecryptError(String),
    Log(String),
}

#[derive(PartialEq)]
enum Tab {
    Encrypt,
    Decrypt,
    Settings,
    Logs,
}

struct NightbaronApp {
    current_tab: Tab,
    encrypt_path: String,
    encrypt_pass: SecureString,
    decrypt_path: String,
    decrypt_pass: SecureString,
    status_message: String,
    is_processing: bool,
    logs: Vec<String>,
    custom_salt: SecureString,
    delete_original: bool,
    sender: Sender<AppMessage>,
    receiver: Receiver<AppMessage>,
    encrypt_pass_buffer: String,
    decrypt_pass_buffer: String,
    custom_salt_buffer: String,
    compression_method: crypto::CompressionMethod,
    compression_level: u32,
    difficulty: Argon2Difficulty,
    enable_split: bool,
    split_size_mb: u32,
    block_size_mb: u32,
}

impl NightbaronApp {
    fn new(_cc: &eframe::CreationContext<'_>) -> Self {
        let (sender, receiver) = channel();
        Self {
            current_tab: Tab::Encrypt,
            encrypt_path: String::new(),
            encrypt_pass: SecureString::new(),
            decrypt_path: String::new(),
            decrypt_pass: SecureString::new(),
            status_message: "Ready".to_owned(),
            is_processing: false,
            logs: vec![Self::format_log("started")],
            custom_salt: SecureString::new(),
            delete_original: false,
            sender,
            receiver,
            encrypt_pass_buffer: String::new(),
            decrypt_pass_buffer: String::new(),
            custom_salt_buffer: String::new(),
            compression_method: crypto::CompressionMethod::Zstd,
            compression_level: 1,
            difficulty: Argon2Difficulty::Medium,
            enable_split: false,
            split_size_mb: 100,
            block_size_mb: 64,
        }
    }

    fn format_log(msg: &str) -> String {
        let start = SystemTime::now();
        let since_the_epoch = start
            .duration_since(UNIX_EPOCH)
            .expect("Time went backwards");
        let in_ms = since_the_epoch.as_millis();
        format!("[{}] {}", in_ms, msg)
    }

    fn add_log(&mut self, msg: String) {
        self.logs.push(Self::format_log(&msg));
    }

    fn handle_messages(&mut self) {
        while let Ok(msg) = self.receiver.try_recv() {
            match msg {
                AppMessage::EncryptStart => {
                    self.status_message = "Encrypting...".to_owned();
                    self.add_log("Started encryption process".to_owned());
                    self.is_processing = true;
                }
                AppMessage::EncryptComplete(filename) => {
                    let msg = format!("Encrypted File: {}", filename);
                    self.status_message = msg.clone();
                    self.add_log(msg);
                    self.is_processing = false;
                    self.encrypt_path.clear();
                    self.encrypt_pass.zeroize();
                    self.encrypt_pass.clear();
                }
                AppMessage::EncryptError(err) => {
                    let msg = format!("Encryption failed: {}", err);
                    self.status_message = msg.clone();
                    self.add_log(msg);
                    self.is_processing = false;
                }
                AppMessage::DecryptStart => {
                    self.status_message = "Decrypting...".to_owned();
                    self.add_log("Decrypting file....".to_owned());
                    self.is_processing = true;
                }
                AppMessage::DecryptComplete(msg) => {
                    let log_msg = format!("The file was decrypted: {}", msg);
                    self.status_message = log_msg.clone();
                    self.add_log(log_msg);
                    self.is_processing = false;
                    self.decrypt_path.clear();
                    self.decrypt_pass.zeroize();
                    self.decrypt_pass.clear();
                }
                AppMessage::DecryptError(err) => {
                    let msg = format!("Failed to decrypt: {}", err);
                    self.status_message = msg.clone();
                    self.add_log(msg);
                    self.is_processing = false;
                }
                AppMessage::Log(msg) => {
                    if msg.starts_with("Analyzing") || msg.starts_with("Encrypting") || msg.starts_with("Decrypting") || msg.starts_with("Deriving") {
                         self.status_message = msg.clone();
                    }
                    self.add_log(msg);
                }
            }
        }
    }
}

impl eframe::App for NightbaronApp {
    fn update(&mut self, ctx: &egui::Context, _frame: &mut eframe::Frame) {
        self.handle_messages();

        egui::CentralPanel::default().show(ctx, |ui| {
            ui.vertical_centered(|ui| {
                ui.heading("NIGHTBARON");
                ui.label("File Encryption System");
            });
            
            ui.add_space(20.0);

            ui.horizontal(|ui| {
                ui.selectable_value(&mut self.current_tab, Tab::Encrypt, "Encrypt Files");
                ui.selectable_value(&mut self.current_tab, Tab::Decrypt, "Decrypt Files");
                ui.selectable_value(&mut self.current_tab, Tab::Settings, "Settings");
                ui.selectable_value(&mut self.current_tab, Tab::Logs, "Logs");
            });

            ui.separator();

            ui.add_space(10.0);

            match self.current_tab {
                Tab::Encrypt => {
                    ui.label("Select a folder to encrypt:");
                    ui.horizontal(|ui| {
                        ui.text_edit_singleline(&mut self.encrypt_path);
                        if ui.button("...").clicked() && !self.is_processing {
                            if let Some(path) = rfd::FileDialog::new().pick_folder() {
                                self.encrypt_path = path.display().to_string();
                            }
                        }
                    });

                    ui.add_space(10.0);
                    ui.label("Password:");
                    ui.add(egui::TextEdit::singleline(&mut self.encrypt_pass_buffer).password(true));

                    ui.add_space(10.0);



                    ui.add_space(20.0);
                    
                    let btn = egui::Button::new("ENCRYPT");
                    
                    if ui.add_enabled(!self.is_processing, btn).clicked() {
                        if !self.encrypt_pass_buffer.is_empty() {
                            self.encrypt_pass.update_from_buffer(&mut self.encrypt_pass_buffer);
                        }
                        if !self.custom_salt_buffer.is_empty() {
                            self.custom_salt.update_from_buffer(&mut self.custom_salt_buffer);
                        }
                        if self.encrypt_path.is_empty() || self.encrypt_pass.is_empty() {
                            self.status_message = "Please fill in all fields".to_owned();
                        } else if !Path::new(&self.encrypt_path).exists() {
                            self.status_message = "Selected path does not exist".to_owned();
                        } else {
                            let path = self.encrypt_path.clone();
                            let mut pass_buffer = self.encrypt_pass.as_str();
                            let sender = self.sender.clone();
                            let progress_sender = self.sender.clone();
                            
                            let options = crypto::EncryptionOptions {
                                custom_salt: if self.custom_salt.is_empty() { None } else { Some(self.custom_salt.as_str().to_string()) },
                                delete_original: self.delete_original,
                                difficulty: self.difficulty,
                                compression_method: self.compression_method,
                                compression_level: self.compression_level,
                                split_size: if self.enable_split { Some(self.split_size_mb as usize * 1024 * 1024) } else { None },
                                block_size: self.block_size_mb as usize * 1024 * 1024,
                            };
                            
                            self.status_message = "Starting encryption...".to_owned();
                            self.is_processing = true;
                            
                            thread::spawn(move || {
                                sender.send(AppMessage::EncryptStart).ok();
                                let res = crypto::encrypt_folder(&path, &pass_buffer, options, |msg| {
                                     progress_sender.send(AppMessage::Log(msg)).ok();
                                });

                                match res {
                                    Ok(filename) => {
                                        sender.send(AppMessage::EncryptComplete(filename)).ok();
                                    },
                                    Err(e) => {
                                        sender.send(AppMessage::EncryptError(e.to_string())).ok();
                                    }
                                }
                                pass_buffer.zeroize();
                            });
                            self.encrypt_pass.zeroize();
                            self.encrypt_pass.clear();
                        }
                    }
                }
                Tab::Decrypt => {
                    ui.label("Select a .nightbaron file to decrypt:");
                    ui.horizontal(|ui| {
                        ui.text_edit_singleline(&mut self.decrypt_path);
                        if ui.button("...").clicked() && !self.is_processing {
                            if let Some(path) = rfd::FileDialog::new().add_filter("Nightbaron Encrypted", &["nightbaron"]).pick_file() {
                                self.decrypt_path = path.display().to_string();
                            }
                        }
                    });

                    ui.add_space(10.0);
                    ui.label("Password:");
                    ui.add(egui::TextEdit::singleline(&mut self.decrypt_pass_buffer).password(true));

                    ui.add_space(20.0);

                    let btn = egui::Button::new("DECRYPT");
                    
                    if ui.add_enabled(!self.is_processing, btn).clicked() {
                        if !self.decrypt_pass_buffer.is_empty() {
                            self.decrypt_pass.update_from_buffer(&mut self.decrypt_pass_buffer);
                        }
                        if self.decrypt_path.is_empty() || self.decrypt_pass.is_empty() {
                            self.status_message = "Please fill in all fields".to_owned();
                        } else {
                            let path = self.decrypt_path.clone();
                            let mut pass_buffer = self.decrypt_pass.as_str();
                            let sender = self.sender.clone();
                            let progress_sender = self.sender.clone();

                            self.status_message = "Starting decryption...".to_owned();
                            self.is_processing = true;

                            thread::spawn(move || {
                                sender.send(AppMessage::DecryptStart).ok();
                                let res = crypto::decrypt_file(&path, &pass_buffer, |msg| {
                                     progress_sender.send(AppMessage::Log(msg)).ok();
                                });
                                
                                match res {
                                    Ok(msg) => {
                                        sender.send(AppMessage::DecryptComplete(msg)).ok();
                                    },
                                    Err(e) => {
                                        sender.send(AppMessage::DecryptError(e.to_string())).ok();
                                    }
                                }
                                pass_buffer.zeroize();
                            });
                            self.decrypt_pass.zeroize();
                            self.decrypt_pass.clear();
                        }
                    }
                }
                Tab::Settings => {
                    egui::ScrollArea::vertical().show(ui, |ui| {
                        ui.heading("Encryption Settings");
                        ui.add_space(10.0);
                        
                        ui.group(|ui| {
                            ui.label("Encryption Difficulty (Memory Usage)");
                            ui.radio_value(&mut self.difficulty, Argon2Difficulty::Light, "Light (64 MB) - Easy");
                            ui.radio_value(&mut self.difficulty, Argon2Difficulty::Low, "Low (1 GB)");
                            ui.radio_value(&mut self.difficulty, Argon2Difficulty::Medium, "Medium (2 GB) - Default");
                            ui.radio_value(&mut self.difficulty, Argon2Difficulty::Hard, "Hard (4 GB)");
                            ui.radio_value(&mut self.difficulty, Argon2Difficulty::Paranoid, "Paranoid (8 GB) - Maximum security");
                        });
                        ui.add_space(10.0);

                        ui.group(|ui| {
                            ui.label("Compression");
                            let mut is_xz = matches!(self.compression_method, crypto::CompressionMethod::Xz);
                            if ui.checkbox(&mut is_xz, "LZMA (High Ratio)").clicked() {
                                self.compression_method = crypto::CompressionMethod::Xz;
                            }

                            let mut is_zstd = matches!(self.compression_method, crypto::CompressionMethod::Zstd);
                            if ui.checkbox(&mut is_zstd, "ZSTD (Fast)").clicked() {
                                self.compression_method = crypto::CompressionMethod::Zstd;
                            }
                            
                            ui.add_space(5.0);
                            ui.label("Compression Level:");
                            ui.add(egui::Slider::new(&mut self.compression_level, 0..=9).text("Level (0-9 for XZ, mapped for ZSTD)"));
                        });

                        ui.add_space(10.0);
                        ui.add_space(10.0);

                        ui.group(|ui| {
                            ui.label("Archive Splitting & Block Size");
                            ui.horizontal(|ui| {
                                ui.label("Block Size (MB):");
                                ui.add(egui::DragValue::new(&mut self.block_size_mb).range(1..=1024));
                            });
                            
                            ui.checkbox(&mut self.enable_split, "Split Archive");
                            if self.enable_split {
                                ui.horizontal(|ui| {
                                    ui.label("Volume Size (MB):");
                                    ui.add(egui::DragValue::new(&mut self.split_size_mb).range(1..=10000));
                                });
                                if self.split_size_mb < self.block_size_mb {
                                    ui.label(egui::RichText::new("Note: Volumes will be at least Block Size").color(egui::Color32::YELLOW));
                                }
                            }
                        });
                        ui.add_space(10.0);

                        ui.separator();
                        ui.label("General");
                        ui.label("Custom Salt (Optional):");
                        ui.add(egui::TextEdit::singleline(&mut self.custom_salt_buffer));
                        
                        ui.add_space(5.0);
                        ui.checkbox(&mut self.delete_original, "Delete original folder after successful encryption");
                        ui.label(egui::RichText::new("Warning: This will permanently delete the original files!").small().color(egui::Color32::RED));
                    });
                }
                Tab::Logs => {
                    egui::ScrollArea::vertical().show(ui, |ui| {
                        ui.set_width(ui.available_width());
                        for log in &self.logs {
                            ui.label(log);
                        }
                    });
                }
            }

            ui.add_space(20.0);
            ui.separator();
            ui.label(&self.status_message);
            
            if self.is_processing {
                ui.spinner();
            }
        });
    }
}

fn main() -> eframe::Result<()> {
    let options = eframe::NativeOptions {
        viewport: egui::ViewportBuilder::default()
            .with_inner_size([600.0, 500.0])
            .with_min_inner_size([400.0, 300.0]),
        ..Default::default()
    };
    
    eframe::run_native(
        "Nightbaron Encryption",
        options,
        Box::new(|cc| {
            Ok(Box::new(NightbaronApp::new(cc)))
        }),
    )
}