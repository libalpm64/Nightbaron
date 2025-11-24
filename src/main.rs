#![cfg_attr(not(debug_assertions), windows_subsystem = "windows")]

use eframe::egui;
use std::sync::mpsc::{channel, Receiver, Sender};
use std::thread;
use std::path::Path;
use std::time::{SystemTime, UNIX_EPOCH};
use zeroize::Zeroize;

mod crypto;

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
    encrypt_pass: String,
    decrypt_path: String,
    decrypt_pass: String,
    status_message: String,
    is_processing: bool,
    logs: Vec<String>,
    custom_salt: String,
    delete_original: bool,
    sender: Sender<AppMessage>,
    receiver: Receiver<AppMessage>,
}

impl NightbaronApp {
    fn new(_cc: &eframe::CreationContext<'_>) -> Self {
        let (sender, receiver) = channel();
        Self {
            current_tab: Tab::Encrypt,
            encrypt_path: String::new(),
            encrypt_pass: String::new(),
            decrypt_path: String::new(),
            decrypt_pass: String::new(),
            status_message: "Ready".to_owned(),
            is_processing: false,
            logs: vec![Self::format_log("started")],
            custom_salt: String::new(),
            delete_original: false,
            sender,
            receiver,
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
                    ui.add(egui::TextEdit::singleline(&mut self.encrypt_pass).password(true));

                    ui.add_space(20.0);
                    
                    let btn = egui::Button::new("ENCRYPT");
                    
                    if ui.add_enabled(!self.is_processing, btn).clicked() {
                        if self.encrypt_path.is_empty() || self.encrypt_pass.is_empty() {
                            self.status_message = "Please fill in all fields".to_owned();
                        } else if !Path::new(&self.encrypt_path).exists() {
                            self.status_message = "Selected path does not exist".to_owned();
                        } else {
                            let path = self.encrypt_path.clone();
                            let mut pass = self.encrypt_pass.clone();
                            let sender = self.sender.clone();
                            
                            let options = crypto::EncryptionOptions {
                                custom_salt: if self.custom_salt.is_empty() { None } else { Some(self.custom_salt.clone()) },
                                delete_original: self.delete_original,
                            };
                            
                            self.status_message = "Starting encryption...".to_owned();
                            self.is_processing = true;
                            
                            thread::spawn(move || {
                                sender.send(AppMessage::EncryptStart).ok();
                                match crypto::encrypt_folder(&path, &pass, options) {
                                    Ok(filename) => {
                                        sender.send(AppMessage::EncryptComplete(filename)).ok();
                                    },
                                    Err(e) => {
                                        sender.send(AppMessage::EncryptError(e.to_string())).ok();
                                    }
                                }
                                pass.zeroize();
                            });
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
                    ui.add(egui::TextEdit::singleline(&mut self.decrypt_pass).password(true));

                    ui.add_space(20.0);

                    let btn = egui::Button::new("DECRYPT");
                    
                    if ui.add_enabled(!self.is_processing, btn).clicked() {
                        if self.decrypt_path.is_empty() || self.decrypt_pass.is_empty() {
                            self.status_message = "Please fill in all fields".to_owned();
                        } else if !self.decrypt_path.ends_with(".nightbaron") {
                            self.status_message = "Please select a .nightbaron file".to_owned();
                        } else {
                            let path = self.decrypt_path.clone();
                            let mut pass = self.decrypt_pass.clone();
                            let sender = self.sender.clone();

                            self.status_message = "Starting decryption...".to_owned();
                            self.is_processing = true;

                            thread::spawn(move || {
                                sender.send(AppMessage::DecryptStart).ok();
                                match crypto::decrypt_file(&path, &pass) {
                                    Ok(msg) => {
                                        sender.send(AppMessage::DecryptComplete(msg)).ok();
                                    },
                                    Err(e) => {
                                        sender.send(AppMessage::DecryptError(e.to_string())).ok();
                                    }
                                }
                                pass.zeroize();
                            });
                        }
                    }
                }
                Tab::Settings => {
                    ui.heading("Encryption Settings");
                    ui.add_space(10.0);
                    
                    ui.label("Custom Salt (Optional):");
                    ui.text_edit_singleline(&mut self.custom_salt);
                    ui.label(egui::RichText::new("Leave empty to use a random salt (Recommended)").small().weak());
                    
                    ui.add_space(10.0);
                    ui.checkbox(&mut self.delete_original, "Delete original folder after successful encryption");
                    ui.label(egui::RichText::new("Warning: This will permanently delete the original files!").small().color(egui::Color32::RED));
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
            .with_inner_size([580.0, 450.0])
            .with_min_inner_size([400.0, 300.0]),
        ..Default::default()
    };
    
    eframe::run_native(
        "Nightbaron Encryption",
        options,
        Box::new(|cc| Ok(Box::new(NightbaronApp::new(cc)))),
    )
}