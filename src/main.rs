#![cfg_attr(not(debug_assertions), windows_subsystem = "windows")]

use eframe::egui;
use std::sync::mpsc::{channel, Receiver, Sender};
use std::thread;
use std::path::Path;
use std::time::{SystemTime, UNIX_EPOCH};
use zeroize::Zeroize;
use memsec;
use rand::RngCore;

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
        #[cfg(windows)]
        {
            unsafe {
                use windows_sys::Win32::System::Memory::{VirtualAlloc, MEM_COMMIT, MEM_RESERVE, PAGE_READWRITE};                
                const PAGE_SIZE: usize = 4096;
                let total_size = capacity + (2 * PAGE_SIZE);
                
                let ptr = VirtualAlloc(
                    std::ptr::null_mut(),
                    total_size,
                    MEM_COMMIT | MEM_RESERVE,
                    PAGE_READWRITE
                );
                
                if ptr.is_null() {
                    Vec::with_capacity(capacity)
                } else {
                    let data_start = ptr.add(PAGE_SIZE) as *mut u8;
                    Vec::from_raw_parts(data_start, 0, capacity)
                }
            }
        }
        #[cfg(not(windows))]
        {
            Vec::with_capacity(capacity)
        }
    }
    
    fn obfuscate_data(&mut self) {
        for (i, byte) in self.data.iter_mut().enumerate() {
            *byte ^= self.obfuscation_key[i % self.obfuscation_key.len()];
        }
    }
    
    fn deobfuscate_data(&mut self) {
        self.obfuscate_data();
    }
    
    
    fn as_str(&self) -> String {
        vmp_ultra!("as_str", {
            let mut temp_data = self.data.clone();
            for (i, byte) in temp_data.iter_mut().enumerate() {
                *byte ^= self.obfuscation_key[i % self.obfuscation_key.len()];
            }
            String::from_utf8(temp_data).unwrap_or_else(|_| String::new())
        })
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
        vmp_ultra!("update_from_buffer", {
            if !self.data.is_empty() {
                unsafe { memsec::munlock(self.data.as_mut_ptr(), self.data.len()) };
            }

            self.data.zeroize();

            if buffer.len() > 64 {
                self.data = Self::allocate_secure(buffer.len());
                self.data.extend_from_slice(buffer.as_bytes());
            } else {
                self.data.clear();
                self.data.extend_from_slice(buffer.as_bytes());
            }
            self.obfuscate_data();

            if !self.data.is_empty() {
                unsafe { memsec::mlock(self.data.as_mut_ptr(), self.data.len()) };
            }

            buffer.zeroize();
            buffer.clear();
        })
    }
    
    fn constant_time_eq(&self, other: &SecureString) -> bool {
        if self.data.len() != other.data.len() {
            return false;
        }
        
        let mut temp_self = self.data.clone();
        let mut temp_other = other.data.clone();
        
        for (i, byte) in temp_self.iter_mut().enumerate() {
            *byte ^= self.obfuscation_key[i % self.obfuscation_key.len()];
        }
        for (i, byte) in temp_other.iter_mut().enumerate() {
            *byte ^= other.obfuscation_key[i % other.obfuscation_key.len()];
        }
        
        let mut result = 0u8;
        for (a, b) in temp_self.iter().zip(temp_other.iter()) {
            result |= a ^ b;
        }
        
        temp_self.zeroize();
        temp_other.zeroize();
        
        result == 0
    }
}

impl Drop for SecureString {
    fn drop(&mut self) {
        if !self.data.is_empty() {
            unsafe { memsec::munlock(self.data.as_mut_ptr(), self.data.len()) };
        }
        self.data.zeroize();
    }
}

#[derive(Clone)]
struct SecureInputBuffer {
    encrypted_data: Vec<u8>,
    encryption_key: [u8; 32],
    length: usize,
}

impl SecureInputBuffer {
    fn new() -> Self {
        let mut key = [0u8; 32];
        rand::thread_rng().fill_bytes(&mut key);
        Self {
            encrypted_data: Vec::new(),
            encryption_key: key,
            length: 0,
        }
    }

    fn push(&mut self, ch: char) {
        vmp_ultra!("secure_input_push", {
            let byte = ch as u8;
            let encrypted_byte = byte ^ self.encryption_key[self.length % 32];
            self.encrypted_data.push(encrypted_byte);
            self.length += 1;
        })
    }

    fn pop(&mut self) -> Option<char> {
        vmp_ultra!("secure_input_pop", {
            if self.length > 0 {
                self.length -= 1;
                let encrypted_byte = self.encrypted_data.pop().unwrap();
                let byte = encrypted_byte ^ self.encryption_key[self.length % 32];
                Some(byte as char)
            } else {
                None
            }
        })
    }

    fn clear(&mut self) {
        vmp_ultra!("secure_input_clear", {
            self.encrypted_data.zeroize();
            self.encrypted_data.clear();
            self.length = 0;
        })
    }

    fn as_string(&self) -> String {
        vmp_ultra!("secure_input_as_string", {
            let mut result = String::with_capacity(self.length);
            for (i, &encrypted_byte) in self.encrypted_data.iter().enumerate() {
                let byte = encrypted_byte ^ self.encryption_key[i % 32];
                result.push(byte as char);
            }
            result
        })
    }

    fn len(&self) -> usize {
        self.length
    }

    fn is_empty(&self) -> bool {
        self.length == 0
    }
}

impl Drop for SecureInputBuffer {
    fn drop(&mut self) {
        vmp_ultra!("secure_input_drop", {
            self.encrypted_data.zeroize();
            self.encryption_key.zeroize();
        })
    }
}


#[cfg(target_os = "linux")]
use dbus::blocking::Connection;
#[cfg(target_os = "linux")]
use std::thread;

#[cfg(windows)]
use windows_sys::Win32::System::Power::PowerRegisterSuspendResumeNotification;
#[cfg(windows)]
use windows_sys::Win32::Foundation::HANDLE;
#[cfg(windows)]
use std::ffi::c_void;
#[cfg(windows)]
use std::sync::mpsc::Sender as MpscSender;
#[cfg(windows)]
use std::sync::Mutex;

#[cfg(windows)]
static WINDOWS_SUSPEND_SENDER: Mutex<Option<MpscSender<AppMessage>>> = Mutex::new(None);

#[cfg(unix)]
use libc::prctl;
#[cfg(unix)]
const PR_SET_DUMPABLE: i32 = 4;

#[cfg(windows)]
use windows_sys::Win32::System::Diagnostics::Debug::{SetErrorMode, SEM_FAILCRITICALERRORS};

#[macro_use]
mod vmp;
mod crypto;

enum AppMessage {
    EncryptStart,
    EncryptComplete(String),
    EncryptError(String),
    DecryptStart,
    DecryptComplete(String),
    DecryptError(String),
    Log(String),
    SuspendDetected,
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
    encrypt_pass_buffer: SecureInputBuffer,
    decrypt_pass_buffer: SecureInputBuffer,
    custom_salt_buffer: SecureInputBuffer,
}

impl NightbaronApp {
    fn zeroize_sensitive_data(&mut self) {
        self.encrypt_pass.zeroize();
        self.encrypt_pass.clear();
        self.decrypt_pass.zeroize();
        self.decrypt_pass.clear();
        self.custom_salt.zeroize();
        self.custom_salt.clear();
        self.add_log("Sensitive data zeroized due to suspend/sleep event".to_owned());
    }
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
            encrypt_pass_buffer: SecureInputBuffer::new(),
            decrypt_pass_buffer: SecureInputBuffer::new(),
            custom_salt_buffer: SecureInputBuffer::new(),
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
                AppMessage::SuspendDetected => {
                    self.zeroize_sensitive_data();
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
                ui.heading(crate::vmp::ui_str_nightbaron());
                ui.label(crate::vmp::ui_str_file_encryption_system());
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
                    ui.label(crate::vmp::ui_str_select_folder());
                    ui.horizontal(|ui| {
                        ui.text_edit_singleline(&mut self.encrypt_path);
                        if ui.button("...").clicked() && !self.is_processing {
                            if let Some(path) = rfd::FileDialog::new().pick_folder() {
                                self.encrypt_path = path.display().to_string();
                            }
                        }
                    });

                    ui.add_space(10.0);
                    ui.label(crate::vmp::ui_str_password());

                    // Secure password input - never stores plain text
                    let mut display_text = "*".repeat(self.encrypt_pass_buffer.len());
                    let response = ui.add(egui::TextEdit::singleline(&mut display_text).password(true));

                    // Handle input events to securely capture password
                    if response.changed() || response.lost_focus() {
                        // Reset display to correct length
                        display_text = "*".repeat(self.encrypt_pass_buffer.len());
                    }

                    // Capture new input characters
                    ui.input(|i| {
                        for event in &i.events {
                            match event {
                                egui::Event::Text(text) => {
                                    for ch in text.chars() {
                                        if ch.is_ascii() && !ch.is_control() {
                                            self.encrypt_pass_buffer.push(ch);
                                        }
                                    }
                                }
                                egui::Event::Key { key: egui::Key::Backspace, pressed: true, .. } => {
                                    self.encrypt_pass_buffer.pop();
                                }
                                _ => {}
                            }
                        }
                    });

                    ui.add_space(20.0);

                    let btn = egui::Button::new(crate::vmp::ui_str_encrypt());
                    
                    if ui.add_enabled(!self.is_processing, btn).clicked() {
                        vmp_ultra!("encrypt_button_handler", {
                            if !self.encrypt_pass_buffer.is_empty() {
                                let mut plain_pass = self.encrypt_pass_buffer.as_string();
                                self.encrypt_pass.update_from_buffer(&mut plain_pass);
                                self.encrypt_pass_buffer.clear();
                            }
                            if !self.custom_salt_buffer.is_empty() {
                                let mut plain_salt = self.custom_salt_buffer.as_string();
                                self.custom_salt.update_from_buffer(&mut plain_salt);
                                self.custom_salt_buffer.clear();
                            }
                            if self.encrypt_path.is_empty() || self.encrypt_pass.is_empty() {
                                self.status_message = "Please fill in all fields".to_owned();
                            } else if !Path::new(&self.encrypt_path).exists() {
                                self.status_message = "Selected path does not exist".to_owned();
                            } else {
                                let path = self.encrypt_path.clone();
                                let mut pass_buffer = self.encrypt_pass.as_str();
                                let sender = self.sender.clone();

                                let options = crypto::EncryptionOptions {
                                    custom_salt: if self.custom_salt.is_empty() { None } else { Some(self.custom_salt.as_str().to_string()) },
                                    delete_original: self.delete_original,
                                };

                                self.status_message = "Starting encryption...".to_owned();
                                self.is_processing = true;

                                thread::spawn(move || {
                                    sender.send(AppMessage::EncryptStart).ok();
                                    match crypto::encrypt_folder(&path, &pass_buffer, options) {
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
                        })
                    }
                }
                Tab::Decrypt => {
                    ui.label(crate::vmp::ui_str_select_file());
                    ui.horizontal(|ui| {
                        ui.text_edit_singleline(&mut self.decrypt_path);
                        if ui.button("...").clicked() && !self.is_processing {
                            if let Some(path) = rfd::FileDialog::new().add_filter("Nightbaron Encrypted", &["nightbaron"]).pick_file() {
                                self.decrypt_path = path.display().to_string();
                            }
                        }
                    });

                    ui.add_space(10.0);
                    ui.label(crate::vmp::ui_str_password());

                    let mut display_text = "*".repeat(self.decrypt_pass_buffer.len());
                    let response = ui.add(egui::TextEdit::singleline(&mut display_text).password(true));

                    if response.changed() || response.lost_focus() {
                        display_text = "*".repeat(self.decrypt_pass_buffer.len());
                    }

                    ui.input(|i| {
                        for event in &i.events {
                            match event {
                                egui::Event::Text(text) => {
                                    for ch in text.chars() {
                                        if ch.is_ascii() && !ch.is_control() {
                                            self.decrypt_pass_buffer.push(ch);
                                        }
                                    }
                                }
                                egui::Event::Key { key: egui::Key::Backspace, pressed: true, .. } => {
                                    self.decrypt_pass_buffer.pop();
                                }
                                _ => {}
                            }
                        }
                    });

                    ui.add_space(20.0);

                    let btn = egui::Button::new(crate::vmp::ui_str_decrypt());
                    
                    if ui.add_enabled(!self.is_processing, btn).clicked() {
                        vmp_ultra!("decrypt_button_handler", {
                            if !self.decrypt_pass_buffer.is_empty() {
                                let mut plain_pass = self.decrypt_pass_buffer.as_string();
                                self.decrypt_pass.update_from_buffer(&mut plain_pass);
                                self.decrypt_pass_buffer.clear();
                            }
                            if self.decrypt_path.is_empty() || self.decrypt_pass.is_empty() {
                                self.status_message = "Please fill in all fields".to_owned();
                            } else if !self.decrypt_path.ends_with(".nightbaron") {
                                self.status_message = "Please select a .nightbaron file".to_owned();
                            } else {
                                let path = self.decrypt_path.clone();
                                let mut pass_buffer = self.decrypt_pass.as_str();
                                let sender = self.sender.clone();

                                self.status_message = "Starting decryption...".to_owned();
                                self.is_processing = true;

                                thread::spawn(move || {
                                    sender.send(AppMessage::DecryptStart).ok();
                                    match crypto::decrypt_file(&path, &pass_buffer) {
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
                        })
                    }
                }
                Tab::Settings => {
                    ui.heading("Encryption Settings");
                    ui.add_space(10.0);
                    
                    ui.label("Custom Salt (Optional):");

                    let mut display_text = "*".repeat(self.custom_salt_buffer.len());
                    let response = ui.add(egui::TextEdit::singleline(&mut display_text));

                    if response.changed() || response.lost_focus() {
                        display_text = "*".repeat(self.custom_salt_buffer.len());
                    }

                    ui.input(|i| {
                        for event in &i.events {
                            match event {
                                egui::Event::Text(text) => {
                                    for ch in text.chars() {
                                        if ch.is_ascii() && !ch.is_control() {
                                            self.custom_salt_buffer.push(ch);
                                        }
                                    }
                                }
                                egui::Event::Key { key: egui::Key::Backspace, pressed: true, .. } => {
                                    self.custom_salt_buffer.pop();
                                }
                                _ => {}
                            }
                        }
                    });
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

fn disable_core_dumps() {
    #[cfg(unix)]
    unsafe {
        prctl(PR_SET_DUMPABLE, 0, 0, 0, 0);
    }
    #[cfg(windows)]
    unsafe {
        SetErrorMode(SEM_FAILCRITICALERRORS);
    }
}

#[cfg(target_os = "linux")]
fn setup_linux_suspend_hook(sender: Sender<AppMessage>) {
    thread::spawn(move || {
        let conn = Connection::new_system().expect("Failed to connect to system bus");
        conn.add_match("type='signal',interface='org.freedesktop.login1.Manager',member='PrepareForSleep'").expect("Failed to add match");
        for msg in conn.incoming(1000) {
            if let Some(prepare) = msg.get1::<bool>() {
                if prepare {
                    sender.send(AppMessage::SuspendDetected).ok();
                    println!("Linux suspend detected zeroizing sensitive data");
                }
            }
        }
    });
}

#[cfg(windows)]
unsafe extern "system" fn suspend_resume_callback(_context: *mut c_void, suspend_type: u32, _: *mut c_void) -> u32 {
    if suspend_type == 4 {
        if let Ok(sender_guard) = WINDOWS_SUSPEND_SENDER.lock() {
            if let Some(ref sender) = *sender_guard {
                sender.send(AppMessage::SuspendDetected).ok();
                println!("Windows suspend detected zeroizing sensitive data");
            }
        }
    }
    0
}

#[cfg(windows)]
fn setup_windows_suspend_hook(app: &mut NightbaronApp) {
    if let Ok(mut sender_guard) = WINDOWS_SUSPEND_SENDER.lock() {
        *sender_guard = Some(app.sender.clone());
    }
    
    unsafe {
        let mut handle: HANDLE = std::mem::zeroed();
        let callback = suspend_resume_callback as isize;
        PowerRegisterSuspendResumeNotification(0, callback, &mut handle as *mut _ as *mut *mut c_void);
    }
}

fn main() -> eframe::Result<()> {
    disable_core_dumps();

    let options = eframe::NativeOptions {
        viewport: egui::ViewportBuilder::default()
            .with_inner_size([580.0, 450.0])
            .with_min_inner_size([400.0, 300.0]),
        ..Default::default()
    };
    
    eframe::run_native(
        "Nightbaron Encryption",
        options,
        Box::new(|cc| {
            let mut app = NightbaronApp::new(cc);

            #[cfg(target_os = "linux")]
            setup_linux_suspend_hook(app.sender.clone());

            #[cfg(windows)]
            setup_windows_suspend_hook(&mut app);

            Ok(Box::new(app))
        }),
    )
}