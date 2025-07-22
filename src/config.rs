use chrono::Utc;
use once_cell::sync::Lazy;
use std::sync::Mutex;

pub struct SystemConfig {
    pub user: String,
}

// Global system configuration
pub static SYSTEM_CONFIG: Lazy<Mutex<SystemConfig>> = Lazy::new(|| {
    Mutex::new(SystemConfig {
        user: String::from("olafcio42"),
    })
});

pub fn get_formatted_timestamp() -> String {
    Utc::now().format("%Y-%m-%d %H:%M:%S").to_string()
}

pub fn get_formatted_date() -> String {
    Utc::now().format("%Y/%m/%d").to_string()
}

pub fn get_current_user() -> String {
    SYSTEM_CONFIG.lock()
        .unwrap()
        .user
        .clone()
}

pub fn initialize_config(user: Option<String>) {
    if let Some(u) = user {
        SYSTEM_CONFIG.lock().unwrap().user = u;
    }
}