use chrono::{DateTime, Utc};
use once_cell::sync::Lazy;
use std::sync::Mutex;

pub struct SystemConfig {
    pub timestamp: DateTime<Utc>,
    pub user: String,
}

// Globalna konfiguracja systemu
pub static SYSTEM_CONFIG: Lazy<Mutex<SystemConfig>> = Lazy::new(|| {
    Mutex::new(SystemConfig {
        timestamp: Utc::now(),
        user: String::from("olafcio42"),
    })
});

pub fn get_formatted_timestamp() -> String {
    SYSTEM_CONFIG.lock()
        .unwrap()
        .timestamp
        .format("%Y-%m-%d %H:%M:%S")
        .to_string()
}

pub fn get_formatted_date() -> String {
    SYSTEM_CONFIG.lock()
        .unwrap()
        .timestamp
        .format("%Y/%m/%d")
        .to_string()
}

pub fn get_current_user() -> String {
    SYSTEM_CONFIG.lock()
        .unwrap()
        .user
        .clone()
}