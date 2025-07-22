//! Implementacja algorytmu Kyber w Rust
//! 
//! Post-kwantowy algorytm wymiany kluczy oparty na Module-LWE

#![no_std]
#![allow(non_snake_case)]

pub mod config;
pub mod core;
pub mod kem;
pub mod types;
pub mod utils;
pub mod variants;

// Re-eksportuj najważniejsze elementy
pub use config::*;
pub use kem::{keygen, encaps, decaps};
pub use types::{PublicKey, SecretKey};

/// Preludium zawierające najczęściej używane typy i funkcje
pub mod prelude {
    pub use crate::config::*;
    pub use crate::kem::*;
    pub use crate::types::*;
}
