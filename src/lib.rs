pub mod kyber768;
pub mod kyber1024;
pub mod utils;

// Re-eksporty głównych komponentów
pub use kyber768::kem as kem768;
pub use kyber1024::kem as kem1024;
pub use utils::{entropy, encoding, validation};

// Stałe konfiguracyjne
pub const KYBER_768_KEY_SIZE: usize = 1088;
pub const KYBER_1024_KEY_SIZE: usize = 1568;