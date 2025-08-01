pub mod adds;
pub mod api;
pub mod config;
pub mod etl;
pub mod data_generator;
pub mod tests;
pub mod security;
pub mod analysis;

// Re-exports
pub use adds::tls::TlsSession;
pub use adds::validation::{
    ValidationCache,
    ValidationResult,
    ValidationError,
    validate_keys
};
pub use etl::{
    transaction::Transaction,
    batch::TransactionBatch,
    pipeline::ETLPipeline,
};



pub mod core;
pub mod variants;
pub mod crypto;
pub mod optimizations;
pub mod integration;
pub mod monitoring;

// Re-eksportuj komponenty crypto
pub use crypto::secure::SecureSecret;
pub use crypto::validation::{ValidationCache, ValidationResult};
pub use crypto::kms::KeyManagementSystem;

// Re-eksportuj komponenty integration
pub use integration::tls::TlsSession;
pub use integration::etl::ETLPipeline;