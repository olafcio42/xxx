pub mod adds;
pub mod api;
pub mod config;
pub mod etl;
pub mod data_generator;
pub mod tests;   // This will be for our test modules
pub mod security;  // Add this line


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