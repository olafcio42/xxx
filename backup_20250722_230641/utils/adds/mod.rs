//Public modules
pub mod secure;    //Secure operations implementation
pub mod validation;//Input validation utilities
pub mod tls;      //TLS protocol implementation

//Private modules
pub mod kms;      //Key Management System internals

// Re-exports
pub use validation::{
    ValidationCache,
    ValidationResult,
    ValidationError,
    validate_keys
};