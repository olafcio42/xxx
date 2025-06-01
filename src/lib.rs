//Kyber PQC Implementation
//Author: olafcio42
//Last Modified: 2025-05-19 16:20:29

//Public modules
pub mod adds;
pub mod api;
pub mod etl;
pub mod data_generator;
pub mod config;

pub use api::ApiConfig;

//Re-export commonly used items
pub use adds::{
    secure::SecureSecret,
    validation::validate_keys,
    tls::TlsSession,
    kms::{CertificateInfo, DummySharedSecret},
};

pub use etl::{
    transaction::Transaction,
    batch::TransactionBatch,
    metrics::BatchMetrics,
    pipeline::ETLPipeline
};

//Library version
pub const VERSION: &str = env!("CARGO_PKG_VERSION");

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_module_availability() {
        // This test ensures that all public modules are available
        let _session = TlsSession::new();
        let _batch = TransactionBatch::new(10);
        assert!(true, "All modules are accessible");
    }
}