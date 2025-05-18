pub mod adds;
pub mod etl;

//Re-export commonly used items
pub use adds::{
    secure::SecureSecret,
    validation::validate_keys,
    tls::TlsSession,
    kms::{DummySharedSecret, CertificateInfo}
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
        let _session = TlsSession::new();
        let _batch = TransactionBatch::new(10);
        assert!(true, "All modules are accessible");
    }
}