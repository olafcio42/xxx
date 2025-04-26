use super::{
    batch::TransactionBatch,
    metrics::PipelineMetrics,
    transaction::Transaction,
};
use tokio::sync::mpsc;
use anyhow::Result;
use std::time::Instant;
use crate::adds::secure::SecureSecret;
use pqcrypto_kyber::kyber1024::*;

pub struct ETLPipeline {
    batch_size: usize,
    current_batch: TransactionBatch,
    metrics: PipelineMetrics,
    public_key: PublicKey,
}

impl ETLPipeline {
    pub fn new(batch_size: usize, public_key: PublicKey) -> Self {
        Self {
            batch_size,
            current_batch: TransactionBatch::new(batch_size),
            metrics: PipelineMetrics::default(),
            public_key,
        }
    }

    pub async fn process_transactions(&mut self, transactions: Vec<Transaction>) -> Result<PipelineMetrics> {
        let (tx, mut rx) = mpsc::channel(self.batch_size);
        let start = Instant::now();
        self.metrics.start_time = Some(chrono::Utc::now());

        println!("\n[🔄 Starting ETL Pipeline]");
        println!("→ Time: 2025-04-26 19:41:13 UTC");
        println!("→ User: olafcio42");
        println!("→ Total transactions: {}", transactions.len());
        println!("→ Batch size: {}", self.batch_size);

        // Process transactions in batches
        for transaction in transactions {
            match self.current_batch.add_transaction(transaction) {
                Ok(_) => {
                    if self.current_batch.is_full() {
                        self.current_batch.process_batch(tx.clone()).await?;
                    }
                }
                Err(_) => {
                    self.current_batch.process_batch(tx.clone()).await?;
                }
            }
        }

        // Process any remaining transactions
        if self.current_batch.current_size() > 0 {
            self.current_batch.process_batch(tx.clone()).await?;
        }

        drop(tx);

        // Process encrypted transactions
        while let Some(transaction) = rx.recv().await {
            self.encrypt_and_store(transaction).await?;
        }

        self.metrics.end_time = Some(chrono::Utc::now());
        self.metrics.processing_duration = start.elapsed();

        println!("\n[✅ ETL Pipeline Completed]");
        println!("→ Time: 2025-04-26 19:41:13 UTC");
        println!("→ Total duration: {:?}", self.metrics.processing_duration);
        println!("→ Average batch duration: {:?}", self.metrics.average_batch_duration);

        Ok(self.metrics.clone())
    }

    async fn encrypt_and_store(&self, mut transaction: Transaction) -> Result<()> {
        // Encrypt transaction data using Kyber
        let transaction_data = serde_json::to_vec(&transaction)?;
        let (shared_secret, ciphertext) = encapsulate(&self.public_key);

        let secure_secret = SecureSecret::from_shared(shared_secret);

        // Encrypt the transaction data
        transaction.encrypted_payload = transaction_data
            .iter()
            .zip(secure_secret.expose().iter().cycle())
            .map(|(a, b)| a ^ b)
            .collect();

        println!("→ Encrypted transaction: {} ({} bytes)",
                 transaction.id,
                 transaction.encrypted_payload.len()
        );

        Ok(())
    }
}