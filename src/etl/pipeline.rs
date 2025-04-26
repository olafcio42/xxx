use super::{
    transaction::Transaction,
    metrics::BatchMetrics,
    batch::TransactionBatch
};
use pqcrypto_traits::kem::PublicKey;
use tokio::sync::mpsc;
use anyhow::Result;
use std::time::Instant;
use indicatif::{ProgressBar, ProgressStyle};

pub struct ETLPipeline {
    batch_size: usize,
    current_batch: TransactionBatch,
    public_key: Box<dyn PublicKey>,
    processed_count: usize,
    failed_count: usize,
}

impl ETLPipeline {
    pub fn new(batch_size: usize, public_key: impl PublicKey + 'static) -> Self {
        Self {
            batch_size,
            current_batch: TransactionBatch::new(batch_size),
            public_key: Box::new(public_key),
            processed_count: 0,
            failed_count: 0,
        }
    }

    pub async fn process_transactions(&mut self, transactions: Vec<Transaction>) -> Result<BatchMetrics> {
        println!("\n[🚀 Starting ETL Pipeline]");
        println!("→ Time: 2025-04-26 21:48:59");
        println!("→ User: olafcio42");
        println!("→ Total transactions to process: {}", transactions.len());

        let start = Instant::now();
        let (tx, mut rx) = mpsc::channel(self.batch_size);
        let mut metrics = BatchMetrics::default();
        metrics.start_time = Some(chrono::Utc::now());

        for transaction in transactions {
            if let Err(e) = self.current_batch.add_transaction(transaction) {
                println!("Error adding transaction to batch: {}", e);
                self.failed_count += 1;
                continue;
            }

            if self.current_batch.is_full() {
                self.process_batch(&mut metrics, tx.clone()).await?;
            }
        }

        if !self.current_batch.is_empty() {
            self.process_batch(&mut metrics, tx.clone()).await?;
        }

        drop(tx);

        while let Some(mut transaction) = rx.recv().await {
            if transaction.validate() {
                self.processed_count += 1;
                metrics.processed_transactions += 1;
            } else {
                self.failed_count += 1;
                metrics.failed_transactions += 1;
            }
        }

        metrics.end_time = Some(chrono::Utc::now());
        metrics.processing_duration = start.elapsed();

        println!("\n[✅ ETL Pipeline Results]");
        println!("→ Time: 2025-04-26 21:48:59");
        println!("→ User: olafcio42");
        println!("→ Total processed: {}", self.processed_count);
        println!("→ Total failed: {}", self.failed_count);
        println!("→ Duration: {:?}", metrics.processing_duration);

        Ok(metrics)
    }

    async fn process_batch(&mut self, metrics: &mut BatchMetrics, tx: mpsc::Sender<Transaction>) -> Result<()> {
        let batch_size = self.current_batch.current_size();
        let start = Instant::now();

        println!("\n[📦 Starting Batch Processing]");
        println!("→ Time: 2025-04-26 21:48:59");
        println!("→ User: olafcio42");
        println!("→ Batch size: {}", batch_size);
        println!("→ Processing started...\n");

        let pb = ProgressBar::new(batch_size as u64);
        pb.set_style(ProgressStyle::default_bar()
            .template("{spinner:.green} [{elapsed_precise}] [{wide_bar:.cyan/blue}] {pos}/{len} | {percent}% | {msg}")
            .unwrap()
            .progress_chars("█▇▆▅▄▃▂▁  "));

        let mut processed = 0;
        let mut failed = 0;

        // Przetwarzaj transakcje w mniejszych chunk'ach
        let chunk_size = 10;
        let mut transactions = Vec::with_capacity(chunk_size);

        while let Some(transaction) = self.current_batch.get_next_transaction() {
            transactions.push(transaction);

            if transactions.len() >= chunk_size {
                for mut txn in transactions.drain(..) {
                    if txn.validate() {
                        processed += 1;
                        tx.send(txn).await?;
                    } else {
                        failed += 1;
                    }

                    let total = processed + failed;
                    pb.set_position(total as u64);
                    pb.set_message(format!(
                        "OK: {} | Failed: {} | Speed: {:.0} tx/s",
                        processed,
                        failed,
                        total as f64 / start.elapsed().as_secs_f64()
                    ));
                }

                tokio::time::sleep(tokio::time::Duration::from_millis(50)).await;
            }
        }

        // Przetwórz pozostałe transakcje
        for mut txn in transactions {
            if txn.validate() {
                processed += 1;
                tx.send(txn).await?;
            } else {
                failed += 1;
            }

            let total = processed + failed;
            pb.set_position(total as u64);
            pb.set_message(format!(
                "OK: {} | Failed: {} | Speed: {:.0} tx/s",
                processed,
                failed,
                total as f64 / start.elapsed().as_secs_f64()
            ));
        }

        pb.finish_with_message(format!(
            "✅ Batch completed! Processed: {} | Failed: {} | Time: {:?}",
            processed,
            failed,
            start.elapsed()
        ));

        metrics.total_batches += 1;
        metrics.total_transactions += batch_size;
        metrics.processed_transactions += processed;
        metrics.failed_transactions += failed;
        metrics.last_batch_duration = start.elapsed();

        println!("\n[📊 Batch Summary]");
        println!("→ Time: 2025-04-26 21:48:59");
        println!("→ User: olafcio42");
        println!("→ Total processed: {}", processed);
        println!("→ Total failed: {}", failed);
        println!("→ Duration: {:?}", metrics.last_batch_duration);
        println!("→ Speed: {:.2} transactions/second",
                 batch_size as f64 / metrics.last_batch_duration.as_secs_f64());

        println!("\n{}", "=".repeat(80));

        Ok(())
    }
}