//ETL Pipeline Implementation
//Author: olafcio42
//Last Modified: 2025-05-08 18:27:02

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
use std::sync::Arc;
use chrono::Utc;

//Returns current timestamp in formatted string
fn get_formatted_timestamp() -> String {
    Utc::now().format("%Y-%m-%d %H:%M:%S").to_string()
}

//Main ETL pipeline for processing transactions
pub struct ETLPipeline {
    batch_size: usize,
    current_batch: TransactionBatch,
    public_key: Box<dyn PublicKey>,
    processed_count: usize,
    failed_count: usize,
}

impl ETLPipeline {
    //Creates new ETL pipeline with specified batch size and encryption key
    pub fn new(batch_size: usize, public_key: impl PublicKey + 'static) -> Self {
        Self {
            batch_size,
            current_batch: TransactionBatch::new(batch_size),
            public_key: Box::new(public_key),
            processed_count: 0,
            failed_count: 0,
        }
    }

    //Processes a vector of transactions asynchronously with progress tracking
    pub async fn process_transactions(&mut self, transactions: Vec<Transaction>) -> Result<BatchMetrics> {
        println!("\n[Starting ETL Pipeline]");
        println!("-> Time: {}", get_formatted_timestamp());
        println!("-> User: olafcio42");
        println!("-> Total transactions to process: {}", transactions.len());

        let start = Instant::now();
        let (tx, mut rx) = mpsc::channel(self.batch_size);
        let mut metrics = BatchMetrics::default();
        metrics.start_time = Some(Utc::now());

        //Process transactions in parallel using channels with increased buffer
        let tx = Arc::new(tx);
        let chunk_size = 50; //Process in smaller chunks for better feedback

        for chunk in transactions.chunks(chunk_size) {
            let chunk_tx = tx.clone();
            let chunk_data: Vec<Transaction> = chunk.to_vec();

            tokio::spawn(async move {
                for txn in chunk_data {
                    if let Err(e) = chunk_tx.send(txn).await {
                        eprintln!("Error sending transaction: {}", e);
                    }
                }
            });
        }

        //Drop the original sender to signal completion
        drop(tx);

        //Process results with progress bar
        let pb = ProgressBar::new(transactions.len() as u64);
        pb.set_style(ProgressStyle::default_bar()
            .template("{spinner:.green} [{elapsed_precise}] [{wide_bar:.cyan/blue}] {pos}/{len} | {percent}% | {msg}")
            .unwrap()
            .progress_chars("█▇▆▅▄▃▂▁  "));

        let mut processed = 0;
        let mut failed = 0;

        while let Some(mut transaction) = rx.recv().await {
            if transaction.validate() {
                processed += 1;
                self.processed_count += 1;
                metrics.processed_transactions += 1;
            } else {
                failed += 1;
                self.failed_count += 1;
                metrics.failed_transactions += 1;
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
            "Processing completed! Processed: {} | Failed: {} | Time: {:?}",
            processed,
            failed,
            start.elapsed()
        ));

        metrics.end_time = Some(Utc::now());
        metrics.processing_duration = start.elapsed();
        metrics.total_transactions = transactions.len();
        metrics.total_batches = (transactions.len() + self.batch_size - 1) / self.batch_size;

        println!("\n[ETL Pipeline Results]");
        println!("-> Time: {}", get_formatted_timestamp());
        println!("-> User: olafcio42");
        println!("-> Total processed: {}", self.processed_count);
        println!("-> Total failed: {}", self.failed_count);
        println!("-> Duration: {:?}", metrics.processing_duration);
        println!("-> Average speed: {:.2} transactions/second",
                 transactions.len() as f64 / metrics.processing_duration.as_secs_f64());

        Ok(metrics)
    }
}