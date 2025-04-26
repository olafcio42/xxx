use super::transaction::Transaction;
use super::metrics::BatchMetrics;
use std::collections::VecDeque;
use tokio::sync::mpsc;
use anyhow::Result;

pub struct TransactionBatch {
    transactions: VecDeque<Transaction>,
    batch_size: usize,
    metrics: BatchMetrics,
}

impl TransactionBatch {
    pub fn new(batch_size: usize) -> Self {
        Self {
            transactions: VecDeque::with_capacity(batch_size),
            batch_size,
            metrics: BatchMetrics::default(),
        }
    }

    // Add a method to get the current batch size
    pub fn current_size(&self) -> usize {
        self.transactions.len()
    }

    // Add a method to check if the batch is full
    pub fn is_full(&self) -> bool {
        self.transactions.len() >= self.batch_size
    }

    pub fn add_transaction(&mut self, transaction: Transaction) -> Result<()> {
        if self.is_full() {
            return Err(anyhow::anyhow!("Batch is full"));
        }

        self.transactions.push_back(transaction);
        self.metrics.total_transactions += 1;

        println!("→ Added transaction to batch ({}/{})",
                 self.current_size(),
                 self.batch_size
        );

        Ok(())
    }

    pub async fn process_batch(&mut self, tx: mpsc::Sender<Transaction>) -> Result<()> {
        let start = std::time::Instant::now();
        let batch_size = self.current_size();

        println!("\n[📦 Processing Batch]");
        println!("→ Time: 2025-04-26 19:41:13 UTC");
        println!("→ User: olafcio42");
        println!("→ Batch size: {}", batch_size);

        while let Some(transaction) = self.transactions.pop_front() {
            if transaction.validate() {
                tx.send(transaction).await?;
                self.metrics.processed_transactions += 1;
            } else {
                self.metrics.failed_transactions += 1;
            }
        }

        self.metrics.last_batch_duration = start.elapsed();

        println!("→ Processed: {}", self.metrics.processed_transactions);
        println!("→ Failed: {}", self.metrics.failed_transactions);
        println!("→ Duration: {:?}", self.metrics.last_batch_duration);

        Ok(())
    }

    // Add getter for metrics
    pub fn get_metrics(&self) -> &BatchMetrics {
        &self.metrics
    }
}