//Transaction batch processing implementation
//Author: olafcio42
//Last Modified: 2025-05-08 18:24:49

use super::transaction::Transaction;
use std::collections::VecDeque;
use anyhow::{Result, anyhow};
use chrono::Utc;

//Returns current timestamp in formatted string
fn get_formatted_timestamp() -> String {
    Utc::now().format("%Y-%m-%d %H:%M:%S").to_string()
}

//Handles batches of transactions with fixed capacity
pub struct TransactionBatch {
    transactions: VecDeque<Transaction>,
    batch_size: usize,
}

impl TransactionBatch {
    //Creates new transaction batch with specified size
    pub fn new(batch_size: usize) -> Self {
        println!("\n[Creating New Transaction Batch]");
        println!("-> Time: {}", get_formatted_timestamp());
        println!("-> User: olafcio42");
        println!("-> Batch size: {}", batch_size);

        Self {
            transactions: VecDeque::with_capacity(batch_size),
            batch_size,
        }
    }

    //Adds a new transaction to the batch if space available
    pub fn add_transaction(&mut self, transaction: Transaction) -> Result<()> {
        if self.is_full() {
            println!("\n[Operation Failed]");
            println!("-> Time: {}", get_formatted_timestamp());
            println!("-> Error: Batch is full ({}/{})",
                     self.current_size(),
                     self.batch_size
            );
            return Err(anyhow!("Batch is full"));
        }

        self.transactions.push_back(transaction);
        println!("-> Time: {}", get_formatted_timestamp());
        println!("-> Added transaction to batch ({}/{})",
                 self.current_size(),
                 self.batch_size
        );

        Ok(())
    }

    //Retrieves and removes the next transaction from the batch
    pub fn get_next_transaction(&mut self) -> Option<Transaction> {
        let transaction = self.transactions.pop_front();
        if transaction.is_some() {
            println!("-> Time: {}", get_formatted_timestamp());
            println!("-> Retrieved transaction from batch ({}/{})",
                     self.current_size(),
                     self.batch_size
            );
        }
        transaction
    }

    //Checks if batch has reached maximum capacity
    pub fn is_full(&self) -> bool {
        self.transactions.len() >= self.batch_size
    }

    //Checks if batch contains no transactions
    pub fn is_empty(&self) -> bool {
        self.transactions.is_empty()
    }

    //Returns current number of transactions in batch
    pub fn current_size(&self) -> usize {
        self.transactions.len()
    }
}

//Unit tests
#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_batch_operations() {
        println!("\n=== Starting Batch Operations Test ===");
        println!("-> Time: {}", get_formatted_timestamp());
        println!("-> User: olafcio42");

        let mut batch = TransactionBatch::new(2);

        //Test adding transactions
        assert!(batch.add_transaction(Transaction::new(
            "SRC_1".to_string(),
            "DST_1".to_string(),
            100.0,
            "USD".to_string()
        )).is_ok());

        assert!(batch.add_transaction(Transaction::new(
            "SRC_2".to_string(),
            "DST_2".to_string(),
            200.0,
            "EUR".to_string()
        )).is_ok());

        //Test batch is full
        assert!(batch.is_full());

        //Test adding to full batch fails
        assert!(batch.add_transaction(Transaction::new(
            "SRC_3".to_string(),
            "DST_3".to_string(),
            300.0,
            "GBP".to_string()
        )).is_err());

        println!("\n=== Test Completed Successfully ===");
        println!("-> Time: {}", get_formatted_timestamp());
    }
}