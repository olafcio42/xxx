use super::transaction::Transaction;
use std::collections::VecDeque;
use anyhow::{Result, anyhow};

pub struct TransactionBatch {
    transactions: VecDeque<Transaction>,
    batch_size: usize,
}

impl TransactionBatch {
    pub fn new(batch_size: usize) -> Self {
        Self {
            transactions: VecDeque::with_capacity(batch_size),
            batch_size,
        }
    }

    pub fn add_transaction(&mut self, transaction: Transaction) -> Result<()> {
        if self.is_full() {
            return Err(anyhow!("Batch is full"));
        }

        self.transactions.push_back(transaction);
        println!("→ Added transaction to batch ({}/{})",
                 self.current_size(),
                 self.batch_size
        );

        Ok(())
    }

    pub fn get_next_transaction(&mut self) -> Option<Transaction> {
        self.transactions.pop_front()
    }

    pub fn is_full(&self) -> bool {
        self.transactions.len() >= self.batch_size
    }

    pub fn is_empty(&self) -> bool {
        self.transactions.is_empty()
    }

    pub fn current_size(&self) -> usize {
        self.transactions.len()
    }
}