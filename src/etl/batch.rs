use super::transaction::Transaction;
use anyhow::Result;
use std::vec::Vec;

pub struct TransactionBatch {
    pub transactions: Vec<Transaction>,
    pub max_size: usize,
}

impl TransactionBatch {
    pub fn new(max_size: usize) -> Self {
        Self {
            transactions: Vec::with_capacity(max_size),
            max_size,
        }
    }

    pub fn add_transaction(&mut self, transaction: Transaction) -> Result<()> {
        if self.transactions.len() >= self.max_size {
            anyhow::bail!("Batch is full");
        }
        self.transactions.push(transaction);
        Ok(())
    }

    pub fn is_full(&self) -> bool {
        self.transactions.len() >= self.max_size
    }

    pub fn clear(&mut self) {
        self.transactions.clear();
    }

    pub fn len(&self) -> usize {
        self.transactions.len()
    }

    pub fn is_empty(&self) -> bool {
        self.transactions.is_empty()
    }
}