use std::fs::{File, create_dir_all};
use std::io::{Write, BufReader, BufRead};
use std::path::Path;
use chrono::Utc;
use csv::{Writer, ReaderBuilder};
use serde::{Serialize, Deserialize};
use anyhow::Result;
use crate::config::{get_formatted_date, get_formatted_timestamp, get_current_user};

pub struct TransactionDataGenerator {
    output_dir: String,
    current_timestamp: String,
    current_user: String,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct Transaction {
    transaction_id: String,
    pub source_account: String,
    pub target_account: String,
    pub amount: f64,
    pub currency: String,
    timestamp: String,
    created_by: String,
}

impl TransactionDataGenerator {
    pub fn new(output_dir: &str, timestamp: &str, user: &str) -> Self {
        Self {
            output_dir: output_dir.to_string(),
            current_timestamp: timestamp.to_string(),
            current_user: user.to_string(),
        }
    }

    // Generuje i zapisuje transakcje do pliku CSV
    pub fn generate_and_save(&self, count: usize, filename: &str) -> Result<String> {
        let full_path = self.ensure_output_dir(filename)?;
        let mut writer = Writer::from_path(&full_path)?;
        let transactions = self.generate_transactions(count);

        for transaction in transactions {
            writer.serialize(transaction)?;
        }
        writer.flush()?;

        println!("→ Generated {} transactions", count);
        println!("→ Saved to: {}", full_path);

        Ok(full_path)
    }

    // Wczytuje transakcje z pliku CSV
    pub fn load_transactions(&self, filepath: &str) -> Result<Vec<Transaction>> {
        let mut reader = ReaderBuilder::new()
            .has_headers(true)
            .from_path(filepath)?;

        let transactions: Vec<Transaction> = reader
            .deserialize()
            .filter_map(|result| result.ok())
            .collect();

        println!("→ Loaded {} transactions from {}", transactions.len(), filepath);

        Ok(transactions)
    }

    // Generuje określoną liczbę transakcji
    fn generate_transactions(&self, count: usize) -> Vec<Transaction> {
        let currencies = ["PLN", "EUR", "USD", "GBP", "CHF"];
        let mut transactions = Vec::with_capacity(count);

        for i in 0..count {
            let currency = currencies[i % currencies.len()];
            let amount = 100.0 + (i as f64 % 9900.0);

            let source_base = format!("{:08}", i);
            let target_base = format!("{:08}", i + 1);

            let source_account = format!("PL{}0000{}", "0".repeat(14), source_base);
            let target_account = format!("PL{}0000{}", "0".repeat(14), target_base);

            transactions.push(Transaction {
                transaction_id: format!("BANK/{}/{:06}",
                                        self.current_timestamp.split_whitespace().next().unwrap_or("2025/06/01")
                                            .replace("-", "/"),
                                        i + 1
                ),
                source_account,
                target_account,
                amount,
                currency: currency.to_string(),
                timestamp: self.current_timestamp.clone(),
                created_by: self.current_user.clone(),
            });
        }

        transactions
    }

    // Tworzy katalog wyjściowy jeśli nie istnieje
    fn ensure_output_dir(&self, filename: &str) -> Result<String> {
        let path = Path::new(&self.output_dir);
        if !path.exists() {
            create_dir_all(path)?;
        }
        Ok(path.join(filename).to_string_lossy().to_string())
    }

    // Generuje nazwę pliku na podstawie timestampu
    pub fn generate_filename(&self) -> String {
        let date = self.current_timestamp.split_whitespace()
            .next()
            .unwrap_or(&get_formatted_date())
            .replace("-", "");
        format!("transactions_{}.csv", date)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::tempdir;

    #[test]
    fn test_transaction_generation_and_loading() -> Result<()> {
        let temp_dir = tempdir()?;
        let temp_path = temp_dir.path().to_string_lossy().to_string();

        let generator = TransactionDataGenerator::new(
            &temp_path,
            "2025-06-01 07:19:41",
            "test_user"
        );

        let filename = generator.generate_filename();
        let file_path = generator.generate_and_save(100, &filename)?;
        let loaded_transactions = generator.load_transactions(&file_path)?;

        assert_eq!(loaded_transactions.len(), 100);
        assert!(loaded_transactions[0].transaction_id.starts_with("BANK/2025/06/01"));
        assert!(loaded_transactions[0].source_account.starts_with("PL"));
        assert_eq!(loaded_transactions[0].created_by, "test_user");

        Ok(())
    }
}