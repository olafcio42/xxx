use serde::{Serialize, Deserialize};
use uuid::Uuid;
use crate::config::{self};


#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Transaction {
    pub id: String,
    pub source: String,
    pub target: String,
    pub amount: f64,
    pub currency: String,
    pub timestamp: String,
    pub created_by: String,
}

impl Transaction {
    pub fn new(source: String, target: String, amount: f64, currency: String) -> Self {
        Self {
            id: format!("TX_{}", Uuid::from_u128(42)),
            source,
            target,
            amount,
            currency,
            timestamp: config::get_formatted_timestamp(),
            created_by: config::get_current_user(),
        }
    }

    pub fn validate(&self) -> bool {
        !self.source.is_empty()
            && !self.target.is_empty()
            && self.amount > 0.0
            && !self.currency.is_empty()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_transaction_creation() {
        // Initialize config with test user

        let tx = Transaction::new(
            "PL12345678".to_string(),
            "PL87654321".to_string(),
            100.0,
            "PLN".to_string()
        );

        assert!(tx.id.starts_with("TX_"));
        assert_eq!(tx.source, "PL12345678");
        assert_eq!(tx.target, "PL87654321");
        assert_eq!(tx.amount, 100.0);
        assert_eq!(tx.currency, "PLN");
        assert!(!tx.timestamp.is_empty());
        assert_eq!(tx.created_by, "test_user");
    }

    #[test]
    fn test_transaction_validation() {
        let valid_tx = Transaction::new(
            "PL12345678".to_string(),
            "PL87654321".to_string(),
            100.0,
            "PLN".to_string()
        );
        assert!(valid_tx.validate());

        let invalid_tx = Transaction::new(
            "".to_string(),
            "PL87654321".to_string(),
            -100.0,
            "".to_string()
        );
        assert!(!invalid_tx.validate());
    }
}