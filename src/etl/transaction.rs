use serde::{Serialize, Deserialize};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Transaction {
    pub source_account: String,
    pub target_account: String,
    pub amount: f64,
    pub currency: String,
    pub encrypted_payload: Vec<u8>,
    pub id: String,
    pub validated: bool,
}

impl Transaction {
    pub fn new(source_account: String, target_account: String, amount: f64, currency: String) -> Self {
        let id = format!(
            "TXN_{}_{}_{}",
            chrono::Utc::now().format("%Y%m%d%H%M%S"),
            source_account.split_at(8).0,
            target_account.split_at(8).0
        );

        Self {
            source_account,
            target_account,
            amount,
            currency,
            encrypted_payload: Vec::new(),
            id,
            validated: false,
        }
    }

    pub fn validate(&mut self) -> bool {
        // Basic validation rules
        let is_valid =
            self.source_account.starts_with("PL") &&
                self.source_account.len() == 28 &&
                self.target_account.starts_with("PL") &&
                self.target_account.len() == 28 &&
                self.amount > 0.0 &&
                ["PLN", "EUR", "USD", "GBP", "CHF"].contains(&self.currency.as_str());

        self.validated = is_valid;
        is_valid
    }
}