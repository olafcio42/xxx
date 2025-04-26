use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use uuid::Uuid;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Transaction {
    pub id: Uuid,
    pub timestamp: DateTime<Utc>,
    pub source_account: String,
    pub target_account: String,
    pub amount: f64,
    pub currency: String,
    pub encrypted_payload: Vec<u8>,
    pub signature: Vec<u8>,
}

impl Transaction {
    pub fn new(
        source_account: String,
        target_account: String,
        amount: f64,
        currency: String,
    ) -> Self {
        Self {
            id: Uuid::new_v4(),
            timestamp: Utc::now(),
            source_account,
            target_account,
            amount,
            currency,
            encrypted_payload: Vec::new(),
            signature: Vec::new(),
        }
    }

    pub fn validate(&self) -> bool {
        // Basic validation rules
        !self.source_account.is_empty()
            && !self.target_account.is_empty()
            && self.amount > 0.0
            && !self.currency.is_empty()
            && self.encrypted_payload.len() > 0
            && self.signature.len() > 0
    }
}