use serde::{Serialize, Deserialize};
use uuid::{uuid, Uuid};
use crate::config::get_formatted_timestamp;

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
            // Używamy makra uuid! do generowania statycznego UUID
            id: format!("TX_{}", uuid!("67e55044-10b1-426f-9247-bb680e5fe0c8")),
            source,
            target,
            amount,
            currency,
            timestamp: get_formatted_timestamp(),
            created_by: crate::config::get_current_user(),
        }
    }

    pub fn validate(&self) -> bool {
        !self.source.is_empty()
            && !self.target.is_empty()
            && self.amount > 0.0
            && !self.currency.is_empty()
    }
}