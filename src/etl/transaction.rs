use serde::{Serialize, Deserialize};
use crate::config::get_formatted_timestamp;

//Represents a financial transaction with validation capabilities
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Transaction {
    pub source_account: String,      //Source bank account number
    pub target_account: String,      //Target bank account number
    pub amount: f64,                 //Transaction amount
    pub currency: String,            //Currency code
    pub encrypted_payload: Vec<u8>,  //Additional encrypted data
    pub id: String,                 //Unique transaction identifier
    pub validated: bool,             //Validation status flag
}

impl Transaction {
    //Creates a new transaction with generated ID
    pub fn new(source_account: String, target_account: String, amount: f64, currency: String) -> Self {
        let timestamp = get_formatted_timestamp();
        let id = format!(
            "TXN_{}_{}_{}",
            timestamp.replace(" ", "").replace("-", "").replace(":", ""),
            if source_account.len() >= 8 { &source_account[..8] } else { &source_account },
            if target_account.len() >= 8 { &target_account[..8] } else { &target_account }
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

    //Validates transaction according to business rules
    pub fn validate(&mut self) -> bool {
        //Basic validation rules:
        //1. Account numbers must start with "PL" and be 28 characters long
        //2. Amount must be positive
        //3. Currency must be one of: PLN, EUR, USD, GBP, CHF
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