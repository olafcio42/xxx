//Public modules
pub mod transaction;  //Transaction processing and validation
pub mod batch;       //Batch operations handling
pub mod metrics;     //Performance and operational metrics
pub mod pipeline;    //ETL pipeline implementation
pub mod validation;  //Validation cache and rules

//Private modules
mod etl_tests;      //Internal testing utilities

// Re-exports
pub use validation::{ValidationCache, ValidationResult, ValidationError};
pub use transaction::Transaction;
pub use batch::TransactionBatch;