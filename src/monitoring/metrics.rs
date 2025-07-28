use chrono::{DateTime, Utc};
use std::time::Duration;

#[derive(Debug, Default, Clone)]
pub struct BatchMetrics {
    pub total_transactions: usize,
    pub processed_transactions: usize,
    pub failed_transactions: usize,
    pub total_batches: usize,
    pub last_batch_duration: Duration,
    pub processing_duration: Duration,
    pub start_time: Option<DateTime<Utc>>,
    pub end_time: Option<DateTime<Utc>>,
    pub average_batch_duration: Duration,
}