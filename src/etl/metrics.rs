use std::time::Duration;
use chrono::{DateTime, Utc};

fn get_formatted_timestamp() -> String {
    Utc::now().format("%Y-%m-%d %H:%M:%S").to_string()
}

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

impl BatchMetrics {
    pub fn record_batch(&mut self, batch_metrics: &BatchMetrics) {
        self.total_batches += 1;
        self.total_transactions += batch_metrics.total_transactions;
        self.processed_transactions += batch_metrics.processed_transactions;
        self.failed_transactions += batch_metrics.failed_transactions;

        let avg_duration = self.average_batch_duration.as_nanos() as u64;
        let new_duration = batch_metrics.last_batch_duration.as_nanos() as u64;
        let total_batches = self.total_batches as u64;

        if total_batches > 0 {
            self.average_batch_duration = Duration::from_nanos(
                (avg_duration * (total_batches - 1) + new_duration) / total_batches
            );
        }

        println!("\n[|||| Batch Metrics Update]");
        println!("→ Time: {}", get_formatted_timestamp());
        println!("→ User: olafcio42");
        println!("→ Total batches: {}", self.total_batches);
        println!("→ Total transactions: {}", self.total_transactions);
        println!("→ Processed transactions: {}", self.processed_transactions);
        println!("→ Failed transactions: {}", self.failed_transactions);
        println!("→ Average batch duration: {:?}", self.average_batch_duration);
    }

    pub fn format_metrics(&self) -> String {
        format!(
            "\n[|||| Pipeline Metrics]\n\
            → Time: {}\n\
            → User: olafcio42\n\
            → Total batches: {}\n\
            → Total transactions: {}\n\
            → Processed transactions: {}\n\
            → Failed transactions: {}\n\
            → Start time: {}\n\
            → End time: {}\n\
            → Processing duration: {:?}\n\
            → Average batch duration: {:?}",
            get_formatted_timestamp(),
            self.total_batches,
            self.total_transactions,
            self.processed_transactions,
            self.failed_transactions,
            self.start_time.map_or("N/A".to_string(), |t| t.to_string()),
            self.end_time.map_or("N/A".to_string(), |t| t.to_string()),
            self.processing_duration,
            self.average_batch_duration
        )
    }
}