use std::time::Duration;

#[derive(Debug, Default, Clone)]
pub struct BatchMetrics {
    pub total_transactions: usize,
    pub processed_transactions: usize,
    pub failed_transactions: usize,
    pub last_batch_duration: Duration,
}

#[derive(Debug, Default, Clone)]
pub struct PipelineMetrics {
    pub total_batches: usize,
    pub total_transactions: usize,
    pub start_time: Option<chrono::DateTime<chrono::Utc>>,
    pub end_time: Option<chrono::DateTime<chrono::Utc>>,
    pub processing_duration: Duration,
    pub average_batch_duration: Duration,
}

impl PipelineMetrics {
    pub fn record_batch(&mut self, batch_metrics: &BatchMetrics) {
        self.total_batches += 1;
        self.total_transactions += batch_metrics.total_transactions;

        let avg_duration = self.average_batch_duration.as_nanos() as u64;
        let new_duration = batch_metrics.last_batch_duration.as_nanos() as u64;
        let total_batches = self.total_batches as u64;

        self.average_batch_duration = Duration::from_nanos(
            (avg_duration * (total_batches - 1) + new_duration) / total_batches
        );

        println!("→ Time: 2025-04-26 19:50:53 UTC");
        println!("→ User: olafcio42");
        println!("→ Batch {} recorded", self.total_batches);
        println!("→ Total transactions so far: {}", self.total_transactions);
    }

    pub fn format_metrics(&self) -> String {
        format!(
            "\n[📊 Pipeline Metrics]\n\
            → Time: 2025-04-26 19:50:53 UTC\n\
            → User: olafcio42\n\
            → Total batches: {}\n\
            → Total transactions: {}\n\
            → Start time: {}\n\
            → End time: {}\n\
            → Processing duration: {:?}\n\
            → Average batch duration: {:?}",
            self.total_batches,
            self.total_transactions,
            self.start_time.map_or("N/A".to_string(), |t| t.to_string()),
            self.end_time.map_or("N/A".to_string(), |t| t.to_string()),
            self.processing_duration,
            self.average_batch_duration
        )
    }
}