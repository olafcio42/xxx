use chrono::Utc;

fn get_formatted_timestamp() -> String {
    Utc::now().format("%Y-%m-%d %H:%M:%S").to_string()
}

fn get_formatted_date() -> String {
    Utc::now().format("%Y/%m/%d").to_string()
}