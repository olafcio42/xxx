use anyhow::Result;

#[derive(Default)]
pub struct ApiConfig {
    pub port: u16,
    pub host: String,
}

pub async fn start_api_server(config: ApiConfig) -> Result<()> {
    // Podstawowa implementacja
    println!("Starting API server on {}:{}", config.host, config.port);
    Ok(())
}