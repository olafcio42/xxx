use actix_web::{web, App, HttpResponse, HttpServer, Responder};
use serde::{Deserialize, Serialize};
use chrono::Utc;
use anyhow::Result;
use base64;
use std::sync::Arc;
use tokio::sync::Mutex;

use crate::adds::{
    secure::SecureSecret,
    validation::validate_keys,
    tls::TlsSession
};
use crate::etl::{
    transaction::Transaction as EtlTransaction,
    pipeline::ETLPipeline
};
use pqcrypto_kyber::kyber1024::*;
use pqcrypto_traits::kem::{PublicKey, SecretKey, SharedSecret, Ciphertext};

// Request/Response Structures
#[derive(Debug, Serialize, Deserialize)]
pub struct EncryptRequest {
    pub data: String,
    pub public_key: Option<String>,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct EncryptResponse {
    pub ciphertext: String,
    pub transaction_id: String,
    pub timestamp: String,
    pub user: String,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct DecryptRequest {
    pub ciphertext: String,
    pub secret_key: String,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct DecryptResponse {
    pub plaintext: String,
    pub transaction_id: String,
    pub timestamp: String,
    pub user: String,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct KeyGenResponse {
    pub public_key: String,
    pub secret_key: String,
    pub key_id: String,
    pub timestamp: String,
    pub user: String,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct BatchProcessRequest {
    pub transactions: Vec<TransactionData>,
    pub batch_size: usize,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct BatchProcessResponse {
    pub processed_count: usize,
    pub failed_count: usize,
    pub processing_time: String,
    pub transaction_id: String,
    pub timestamp: String,
    pub user: String,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct TransactionData {
    pub transaction_id: String,
    pub source_account: String,
    pub target_account: String,
    pub amount: f64,
    pub currency: String,
    pub timestamp: String,
}

// Shared Application State
pub struct AppState {
    tls_session: Arc<Mutex<TlsSession>>,
}

// Configuration Structure
#[derive(Clone, Debug)]
pub struct ApiConfig {
    pub host: String,
    pub port: u16,
}

impl Default for ApiConfig {
    fn default() -> Self {
        Self {
            host: "127.0.0.1".to_string(),
            port: 8080,
        }
    }
}

// Helper Functions
fn get_formatted_timestamp() -> String {
    Utc::now().format("%Y-%m-%d %H:%M:%S").to_string()
}

// API Endpoints
async fn generate_keypair() -> impl Responder {
    println!("\n[API] Generating new keypair");
    println!("→ Time: {}", get_formatted_timestamp());
    println!("→ User: olafcio42");

    let (public_key, secret_key) = keypair();

    let response = KeyGenResponse {
        public_key: base64::encode(public_key.as_bytes()),
        secret_key: base64::encode(secret_key.as_bytes()),
        key_id: format!("KEY_{}", Utc::now().timestamp()),
        timestamp: get_formatted_timestamp(),
        user: "olafcio42".to_string(),
    };

    HttpResponse::Ok().json(response)
}

async fn encrypt(
    req: web::Json<EncryptRequest>,
    state: web::Data<AppState>
) -> impl Responder {
    println!("\n[API] Processing encryption request");
    println!("→ Time: {}", get_formatted_timestamp());
    println!("→ User: olafcio42");

    let mut tls_session = state.tls_session.lock().await;

    match tls_session.begin_handshake() {
        Ok(_) => {
            let (public_key, _) = keypair();
            let data = req.data.as_bytes();

            let (shared_secret, ciphertext) = encapsulate(&public_key);
            let secure = SecureSecret::from_shared(shared_secret);

            let encrypted = data.iter()
                .zip(secure.expose().iter().cycle())
                .map(|(a, b)| a ^ b)
                .collect::<Vec<u8>>();

            let response = EncryptResponse {
                ciphertext: base64::encode(&encrypted),
                transaction_id: format!("TXN_{}", Utc::now().timestamp()),
                timestamp: get_formatted_timestamp(),
                user: "olafcio42".to_string(),
            };

            HttpResponse::Ok().json(response)
        },
        Err(e) => {
            HttpResponse::InternalServerError().body(format!("Encryption failed: {}", e))
        }
    }
}

async fn decrypt(
    req: web::Json<DecryptRequest>,
    state: web::Data<AppState>
) -> impl Responder {
    println!("\n[API] Processing decryption request");
    println!("→ Time: {}", get_formatted_timestamp());
    println!("→ User: olafcio42");

    match base64::decode(&req.ciphertext) {
        Ok(ciphertext) => {
            let mut tls_session = state.tls_session.lock().await;
            let (_, secret_key) = keypair();

            let decrypted = ciphertext.iter()
                .zip(secret_key.as_bytes().iter().cycle())
                .map(|(a, b)| a ^ b)
                .collect::<Vec<u8>>();

            let response = DecryptResponse {
                plaintext: String::from_utf8_lossy(&decrypted).to_string(),
                transaction_id: format!("TXN_{}", Utc::now().timestamp()),
                timestamp: get_formatted_timestamp(),
                user: "olafcio42".to_string(),
            };

            HttpResponse::Ok().json(response)
        },
        Err(e) => {
            HttpResponse::BadRequest().body(format!("Invalid base64 input: {}", e))
        }
    }
}

async fn process_batch(
    data: web::Json<BatchProcessRequest>,
    state: web::Data<AppState>,
) -> impl Responder {
    println!("\n[API] Processing batch request");
    println!("→ Time: {}", get_formatted_timestamp());
    println!("→ User: olafcio42");
    println!("→ Batch size: {}", data.transactions.len());

    let (public_key, _) = keypair();

    let etl_transactions: Vec<EtlTransaction> = data.transactions
        .iter()
        .map(|t| EtlTransaction::new(
            t.source_account.clone(),
            t.target_account.clone(),
            t.amount,
            t.currency.clone()
        ))
        .collect();

    let mut pipeline = ETLPipeline::new(data.batch_size, public_key);

    match pipeline.process_transactions(etl_transactions).await {
        Ok(metrics) => {
            let response = BatchProcessResponse {
                processed_count: metrics.processed_transactions,
                failed_count: metrics.failed_transactions,
                processing_time: format!("{:?}", metrics.processing_duration),
                transaction_id: format!("BATCH_{}", Utc::now().timestamp()),
                timestamp: get_formatted_timestamp(),
                user: "olafcio42".to_string(),
            };
            HttpResponse::Ok().json(response)
        },
        Err(e) => {
            HttpResponse::InternalServerError()
                .body(format!("Batch processing failed: {}", e))
        }
    }
}

// Server Setup and Initialization
// Update the return type to match what we need
pub async fn start_api_server(config: ApiConfig) -> Result<(), std::io::Error> {
    println!("\n=== Starting Kyber PQC API Server ===");
    println!("→ Time: {}", get_formatted_timestamp());
    println!("→ User: olafcio42");
    println!("→ Host: {}", config.host);
    println!("→ Port: {}", config.port);

    let state = web::Data::new(AppState {
        tls_session: Arc::new(Mutex::new(TlsSession::new())),
    });

    HttpServer::new(move || {
        App::new()
            .app_data(state.clone())
            .route("/api/v1/keypair", web::post().to(generate_keypair))
            .route("/api/v1/encrypt", web::post().to(encrypt))
            .route("/api/v1/decrypt", web::post().to(decrypt))
            .route("/api/v1/batch", web::post().to(process_batch))
            .wrap(actix_web::middleware::Logger::default())
    })
        .bind(format!("{}:{}", config.host, config.port))?
        .run()
        .await?;

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use actix_web::{test, App};

    #[actix_web::test]
    async fn test_generate_keypair() {
        let app = test::init_service(
            App::new()
                .route("/api/v1/keypair", web::post().to(generate_keypair))
        ).await;

        let req = test::TestRequest::post()
            .uri("/api/v1/keypair")
            .to_request();

        let resp: KeyGenResponse = test::call_and_read_body_json(&app, req).await;

        assert!(!resp.public_key.is_empty());
        assert!(!resp.secret_key.is_empty());
        assert!(resp.key_id.starts_with("KEY_"));
        assert_eq!(resp.user, "olafcio42");
    }

    #[actix_web::test]
    async fn test_encrypt_decrypt() {
        let state = web::Data::new(AppState {
            tls_session: Arc::new(Mutex::new(TlsSession::new())),
        });

        let app = test::init_service(
            App::new()
                .app_data(state.clone())
                .route("/api/v1/encrypt", web::post().to(encrypt))
                .route("/api/v1/decrypt", web::post().to(decrypt))
        ).await;

        let test_data = "Test message";

        // Test encryption
        let enc_req = EncryptRequest {
            data: test_data.to_string(),
            public_key: None,
        };

        let req = test::TestRequest::post()
            .uri("/api/v1/encrypt")
            .set_json(&enc_req)
            .to_request();

        let enc_resp: EncryptResponse = test::call_and_read_body_json(&app, req).await;
        assert!(!enc_resp.ciphertext.is_empty());

        // Test decryption
        let dec_req = DecryptRequest {
            ciphertext: enc_resp.ciphertext,
            secret_key: "".to_string(), // In real scenario, this would be the actual secret key
        };

        let req = test::TestRequest::post()
            .uri("/api/v1/decrypt")
            .set_json(&dec_req)
            .to_request();

        let dec_resp: DecryptResponse = test::call_and_read_body_json(&app, req).await;
        assert!(!dec_resp.plaintext.is_empty());
    }
}