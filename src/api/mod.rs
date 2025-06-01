use crate::adds::tls::TlsSession;  // Poprawny import
use anyhow::Result;

pub async fn handle_handshake(tls_session: &mut TlsSession) -> Result<()> {
    match tls_session.begin_handshake().await {
        Ok(_) => {
            println!("Handshake completed successfully");
            Ok(())
        }
        Err(e) => {
            println!("Handshake failed: {}", e);
            Err(e)
        }
    }
}