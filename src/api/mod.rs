// W funkcji gdzie występuje begin_handshake
async fn handle_handshake(tls_session: &mut TlsSession) -> Result<(), anyhow::Error> {
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