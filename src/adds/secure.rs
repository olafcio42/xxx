use pqcrypto_traits::kem::SharedSecret as SharedSecretTrait;
use secrecy::{Secret, ExposeSecret};

//SecureSecret wrapper for handling sensitive cryptographic material
//Provides safe storage and controlled access to secret data
pub struct SecureSecret(Secret<Vec<u8>>);

impl SecureSecret {
    //Creates a new SecureSecret from any type implementing SharedSecretTrait
    //Safely wraps the secret bytes in a protected memory location
    pub fn from_shared<T: SharedSecretTrait>(ss: T) -> Self {
        Self(Secret::new(ss.as_bytes().to_vec()))
    }

    //Exposes the underlying secret bytes
    //Warning: This method should be used with caution and only when necessary
    pub fn expose(&self) -> &[u8] {
        self.0.expose_secret()
    }
}