use pqcrypto_traits::kem::SharedSecret as SharedSecretTrait;
use secrecy::{Secret, ExposeSecret};

pub struct SecureSecret(Secret<Vec<u8>>);

impl SecureSecret {
    pub fn from_shared<T: SharedSecretTrait>(ss: T) -> Self {
        Self(Secret::new(ss.as_bytes().to_vec()))
    }

    pub fn expose(&self) -> &[u8] {
        self.0.expose_secret()
    }
}