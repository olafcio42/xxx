use crate::utils::{entropy, validation};
use anyhow::Result;

pub struct KeyGenerator {
    security_level: SecurityLevel,
    entropy_source: Box<dyn EntropySource>,
}

impl KeyGenerator {
    pub fn new(security_level: SecurityLevel) -> Self {
        Self {
            security_level,
            entropy_source: Box::new(SystemEntropySource::new()),
        }
    }

    pub fn generate_keypair(&self) -> Result<KeyPair> {
        let entropy = self.entropy_source.get_entropy()?;
        validation::validate_key_material(&entropy, self.security_level.min_entropy())?;

        match self.security_level {
            SecurityLevel::Kyber768 => kem768::KeyPair::generate(&entropy),
            SecurityLevel::Kyber1024 => kem1024::KeyPair::generate(&entropy),
        }
    }
}