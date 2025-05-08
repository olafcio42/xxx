use anyhow::{Result, bail};
use pqcrypto_kyber::kyber1024::{PublicKey, SecretKey, encapsulate, decapsulate};
use pqcrypto_traits::kem::SharedSecret;

//Validates compatibility between public and secret Kyber keys
pub fn validate_keys(pk: &PublicKey, sk: &SecretKey) -> Result<()> {
    //Perform test encapsulation
    let (ss1, ct) = encapsulate(pk);
    let ss2 = decapsulate(&ct, sk);

    //Verify that shared secrets match
    if ss1.as_bytes() != ss2.as_bytes() {
        bail!("Keys are not compatible - shared secrets mismatch")
    }

    Ok(())
}