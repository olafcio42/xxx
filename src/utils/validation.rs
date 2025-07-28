use crate::utils::entropy;
use anyhow::Result;

pub fn validate_key_material(data: &[u8], min_entropy: f64) -> Result<()> {
    let entropy_score = entropy::calculate(data);
    if entropy_score < min_entropy {
        return Err(anyhow!("Insufficient entropy in key material"));
    }
    Ok(())
}