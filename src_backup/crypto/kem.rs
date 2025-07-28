// Key Encapsulation Mechanism
pub struct KyberKEM<P: KyberParameters> {
    core: KyberCore<P>,
}