//! Różne warianty Kyber (512, 768, 1024)

#[cfg(feature = "kyber512")]
pub mod kyber512;

#[cfg(feature = "kyber768")]
pub mod kyber768;

#[cfg(feature = "kyber1024")]
pub mod kyber1024;
mod kyber512;
mod kyber768;
mod kyber1024;
