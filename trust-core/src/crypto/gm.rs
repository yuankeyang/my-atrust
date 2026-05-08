//! 国密 cryptographic primitives

pub trait SM2 {}
pub trait SM3 {}
pub trait SM4 {}

pub struct GmCrypto;

impl GmCrypto {
    pub fn new() -> Self {
        Self
    }
}
