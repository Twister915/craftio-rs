use crate::cfb8::CipherError;
use mcproto_rs::protocol::State;

pub trait CraftWrapper<I> {
    fn into_inner(self) -> I;
}

pub trait CraftIo {
    fn set_state(&mut self, next: State);
    fn set_compression_threshold(&mut self, threshold: Option<i32>);
    fn enable_encryption(&mut self, key: &[u8], iv: &[u8]) -> Result<(), CipherError>;
}
