#[cfg(feature = "encryption")]
use crate::cfb8::CipherError;
use mcproto_rs::protocol::State;

///
/// Indicates that a type provided by this crate is wrapping some inner value of type `I`, which can
/// be unwrapped by calling the `into_inner` function.
///
pub trait CraftWrapper<I> {
    ///
    /// Unwraps the wrapped value of type `I`, and drops the wrapper type
    ///
    fn into_inner(self) -> I;
}

///
/// Trait for stateful connection types, such as the `CraftReader<R>` or `CraftWriter<W>` or combo
/// type `CraftConnection<R, W>`.
///
/// Allows for control over protocol state, compression threshold, and encryption if those features
/// are enabled.
///
pub trait CraftIo {
    ///
    /// Changes the current connection state. For readers, this changes how numeric packet IDs are
    /// interpreted. For writers, this will change the packets that can be written without a panic.
    ///
    fn set_state(&mut self, next: State);


    #[cfg(feature = "compression")]
    ///
    /// Modifies the compression configuration. If a value of `None` is provided, then compression is
    /// disabled. If a value of `Some` is provided, then the threshold is set to that value.
    ///
    /// If a 0 or negative value is provided in a `Some` variant, then it is the same as calling
    /// this function with the `None` variant
    ///
    fn set_compression_threshold(&mut self, threshold: Option<i32>);

    #[cfg(feature = "encryption")]
    ///
    /// Modifies the encryption configuration. This function should only be called once, and can only
    /// be used to enable encryption.
    ///
    /// If encryption is already enabled or the arguments are not valid for the cipher, then an
    /// error is returned and nothing in the underlying state is changed.
    ///
    fn enable_encryption(&mut self, key: &[u8], iv: &[u8]) -> Result<(), CipherError>;

    ///
    /// Sets the max packet size which this I/O wrapper will decode or transmit.
    ///
    /// This limit is meant to be used to ensure connections never allocate gigantic buffers.
    /// Therefore, the limitation applies to the representation of packet in memory. This means
    /// that a reader cannot read a compressed packet above this threshold, nor can it decompress
    /// to a packet which is above this threshold. A writer cannot write a packet which exceeds
    /// this size (when serialized) even if compression is enabled.
    ///
    /// todo split the compressed vs not compressed limits?
    ///
    fn set_max_packet_size(&mut self, max_size: usize);
}
