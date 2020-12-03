use crate::cfb8::{setup_craft_cipher, CipherError, CraftCipher};
use crate::util::{get_sized_buf, VAR_INT_BUF_SIZE};
use crate::wrapper::{CraftIo, CraftWrapper};
use flate2::{DecompressError, FlushDecompress, Status};
use mcproto_rs::protocol::{Id, PacketDirection, RawPacket, State};
use mcproto_rs::types::VarInt;
use mcproto_rs::{Deserialize, Deserialized};
use thiserror::Error;

#[cfg(feature = "async")]
use {async_trait::async_trait, futures::AsyncReadExt};

#[derive(Debug, Error)]
pub enum ReadError {
    #[error("i/o failure during read")]
    IoFailure(#[from] std::io::Error),
    #[error("failed to read header VarInt")]
    PacketHeaderErr(#[from] mcproto_rs::DeserializeErr),
    #[error("failed to read packet")]
    PacketErr(#[from] mcproto_rs::protocol::PacketErr),
    #[error("failed to decompress packet")]
    DecompressFailed(#[from] DecompressErr),
}

#[derive(Debug, Error)]
pub enum DecompressErr {
    #[error("buf error")]
    BufError,
    #[error("failure while decompressing")]
    Failure(#[from] DecompressError),
}

pub type ReadResult<P> = Result<Option<P>, ReadError>;

#[cfg(feature = "async")]
#[async_trait]
pub trait CraftAsyncReader {
    async fn read_packet<'a, P>(&'a mut self) -> ReadResult<<P as RawPacket<'a>>::Packet>
    where
        P: RawPacket<'a>,
    {
        deserialize_raw_packet(self.read_raw_packet::<P>().await)
    }

    async fn read_raw_packet<'a, P>(&'a mut self) -> ReadResult<P>
    where
        P: RawPacket<'a>;
}

pub trait CraftSyncReader {
    fn read_packet<'a, P>(&'a mut self) -> ReadResult<<P as RawPacket<'a>>::Packet>
    where
        P: RawPacket<'a>,
    {
        deserialize_raw_packet(self.read_raw_packet::<'a, P>())
    }

    fn read_raw_packet<'a, P>(&'a mut self) -> ReadResult<P>
    where
        P: RawPacket<'a>;
}

pub struct CraftReader<R> {
    inner: R,
    raw_buf: Option<Vec<u8>>,
    decompress_buf: Option<Vec<u8>>,
    compression_threshold: Option<i32>,
    state: State,
    direction: PacketDirection,
    encryption: Option<CraftCipher>,
}

impl<R> CraftWrapper<R> for CraftReader<R> {
    fn into_inner(self) -> R {
        self.inner
    }
}

impl<R> CraftIo for CraftReader<R> {
    fn set_state(&mut self, next: State) {
        self.state = next;
    }

    fn set_compression_threshold(&mut self, threshold: Option<i32>) {
        self.compression_threshold = threshold;
    }

    fn enable_encryption(&mut self, key: &[u8], iv: &[u8]) -> Result<(), CipherError> {
        setup_craft_cipher(&mut self.encryption, key, iv)
    }
}

macro_rules! rr_unwrap {
    ($result: expr) => {
        match $result {
            Ok(Some(r)) => r,
            Ok(None) => return Ok(None),
            Err(err) => return Err(err),
        }
    };
}

macro_rules! check_unexpected_eof {
    ($result: expr) => {
        if let Err(err) = $result {
            if err.kind() == std::io::ErrorKind::UnexpectedEof {
                return Ok(None);
            }

            return Err(ReadError::IoFailure(err));
        }
    };
}

impl<R> CraftSyncReader for CraftReader<R>
where
    R: std::io::Read,
{
    fn read_raw_packet<'a, P>(&'a mut self) -> ReadResult<P>
    where
        P: RawPacket<'a>,
    {
        let (primary_packet_len, len_bytes) = rr_unwrap!(self.read_one_varint_sync());
        let primary_packet_len = primary_packet_len.0 as usize;
        rr_unwrap!(self.read_n(VAR_INT_BUF_SIZE, primary_packet_len - VAR_INT_BUF_SIZE + len_bytes));
        self.read_packet_in_buf::<'a, P>(len_bytes, primary_packet_len)
    }
}

#[cfg(feature = "async")]
#[async_trait]
impl<R> CraftAsyncReader for CraftReader<R>
where
    R: futures::AsyncRead + Unpin + Sync + Send,
{
    async fn read_raw_packet<'a, P>(&'a mut self) -> Result<Option<P>, ReadError>
    where
        P: RawPacket<'a>,
    {
        let (primary_packet_len, len_bytes) = rr_unwrap!(self.read_one_varint_async().await);
        let primary_packet_len = primary_packet_len.0 as usize;
        rr_unwrap!(self.read_n_async(VAR_INT_BUF_SIZE, primary_packet_len - VAR_INT_BUF_SIZE + len_bytes).await);
        self.read_packet_in_buf::<P>(len_bytes, primary_packet_len)
    }
}

impl<R> CraftReader<R>
where
    R: std::io::Read,
{
    fn read_one_varint_sync(&mut self) -> ReadResult<(VarInt, usize)> {
        deserialize_varint(rr_unwrap!(self.read_n(0, VAR_INT_BUF_SIZE)))
    }

    fn read_n(&mut self, offset: usize, n: usize) -> ReadResult<&mut [u8]> {
        let buf = get_sized_buf(&mut self.raw_buf, offset, n);
        check_unexpected_eof!(self.inner.read_exact(buf));
        Ok(Some(buf))
    }
}

#[cfg(feature = "async")]
impl<R> CraftReader<R>
where
    R: futures::io::AsyncRead + Unpin + Sync + Send,
{
    async fn read_one_varint_async(&mut self) -> ReadResult<(VarInt, usize)> {
        deserialize_varint(rr_unwrap!(self.read_n_async(0, VAR_INT_BUF_SIZE).await))
    }

    async fn read_n_async(&mut self, offset: usize, n: usize) -> ReadResult<&mut [u8]> {
        let buf = get_sized_buf(&mut self.raw_buf, offset, n);
        check_unexpected_eof!(self.inner.read_exact(buf).await);
        Ok(Some(buf))
    }
}

macro_rules! dsz_unwrap {
    ($bnam: expr, $k: ty) => {
        match <$k>::mc_deserialize($bnam) {
            Ok(Deserialized {
                value: val,
                data: rest,
            }) => (val, rest),
            Err(err) => {
                return Err(ReadError::PacketHeaderErr(err));
            }
        };
    };
}

impl<R> CraftReader<R> {
    pub fn wrap(inner: R, direction: PacketDirection) -> Self {
        Self::wrap_with_state(inner, direction, State::Handshaking)
    }

    pub fn wrap_with_state(inner: R, direction: PacketDirection, state: State) -> Self {
        Self {
            inner,
            raw_buf: None,
            decompress_buf: None,
            compression_threshold: None,
            state,
            direction,
            encryption: None,
        }
    }

    fn read_packet_in_buf<'a, P>(&'a mut self, offset: usize, size: usize) -> ReadResult<P>
    where
        P: RawPacket<'a>,
    {
        // find data in buf
        let buf = &mut self.raw_buf.as_mut().expect("should exist right now")[offset..offset+size];
        // decrypt the packet if encryption is enabled
        if let Some(encryption) = self.encryption.as_mut() {
            encryption.decrypt(buf);
        }

        // try to get the packet body bytes... this boils down to:
        // * check if compression enabled,
        //    * read data len (VarInt) which isn't compressed
        //    * if data len is 0, then rest of packet is not compressed, remaining data is body
        //    * otherwise, data len is decompressed length, so prepare a decompression buf and decompress from
        //      the buffer into the decompression buffer, and return the slice of the decompression buffer
        //      which contains this packet's data
        // * if compression not enabled, then the buf contains only the packet body bytes

        let packet_buf = if let Some(_) = self.compression_threshold {
            let (data_len, rest) = dsz_unwrap!(buf, VarInt);
            let data_len = data_len.0 as usize;
            if data_len == 0 {
                rest
            } else {
                decompress(rest, &mut self.decompress_buf, data_len)?
            }
        } else {
            buf
        };

        let (raw_id, body_buf) = dsz_unwrap!(packet_buf, VarInt);

        let id = Id {
            id: raw_id.0,
            state: self.state.clone(),
            direction: self.direction.clone(),
        };

        match P::create(id, body_buf) {
            Ok(raw) => Ok(Some(raw)),
            Err(err) => Err(ReadError::PacketErr(err)),
        }
    }
}

fn deserialize_raw_packet<'a, P>(raw: ReadResult<P>) -> ReadResult<P::Packet>
where
    P: RawPacket<'a>,
{
    match raw {
        Ok(Some(raw)) => match raw.deserialize() {
            Ok(deserialized) => Ok(Some(deserialized)),
            Err(err) => Err(ReadError::PacketErr(err)),
        },
        Ok(None) => Ok(None),
        Err(err) => Err(err),
    }
}

fn deserialize_varint(buf: &[u8]) -> ReadResult<(VarInt, usize)> {
    match VarInt::mc_deserialize(buf) {
        Ok(v) => Ok(Some((v.value, buf.len() - v.data.len()))),
        Err(err) => Err(ReadError::PacketHeaderErr(err)),
    }
}

fn decompress<'a>(
    src: &'a [u8],
    target: &'a mut Option<Vec<u8>>,
    decompressed_len: usize,
) -> Result<&'a mut [u8], ReadError> {
    let mut decompress = flate2::Decompress::new(true);
    let decompress_buf = get_sized_buf(target, 0, decompressed_len);
    loop {
        match decompress.decompress(src, decompress_buf, FlushDecompress::Finish) {
            Ok(Status::StreamEnd) => break,
            Ok(Status::Ok) => {}
            Ok(Status::BufError) => {
                return Err(ReadError::DecompressFailed(DecompressErr::BufError))
            }
            Err(err) => return Err(ReadError::DecompressFailed(DecompressErr::Failure(err))),
        }
    }

    Ok(&mut decompress_buf[..(decompress.total_out() as usize)])
}
