#[cfg(feature = "encryption")]
use crate::cfb8::{setup_craft_cipher, CipherError, CraftCipher};
use crate::util::{get_sized_buf, move_data_rightwards, VAR_INT_BUF_SIZE};
use crate::wrapper::{CraftIo, CraftWrapper};
use crate::DEAFULT_MAX_PACKET_SIZE;
#[cfg(feature = "compression")]
use flate2::{CompressError, Compression, FlushCompress, Status};
use mcproto_rs::protocol::{Id, Packet, PacketDirection, RawPacket, State};
use mcproto_rs::types::VarInt;
use mcproto_rs::{Serialize, SerializeErr, SerializeResult, Serializer};
#[cfg(feature = "backtrace")]
use std::backtrace::Backtrace;
use std::ops::{Deref, DerefMut};
use thiserror::Error;
#[cfg(any(feature = "futures-io", feature = "tokio-io"))]
use async_trait::async_trait;

#[derive(Debug, Error)]
pub enum WriteError {
    #[error("packet serialization error")]
    Serialize {
        #[from]
        err: PacketSerializeFail,
        #[cfg(feature = "backtrace")]
        backtrace: Backtrace,
    },
    #[error("failed to compress packet")]
    #[cfg(feature = "compression")]
    CompressFail {
        #[from]
        err: CompressError,
        #[cfg(feature = "backtrace")]
        backtrace: Backtrace,
    },
    #[error("compression gave buf error")]
    #[cfg(feature = "compression")]
    CompressBufError {
        #[cfg(feature = "backtrace")]
        backtrace: Backtrace,
    },
    #[error("io error while writing data")]
    IoFail {
        #[from]
        err: std::io::Error,
        #[cfg(feature = "backtrace")]
        backtrace: Backtrace,
    },
    #[error("bad direction")]
    BadDirection {
        attempted: PacketDirection,
        expected: PacketDirection,
        #[cfg(feature = "backtrace")]
        backtrace: Backtrace,
    },
    #[error("bad state")]
    BadState {
        attempted: State,
        expected: State,
        #[cfg(feature = "backtrace")]
        backtrace: Backtrace,
    },
    #[error("packet size {size} exceeds maximum size {max_size}")]
    PacketTooLarge {
        size: usize,
        max_size: usize,
        #[cfg(feature = "backtrace")]
        backtrace: Backtrace,
    }
}

#[derive(Debug, Error)]
pub enum PacketSerializeFail {
    #[error("failed to serialize packet header")]
    Header(#[source] SerializeErr),
    #[error("failed to serialize packet contents")]
    Body(#[source] SerializeErr),
}

impl Deref for PacketSerializeFail {
    type Target = SerializeErr;

    fn deref(&self) -> &Self::Target {
        use PacketSerializeFail::*;
        match self {
            Header(err) => err,
            Body(err) => err,
        }
    }
}

impl DerefMut for PacketSerializeFail {
    fn deref_mut(&mut self) -> &mut Self::Target {
        use PacketSerializeFail::*;
        match self {
            Header(err) => err,
            Body(err) => err,
        }
    }
}

impl Into<SerializeErr> for PacketSerializeFail {
    fn into(self) -> SerializeErr {
        use PacketSerializeFail::*;
        match self {
            Header(err) => err,
            Body(err) => err,
        }
    }
}

pub type WriteResult<P> = Result<P, WriteError>;

///
/// This trait is the interface by which you can write packets to some underlying `AsyncWrite` stream
///
/// If you construct a `CraftWriter` by wrapping an `AsyncWrite` then `CraftWriter` will implement
/// this trait.
///
#[cfg(any(feature = "futures-io", feature = "tokio-io"))]
#[async_trait]
pub trait CraftAsyncWriter {
    ///
    /// Attempts to serialize, and then write a packet struct to the wrapped stream.
    ///
    async fn write_packet_async<P>(&mut self, packet: P) -> WriteResult<()>
    where
        P: Packet + Send + Sync;

    ///
    /// Attempts to write a serialized packet to the wrapped stream.
    ///
    /// This function is most useful when forwarding packets from a reader. You can read raw
    /// packets from the reader, then match on the enum variant to conditionally deserialize only
    /// certain packet types to implement behavior, and leave other packets that are irrelevant to
    /// your application in their raw form.
    ///
    async fn write_raw_packet_async<'a, P>(&mut self, packet: P) -> WriteResult<()>
    where
        P: RawPacket<'a> + Send + Sync;
}

///
/// This trait is the interface by which you can write packets to some underlying implementor of
/// `std::io::Write`.
///
/// If you construct a `CraftWriter` by wrapping a `std::io::Write` implementor then `CraftWriter`
/// will implement this trait.
///
pub trait CraftSyncWriter {
    ///
    /// Attempts to serialize, and then write a packet struct to the wrapped stream.
    ///
    fn write_packet<P>(&mut self, packet: P) -> WriteResult<()>
    where
        P: Packet;

    ///
    /// Attempts to write a serialized packet to the wrapped stream
    ///
    /// This function is most useful when forwarding packets from a reader. You can read raw
    /// packets from the reader, then match on the enum variant to conditionally deserialize only
    /// certain packet types to implement behavior, and leave other packets that are irrelevant to
    /// your application in their raw form.
    ///
    fn write_raw_packet<'a, P>(&mut self, packet: P) -> WriteResult<()>
    where
        P: RawPacket<'a>;
}

///
/// Wraps some stream of type `W`, and implements either `CraftSyncWriter` or `CraftAsyncWriter` (or both)
/// based on what types `W` implements.
///
/// You can construct this type calling the function `wrap_with_state`, which requires you to specify
/// a packet direction (are written packets server-bound or client-bound?) and a state
/// (`handshaking`? `login`? `status`? `play`?).
///
/// This type holds some internal buffers but only allocates them when they are required.
///
pub struct CraftWriter<W> {
    inner: W,
    raw_buf: Option<Vec<u8>>,
    #[cfg(feature = "compression")]
    compress_buf: Option<Vec<u8>>,
    #[cfg(feature = "compression")]
    compression_threshold: Option<i32>,
    state: State,
    direction: PacketDirection,
    #[cfg(feature = "encryption")]
    encryption: Option<CraftCipher>,
    max_packet_size: usize,
}

impl<W> CraftWrapper<W> for CraftWriter<W> {
    fn into_inner(self) -> W {
        self.inner
    }
}

impl<W> CraftIo for CraftWriter<W> {
    fn set_state(&mut self, next: State) {
        self.state = next;
    }

    #[cfg(feature = "compression")]
    fn set_compression_threshold(&mut self, threshold: Option<i32>) {
        self.compression_threshold = threshold;
    }

    #[cfg(feature = "encryption")]
    fn enable_encryption(&mut self, key: &[u8], iv: &[u8]) -> Result<(), CipherError> {
        setup_craft_cipher(&mut self.encryption, key, iv)
    }

    fn set_max_packet_size(&mut self, max_size: usize) {
        debug_assert!(max_size > 5);
        self.max_packet_size = max_size;
    }

    fn ensure_buf_capacity(&mut self, capacity: usize) {
        get_sized_buf(&mut self.raw_buf, 0, if capacity > self.max_packet_size {
            self.max_packet_size
        } else {
            capacity
        });
    }

    #[cfg(feature = "compression")]
    fn ensure_compression_buf_capacity(&mut self, capacity: usize) {
        get_sized_buf(&mut self.compress_buf, 0, if capacity > self.max_packet_size {
            self.max_packet_size
        } else {
            capacity
        });
    }
}

impl<W> CraftSyncWriter for CraftWriter<W>
where
    W: std::io::Write,
{
    fn write_packet<P>(&mut self, packet: P) -> WriteResult<()>
    where
        P: Packet,
    {
        let prepared = self.serialize_packet_to_buf(packet)?;
        write_data_to_target_sync(self.prepare_packet_in_buf(prepared)?)?;
        Ok(())
    }

    fn write_raw_packet<'a, P>(&mut self, packet: P) -> WriteResult<()>
    where
        P: RawPacket<'a>,
    {
        let prepared = self.serialize_raw_packet_to_buf(packet)?;
        write_data_to_target_sync(self.prepare_packet_in_buf(prepared)?)?;
        Ok(())
    }
}

fn write_data_to_target_sync<'a, W>(tuple: (&'a [u8], &'a mut W)) -> Result<(), std::io::Error>
where
    W: std::io::Write,
{
    let (data, target) = tuple;
    target.write_all(data)
}

#[cfg(any(feature = "tokio-io", feature = "futures-io"))]
#[async_trait]
pub trait AsyncWriteAll: Unpin + Send + Sync {
    async fn write_all(&mut self, data: &[u8]) -> Result<(), std::io::Error>;
}

#[cfg(all(feature = "futures-io", not(feature = "tokio-io")))]
#[async_trait]
impl<W> AsyncWriteAll for W
where
    W: futures::AsyncWrite + Unpin + Send + Sync,
{
    async fn write_all(&mut self, data: &[u8]) -> Result<(), std::io::Error> {
        futures::AsyncWriteExt::write_all(self, data).await?;
        Ok(())
    }
}

#[cfg(feature = "tokio-io")]
#[async_trait]
impl<W> AsyncWriteAll for W
where
    W: tokio::io::AsyncWrite + Unpin + Send + Sync,
{
    async fn write_all(&mut self, data: &[u8]) -> Result<(), std::io::Error> {
        tokio::io::AsyncWriteExt::write_all(self, data).await?;
        Ok(())
    }
}

#[cfg(any(feature = "futures-io", feature = "tokio-io"))]
#[async_trait]
impl<W> CraftAsyncWriter for CraftWriter<W>
where
    W: AsyncWriteAll,
{
    async fn write_packet_async<P>(&mut self, packet: P) -> WriteResult<()>
    where
        P: Packet + Send + Sync,
    {
        let prepared = self.serialize_packet_to_buf(packet)?;
        write_data_to_target_async(self.prepare_packet_in_buf(prepared)?).await?;
        Ok(())
    }

    async fn write_raw_packet_async<'a, P>(&mut self, packet: P) -> WriteResult<()>
    where
        P: RawPacket<'a> + Send + Sync,
    {
        let prepared = self.serialize_raw_packet_to_buf(packet)?;
        write_data_to_target_async(self.prepare_packet_in_buf(prepared)?).await?;
        Ok(())
    }
}

#[cfg(any(feature = "futures-io", feature = "tokio-io"))]
async fn write_data_to_target_async<'a, W>(
    tuple: (&'a [u8], &'a mut W),
) -> Result<(), std::io::Error>
where
    W: AsyncWriteAll,
{
    let (data, target) = tuple;
    target.write_all(data).await
}

// this HEADER_OFFSET is basically the number of free 0s at the front of the packet buffer when
// we setup serialization of a packet. The purpose of doing this is to serialize packet id + body
// first, then serialize the length in front of it. The length, which is a VarInt, can be up to 5
// bytes long.
//
// Therefore, the general algorithm for serializing a packet is:
//  * use a Vec<u8> as a buffer
//  * use GrowVecSerializer to serialize packet id + body into buffer starting at offset HEADER_OFFSET
//
//  If we are in compressed mode, then we must write two lengths:
//    * packet length (literal length, as in number of bytes that follows)
//    * data length (length of the id + body when uncompressed)
//
//  In a compressed mode, we only perform compression when the length >= threshold, and if it's below
//  the threshold we write these two VarInts at the front of the packet:
//    * packet length (literal # of bytes to follow)
//    * 0 - the data length
//
//  No matter what mode we are in, we first write packet id + packet body to a buffer called "buf"
//
//  If we are not in a compressed mode, then we simply put the packet length at the front of this
//  buf and return a pointer to the region which contains the length + id + data.
//
//  In compressed mode, we lazily allocate a second buffer called "compress_buf" which will only be
//  used if we actually compress a packet.
//
//  "buf" reserves enough space for a length varint and 1 extra byte for a 0 data length
//
//  If we are in compressed mode, but not actually performing compression, we use the packet data
//  already in buf, and simply put the length of the packet (+ 1) into the region starting at 0
//
//  If we are in compressed mode, and we perform compression on the packet, we will compress data
//  in buf from HEADER_OFFSET..packet_id_and_body_len into compress_buf region at COMPRESS_HEADER_OFFSET..
//  We can then put the packet length and data length in the region 0..COMPRESS_HEADER_OFFSET
//
// Once the packet is prepared in a buffer, if encryption is enabled we simply encrypt that entire
// block of data, and then we write that region of data to the target pipe
//
#[cfg(feature = "compression")]
const HEADER_OFFSET: usize = VAR_INT_BUF_SIZE + 1;

#[cfg(not(feature = "compression"))]
const HEADER_OFFSET: usize = VAR_INT_BUF_SIZE;

#[cfg(feature = "compression")]
const COMPRESSED_HEADER_OFFSET: usize = VAR_INT_BUF_SIZE * 2;

struct PreparedPacketHandle {
    id_size: usize,
    data_size: usize,
}

impl<W> CraftWriter<W> {
    pub fn wrap(inner: W, direction: PacketDirection) -> Self {
        Self::wrap_with_state(inner, direction, State::Handshaking)
    }

    pub fn wrap_with_state(inner: W, direction: PacketDirection, state: State) -> Self {
        Self {
            inner,
            raw_buf: None,
            #[cfg(feature = "compression")]
            compression_threshold: None,
            #[cfg(feature = "compression")]
            compress_buf: None,
            state,
            direction,
            #[cfg(feature = "encryption")]
            encryption: None,
            max_packet_size: DEAFULT_MAX_PACKET_SIZE,
        }
    }

    fn prepare_packet_in_buf(
        &mut self,
        prepared: PreparedPacketHandle,
    ) -> WriteResult<(&[u8], &mut W)> {
        // assume id and body are in raw buf from HEADER_OFFSET .. size + HEADER_OFFSET
        let body_size = prepared.id_size + prepared.data_size;
        let buf = get_sized_buf(&mut self.raw_buf, 0, HEADER_OFFSET + body_size);

        #[cfg(feature = "compression")]
        let packet_data = if let Some(threshold) = self.compression_threshold {
            if threshold >= 0 && (threshold as usize) <= body_size {
                let body_data = &buf[HEADER_OFFSET..];
                prepare_packet_compressed(body_data, &mut self.compress_buf)?
            } else {
                prepare_packet_compressed_below_threshold(buf, body_size)?
            }
        } else {
            prepare_packet_normally(buf, body_size)?
        };

        #[cfg(not(feature = "compression"))]
        let packet_data = prepare_packet_normally(buf, body_size)?;

        #[cfg(feature = "encryption")]
        handle_encryption(self.encryption.as_mut(), packet_data);

        Ok((packet_data, &mut self.inner))
    }

    fn serialize_packet_to_buf<P>(&mut self, packet: P) -> WriteResult<PreparedPacketHandle>
    where
        P: Packet,
    {
        let id_size = self.serialize_id_to_buf(packet.id())?;
        let data_size = self.serialize_to_buf(HEADER_OFFSET + id_size, move |serializer| {
            packet
                .mc_serialize_body(serializer)
                .map_err(move |err| PacketSerializeFail::Body(err).into())
        })?;

        Ok(PreparedPacketHandle { id_size, data_size })
    }

    fn serialize_raw_packet_to_buf<'a, P>(&mut self, packet: P) -> WriteResult<PreparedPacketHandle>
    where
        P: RawPacket<'a>,
    {
        let id_size = self.serialize_id_to_buf(packet.id())?;
        let packet_data = packet.data();
        let data_size = packet_data.len();
        if data_size > self.max_packet_size {
            return Err(WriteError::PacketTooLarge {
                size: data_size,
                max_size: self.max_packet_size,
                #[cfg(feature = "backtrace")]
                backtrace: Backtrace::capture()
            })
        }
        let buf = get_sized_buf(&mut self.raw_buf, HEADER_OFFSET, id_size + data_size);

        (&mut buf[id_size..]).copy_from_slice(packet_data);

        Ok(PreparedPacketHandle { id_size, data_size })
    }

    fn serialize_id_to_buf(&mut self, id: Id) -> WriteResult<usize> {
        if id.direction != self.direction {
            return Err(WriteError::BadDirection {
                expected: self.direction,
                attempted: id.direction,
                #[cfg(feature = "backtrace")]
                backtrace: Backtrace::capture(),
            });
        }

        if id.state != self.state {
            return Err(WriteError::BadState {
                expected: self.state,
                attempted: id.state,
                #[cfg(feature = "backtrace")]
                backtrace: Backtrace::capture(),
            });
        }

        self.serialize_to_buf(HEADER_OFFSET, move |serializer| {
            id.mc_serialize(serializer)
                .map_err(move |err| PacketSerializeFail::Header(err).into())
        })
    }

    fn serialize_to_buf<'a, F>(&'a mut self, offset: usize, f: F) -> WriteResult<usize>
    where
        F: FnOnce(&mut GrowVecSerializer<'a>) -> Result<(), WriteError>,
    {
        let mut serializer = GrowVecSerializer::create(&mut self.raw_buf, offset, self.max_packet_size);
        f(&mut serializer)?;
        let packet_size = serializer.written_data_len();
        if serializer.exceeded_max_size {
            Err(WriteError::PacketTooLarge {
                size: packet_size,
                max_size: self.max_packet_size,
                #[cfg(feature = "backtrace")]
                backtrace: Backtrace::capture(),
            })
        } else {
            Ok(packet_size)
        }
    }
}

fn prepare_packet_normally(buf: &mut [u8], body_size: usize) -> WriteResult<&mut [u8]> {
    #[cfg(feature = "compression")]
    const BUF_SKIP_BYTES: usize = 1;

    #[cfg(not(feature = "compression"))]
    const BUF_SKIP_BYTES: usize = 0;

    let packet_len_target = &mut buf[BUF_SKIP_BYTES..HEADER_OFFSET];
    let mut packet_len_serializer = SliceSerializer::create(packet_len_target);
    VarInt(body_size as i32)
        .mc_serialize(&mut packet_len_serializer)
        .map_err(move |err| PacketSerializeFail::Header(err))?;
    let packet_len_bytes = packet_len_serializer.finish().len();

    let n_shift_packet_len = VAR_INT_BUF_SIZE - packet_len_bytes;
    move_data_rightwards(
        &mut buf[BUF_SKIP_BYTES..HEADER_OFFSET],
        packet_len_bytes,
        n_shift_packet_len,
    );

    let start_offset = n_shift_packet_len + BUF_SKIP_BYTES;
    let end_at = start_offset + packet_len_bytes + body_size;
    Ok(&mut buf[start_offset..end_at])
}

#[cfg(feature = "compression")]
fn prepare_packet_compressed<'a>(
    buf: &'a [u8],
    compress_buf: &'a mut Option<Vec<u8>>,
) -> WriteResult<&'a mut [u8]> {
    let compressed_size = compress(buf, compress_buf, COMPRESSED_HEADER_OFFSET)?.len();
    let compress_buf = get_sized_buf(compress_buf, 0, compressed_size + COMPRESSED_HEADER_OFFSET);

    let data_len_target = &mut compress_buf[VAR_INT_BUF_SIZE..COMPRESSED_HEADER_OFFSET];
    let mut data_len_serializer = SliceSerializer::create(data_len_target);
    VarInt(buf.len() as i32)
        .mc_serialize(&mut data_len_serializer)
        .map_err(move |err| PacketSerializeFail::Header(err))?;
    let data_len_bytes = data_len_serializer.finish().len();

    let packet_len_target = &mut compress_buf[..VAR_INT_BUF_SIZE];
    let mut packet_len_serializer = SliceSerializer::create(packet_len_target);
    VarInt((compressed_size + data_len_bytes) as i32)
        .mc_serialize(&mut packet_len_serializer)
        .map_err(move |err| PacketSerializeFail::Header(err))?;
    let packet_len_bytes = packet_len_serializer.finish().len();

    let n_shift_packet_len = VAR_INT_BUF_SIZE - packet_len_bytes;
    move_data_rightwards(
        &mut compress_buf[..COMPRESSED_HEADER_OFFSET],
        packet_len_bytes,
        n_shift_packet_len,
    );
    let n_shift_data_len = VAR_INT_BUF_SIZE - data_len_bytes;
    move_data_rightwards(
        &mut compress_buf[n_shift_packet_len..COMPRESSED_HEADER_OFFSET],
        packet_len_bytes + data_len_bytes,
        n_shift_data_len,
    );
    let start_offset = n_shift_data_len + n_shift_packet_len;
    let end_at = start_offset + data_len_bytes + packet_len_bytes + compressed_size;

    Ok(&mut compress_buf[start_offset..end_at])
}

#[cfg(feature = "compression")]
fn prepare_packet_compressed_below_threshold(
    buf: &mut [u8],
    body_size: usize,
) -> WriteResult<&mut [u8]> {
    let packet_len_target = &mut buf[..HEADER_OFFSET - 1];
    let mut packet_len_serializer = SliceSerializer::create(packet_len_target);
    VarInt((body_size + 1) as i32) // +1 because of data length
        .mc_serialize(&mut packet_len_serializer)
        .map_err(move |err| PacketSerializeFail::Header(err))?;

    let packet_len_bytes = packet_len_serializer.finish().len();
    let n_shift_packet_len = VAR_INT_BUF_SIZE - packet_len_bytes;
    move_data_rightwards(
        &mut buf[..HEADER_OFFSET - 1],
        packet_len_bytes,
        n_shift_packet_len,
    );

    let end_at = n_shift_packet_len + packet_len_bytes + 1 + body_size;
    buf[HEADER_OFFSET - 1] = 0; // data_len = 0
    Ok(&mut buf[n_shift_packet_len..end_at])
}

#[cfg(feature = "encryption")]
fn handle_encryption(encryption: Option<&mut CraftCipher>, buf: &mut [u8]) {
    if let Some(encryption) = encryption {
        encryption.encrypt(buf);
    }
}

#[derive(Debug)]
struct GrowVecSerializer<'a> {
    target: &'a mut Option<Vec<u8>>,
    at: usize,
    offset: usize,
    max_size: usize,
    exceeded_max_size: bool,
}

impl<'a> Serializer for GrowVecSerializer<'a> {
    fn serialize_bytes(&mut self, data: &[u8]) -> SerializeResult {
        if !self.exceeded_max_size {
            let cur_len = self.written_data_len();
            let new_len = cur_len + data.len();
            if new_len > self.max_size {
                self.exceeded_max_size = true;
            } else {
                get_sized_buf(self.target, self.at + self.offset, data.len()).copy_from_slice(data);
            }
        }

        self.at += data.len();

        Ok(())
    }
}

impl<'a> GrowVecSerializer<'a> {
    fn create(target: &'a mut Option<Vec<u8>>, offset: usize, max_size: usize) -> Self {
        Self {
            target,
            at: 0,
            offset,
            max_size,
            exceeded_max_size: false,
        }
    }

    fn written_data_len(&self) -> usize {
        self.at
    }
}

struct SliceSerializer<'a> {
    target: &'a mut [u8],
    at: usize,
}

impl<'a> Serializer for SliceSerializer<'a> {
    fn serialize_bytes(&mut self, data: &[u8]) -> SerializeResult {
        let end_at = self.at + data.len();
        if end_at >= self.target.len() {
            panic!(
                "cannot fit data in slice ({} exceeds length {} at {})",
                data.len(),
                self.target.len(),
                self.at
            );
        }

        (&mut self.target[self.at..end_at]).copy_from_slice(data);
        self.at = end_at;
        Ok(())
    }
}

impl<'a> SliceSerializer<'a> {
    fn create(target: &'a mut [u8]) -> Self {
        Self { target, at: 0 }
    }

    fn finish(self) -> &'a [u8] {
        &self.target[..self.at]
    }
}

#[cfg(feature = "compression")]
fn compress<'a, 'b>(
    src: &'b [u8],
    output: &'a mut Option<Vec<u8>>,
    offset: usize,
) -> Result<&'a mut [u8], WriteError> {
    let target = get_sized_buf(output, offset, src.len());
    let mut compressor = flate2::Compress::new_with_window_bits(Compression::fast(), true, 15);
    loop {
        let input = &src[(compressor.total_in() as usize)..];
        let eof = input.is_empty();
        let output = &mut target[(compressor.total_out() as usize)..];
        let flush = if eof {
            FlushCompress::Finish
        } else {
            FlushCompress::None
        };

        match compressor.compress(input, output, flush)? {
            Status::Ok => {}
            Status::BufError => {
                return Err(WriteError::CompressBufError {
                    #[cfg(feature = "backtrace")]
                    backtrace: Backtrace::capture(),
                })
            }
            Status::StreamEnd => break,
        }
    }

    Ok(&mut target[..(compressor.total_out() as usize)])
}
