use crate::cfb8::{setup_craft_cipher, CipherError, CraftCipher};
use crate::util::{get_sized_buf, move_data_rightwards, VAR_INT_BUF_SIZE};
use crate::wrapper::{CraftIo, CraftWrapper};
use flate2::{CompressError, Compression, FlushCompress, Status};
use mcproto_rs::protocol::{Id, Packet, PacketDirection, RawPacket, State};
use mcproto_rs::types::VarInt;
use mcproto_rs::{Serialize, SerializeErr, SerializeResult, Serializer};
use thiserror::Error;

#[cfg(feature = "async")]
use {async_trait::async_trait, futures::AsyncWriteExt};

#[derive(Debug, Error)]
pub enum WriteError {
    #[error("serialization of header data failed")]
    HeaderSerializeFail(SerializeErr),
    #[error("packet body serialization failed")]
    BodySerializeFail(SerializeErr),
    #[error("failed to compress packet")]
    CompressFail(CompressError),
    #[error("compression gave buf error")]
    CompressBufError,
    #[error("io error while writing data")]
    IoFail(#[from] std::io::Error),
    #[error("bad direction")]
    BadDirection {
        attempted: PacketDirection,
        expected: PacketDirection,
    },
    #[error("bad state")]
    BadState { attempted: State, expected: State },
}

pub type WriteResult<P> = Result<P, WriteError>;

#[cfg(feature = "async")]
#[async_trait]
pub trait CraftAsyncWriter {
    async fn write_packet<P>(&mut self, packet: P) -> WriteResult<()>
    where
        P: Packet + Send + Sync;

    async fn write_raw_packet<'a, P>(&mut self, packet: P) -> WriteResult<()>
    where
        P: RawPacket<'a> + Send + Sync;
}

pub trait CraftSyncWriter {
    fn write_packet<P>(&mut self, packet: P) -> WriteResult<()>
    where
        P: Packet;

    fn write_raw_packet<'a, P>(&mut self, packet: P) -> WriteResult<()>
    where
        P: RawPacket<'a>;
}

pub struct CraftWriter<W> {
    inner: W,

    raw_buf: Option<Vec<u8>>,
    compress_buf: Option<Vec<u8>>,
    compression_threshold: Option<i32>,
    state: State,
    direction: PacketDirection,
    encryption: Option<CraftCipher>,
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

    fn set_compression_threshold(&mut self, threshold: Option<i32>) {
        self.compression_threshold = threshold;
    }

    fn enable_encryption(&mut self, key: &[u8], iv: &[u8]) -> Result<(), CipherError> {
        setup_craft_cipher(&mut self.encryption, key, iv)
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

#[cfg(feature = "async")]
#[async_trait]
impl<W> CraftAsyncWriter for CraftWriter<W>
where
    W: futures::AsyncWrite + Unpin + Send + Sync,
{
    async fn write_packet<P>(&mut self, packet: P) -> WriteResult<()>
    where
        P: Packet + Send + Sync,
    {
        let prepared = self.serialize_packet_to_buf(packet)?;
        write_data_to_target_async(self.prepare_packet_in_buf(prepared)?).await?;
        Ok(())
    }

    async fn write_raw_packet<'a, P>(&mut self, packet: P) -> WriteResult<()>
    where
        P: RawPacket<'a> + Send + Sync,
    {
        let prepared = self.serialize_raw_packet_to_buf(packet)?;
        write_data_to_target_async(self.prepare_packet_in_buf(prepared)?).await?;
        Ok(())
    }
}

#[cfg(feature = "async")]
async fn write_data_to_target_async<'a, W>(
    tuple: (&'a [u8], &'a mut W),
) -> Result<(), std::io::Error>
where
    W: futures::AsyncWrite + Unpin + Send + Sync,
{
    let (data, target) = tuple;
    target.write_all(data).await
}

const HEADER_OFFSET: usize = VAR_INT_BUF_SIZE * 2;

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
            compression_threshold: None,
            compress_buf: None,
            state,
            direction,
            encryption: None,
        }
    }

    fn prepare_packet_in_buf(
        &mut self,
        prepared: PreparedPacketHandle,
    ) -> WriteResult<(&[u8], &mut W)> {
        // assume id and body are in raw buf from HEADER_OFFSET .. size + HEADER_OFFSET
        let body_size = prepared.id_size + prepared.data_size;
        let buf = get_sized_buf(&mut self.raw_buf, 0, body_size);

        let packet_data = if let Some(threshold) = self.compression_threshold {
            if threshold >= 0 && (threshold as usize) <= body_size {
                let compressed_size = compress(buf, &mut self.compress_buf, HEADER_OFFSET)?.len();
                let compress_buf =
                    get_sized_buf(&mut self.compress_buf, 0, compressed_size + HEADER_OFFSET);

                let data_len_target = &mut compress_buf[VAR_INT_BUF_SIZE..HEADER_OFFSET];
                let mut data_len_serializer = SliceSerializer::create(data_len_target);
                VarInt(body_size as i32)
                    .mc_serialize(&mut data_len_serializer)
                    .map_err(move |err| WriteError::HeaderSerializeFail(err))?;
                let data_len_bytes = data_len_serializer.finish().len();

                let packet_len_target = &mut compress_buf[..VAR_INT_BUF_SIZE];
                let mut packet_len_serializer = SliceSerializer::create(packet_len_target);
                VarInt((compressed_size + data_len_bytes) as i32)
                    .mc_serialize(&mut packet_len_serializer)
                    .map_err(move |err| WriteError::HeaderSerializeFail(err))?;
                let packet_len_bytes = packet_len_serializer.finish().len();

                let n_shift_packet_len = VAR_INT_BUF_SIZE - packet_len_bytes;
                move_data_rightwards(
                    &mut compress_buf[..HEADER_OFFSET],
                    packet_len_bytes,
                    n_shift_packet_len,
                );
                let n_shift_data_len = VAR_INT_BUF_SIZE - data_len_bytes;
                move_data_rightwards(
                    &mut compress_buf[n_shift_packet_len..HEADER_OFFSET],
                    packet_len_bytes + data_len_bytes,
                    n_shift_data_len,
                );
                let start_offset = n_shift_data_len + n_shift_packet_len;
                let end_at = start_offset + data_len_bytes + packet_len_bytes + compressed_size;
                &mut compress_buf[start_offset..end_at]
            } else {
                let packet_len_start_at = VAR_INT_BUF_SIZE - 1;
                let packet_len_target = &mut buf[packet_len_start_at..HEADER_OFFSET - 1];
                let mut packet_len_serializer = SliceSerializer::create(packet_len_target);
                VarInt((body_size + 1) as i32)
                    .mc_serialize(&mut packet_len_serializer)
                    .map_err(move |err| WriteError::HeaderSerializeFail(err))?;

                let packet_len_bytes = packet_len_serializer.finish().len();
                let n_shift_packet_len = VAR_INT_BUF_SIZE - packet_len_bytes;
                move_data_rightwards(
                    &mut buf[packet_len_start_at..HEADER_OFFSET - 1],
                    packet_len_bytes,
                    n_shift_packet_len,
                );

                let start_offset = packet_len_start_at + n_shift_packet_len;
                let end_at = start_offset + packet_len_bytes + 1 + body_size;
                &mut buf[start_offset..end_at]
            }
        } else {
            let packet_len_target = &mut buf[VAR_INT_BUF_SIZE..HEADER_OFFSET];
            let mut packet_len_serializer = SliceSerializer::create(packet_len_target);
            VarInt(body_size as i32)
                .mc_serialize(&mut packet_len_serializer)
                .map_err(move |err| WriteError::HeaderSerializeFail(err))?;
            let packet_len_bytes = packet_len_serializer.finish().len();
            let n_shift_packet_len = VAR_INT_BUF_SIZE - packet_len_bytes;
            move_data_rightwards(
                &mut buf[VAR_INT_BUF_SIZE..HEADER_OFFSET],
                packet_len_bytes,
                n_shift_packet_len,
            );
            let start_offset = VAR_INT_BUF_SIZE + n_shift_packet_len;
            let end_at = start_offset + packet_len_bytes + body_size;
            &mut buf[start_offset..end_at]
        };

        if let Some(encryption) = &mut self.encryption {
            encryption.encrypt(packet_data);
        }

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
                .map_err(move |err| WriteError::BodySerializeFail(err))
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
        let buf = get_sized_buf(&mut self.raw_buf, HEADER_OFFSET, id_size + data_size);

        (&mut buf[id_size..]).copy_from_slice(packet_data);

        Ok(PreparedPacketHandle { id_size, data_size })
    }

    fn serialize_id_to_buf(&mut self, id: Id) -> WriteResult<usize> {
        if id.direction != self.direction {
            return Err(WriteError::BadDirection {
                expected: self.direction,
                attempted: id.direction,
            });
        }

        if id.state != self.state {
            return Err(WriteError::BadState {
                expected: self.state,
                attempted: id.state,
            });
        }

        self.serialize_to_buf(HEADER_OFFSET, move |serializer| {
            id.mc_serialize(serializer)
                .map_err(move |err| WriteError::HeaderSerializeFail(err))
        })
    }

    fn serialize_to_buf<'a, F>(&'a mut self, offset: usize, f: F) -> WriteResult<usize>
    where
        F: FnOnce(&mut GrowVecSerializer<'a>) -> Result<(), WriteError>,
    {
        let mut serializer = GrowVecSerializer::create(&mut self.raw_buf, offset);
        f(&mut serializer)?;
        Ok(serializer.finish().map(move |b| b.len()).unwrap_or(0))
    }
}

#[derive(Debug)]
struct GrowVecSerializer<'a> {
    target: &'a mut Option<Vec<u8>>,
    at: usize,
    offset: usize,
}

impl<'a> Serializer for GrowVecSerializer<'a> {
    fn serialize_bytes(&mut self, data: &[u8]) -> SerializeResult {
        get_sized_buf(self.target, self.at + self.offset, data.len()).copy_from_slice(data);
        Ok(())
    }
}

impl<'a> GrowVecSerializer<'a> {
    fn create(target: &'a mut Option<Vec<u8>>, offset: usize) -> Self {
        Self {
            target,
            at: 0,
            offset,
        }
    }

    fn finish(self) -> Option<&'a mut [u8]> {
        if let Some(buf) = self.target {
            Some(&mut buf[self.offset..self.offset + self.at])
        } else {
            None
        }
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

        match compressor
            .compress(input, output, flush)
            .map_err(move |err| WriteError::CompressFail(err))?
        {
            Status::Ok => {}
            Status::BufError => return Err(WriteError::CompressBufError),
            Status::StreamEnd => break,
        }
    }

    Ok(&mut target[..(compressor.total_out() as usize)])
}
