use crate::cfb8::CipherError;
use crate::reader::{CraftAsyncReader, CraftReader, CraftSyncReader, ReadResult};
use crate::wrapper::{CraftIo, CraftWrapper};
use crate::writer::{CraftAsyncWriter, CraftSyncWriter, CraftWriter, WriteResult};
use mcproto_rs::protocol::{Packet, RawPacket, State};

#[cfg(feature = "async")]
use async_trait::async_trait;

pub struct CraftConnection<R, W> {
    pub(crate) reader: CraftReader<R>,
    pub(crate) writer: CraftWriter<W>,
}

impl<R, W> CraftWrapper<(CraftReader<R>, CraftWriter<W>)> for CraftConnection<R, W> {
    fn into_inner(self) -> (CraftReader<R>, CraftWriter<W>) {
        (self.reader, self.writer)
    }
}

impl<R, W> CraftIo for CraftConnection<R, W> {
    fn set_state(&mut self, next: State) {
        self.reader.set_state(next);
        self.writer.set_state(next);
    }

    fn set_compression_threshold(&mut self, threshold: Option<i32>) {
        self.reader.set_compression_threshold(threshold);
        self.writer.set_compression_threshold(threshold);
    }

    fn enable_encryption(&mut self, key: &[u8], iv: &[u8]) -> Result<(), CipherError> {
        self.reader.enable_encryption(key, iv)?;
        self.writer.enable_encryption(key, iv)?;
        Ok(())
    }
}

impl<R, W> CraftSyncReader for CraftConnection<R, W>
where
    CraftReader<R>: CraftSyncReader,
    CraftWriter<W>: CraftSyncWriter,
{
    fn read_packet<'a, P>(&'a mut self) -> ReadResult<<P as RawPacket<'a>>::Packet>
    where
        P: RawPacket<'a>,
    {
        self.reader.read_packet::<P>()
    }

    fn read_raw_packet<'a, P>(&'a mut self) -> ReadResult<P>
    where
        P: RawPacket<'a>,
    {
        self.reader.read_raw_packet::<P>()
    }
}

impl<R, W> CraftSyncWriter for CraftConnection<R, W>
where
    CraftReader<R>: CraftSyncReader,
    CraftWriter<W>: CraftSyncWriter,
{
    fn write_packet<P>(&mut self, packet: P) -> WriteResult<()>
    where
        P: Packet,
    {
        self.writer.write_packet(packet)
    }

    fn write_raw_packet<'a, P>(&mut self, packet: P) -> WriteResult<()>
    where
        P: RawPacket<'a>,
    {
        self.writer.write_raw_packet(packet)
    }
}

#[cfg(feature = "async")]
#[async_trait]
impl<R, W> CraftAsyncReader for CraftConnection<R, W>
where
    CraftReader<R>: CraftAsyncReader,
    R: Send + Sync,
    CraftWriter<W>: CraftAsyncWriter,
    W: Send + Sync,
{
    async fn read_packet<'a, P>(&'a mut self) -> ReadResult<<P as RawPacket<'a>>::Packet>
    where
        P: RawPacket<'a>,
    {
        self.reader.read_packet::<P>().await
    }

    async fn read_raw_packet<'a, P>(&'a mut self) -> ReadResult<P>
    where
        P: RawPacket<'a>,
    {
        self.reader.read_raw_packet::<P>().await
    }
}

#[cfg(feature = "async")]
#[async_trait]
impl<R, W> CraftAsyncWriter for CraftConnection<R, W>
where
    CraftReader<R>: CraftAsyncReader,
    R: Send + Sync,
    CraftWriter<W>: CraftAsyncWriter,
    W: Send + Sync,
{
    async fn write_packet<P>(&mut self, packet: P) -> WriteResult<()>
    where
        P: Packet + Send + Sync,
    {
        self.writer.write_packet(packet).await
    }

    async fn write_raw_packet<'a, P>(&mut self, packet: P) -> WriteResult<()>
    where
        P: RawPacket<'a> + Send + Sync,
    {
        self.writer.write_raw_packet(packet).await
    }
}
