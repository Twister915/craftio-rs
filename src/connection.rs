#[cfg(feature = "encryption")]
use crate::cfb8::CipherError;
use crate::reader::{CraftReader, CraftSyncReader, ReadResult};
use crate::wrapper::{CraftIo, CraftWrapper};
use crate::writer::{CraftSyncWriter, CraftWriter, WriteResult};
use mcproto_rs::protocol::{Packet, RawPacket, State, Id};
#[cfg(feature = "gat")]
use mcproto_rs::protocol::PacketKind;
#[cfg(any(feature = "futures-io", feature = "tokio-io"))]
use {
    crate::{reader::CraftAsyncReader, writer::CraftAsyncWriter},
    async_trait::async_trait,
};

pub struct CraftConnection<R, W> {
    pub(crate) reader: CraftReader<R>,
    pub(crate) writer: CraftWriter<W>,
}

impl<R, W> CraftWrapper<(R, W)> for CraftConnection<R, W> {
    fn into_inner(self) -> (R, W) {
        (self.reader.into_inner(), self.writer.into_inner())
    }
}

impl<R, W> CraftIo for CraftConnection<R, W> {
    fn set_state(&mut self, next: State) {
        self.reader.set_state(next);
        self.writer.set_state(next);
    }

    #[cfg(feature = "compression")]
    fn set_compression_threshold(&mut self, threshold: Option<i32>) {
        self.reader.set_compression_threshold(threshold);
        self.writer.set_compression_threshold(threshold);
    }

    #[cfg(feature = "encryption")]
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
    #[cfg(not(feature = "gat"))]
    fn read_packet<'a, P>(&'a mut self) -> ReadResult<<P as RawPacket<'a>>::Packet>
    where
        P: RawPacket<'a>,
    {
        self.reader.read_packet::<P>()
    }

    #[cfg(feature = "gat")]
    fn read_packet<P>(&mut self) -> ReadResult<<P::RawPacket<'_> as RawPacket>::Packet>
    where
        P: PacketKind
    {
        self.reader.read_packet::<P>()
    }

    #[cfg(not(feature = "gat"))]
    fn read_raw_packet<'a, P>(&'a mut self) -> ReadResult<P>
    where
        P: RawPacket<'a>,
    {
        self.reader.read_raw_packet::<P>()
    }

    #[cfg(feature = "gat")]
    fn read_raw_packet<P>(&mut self) -> ReadResult<P::RawPacket<'_>>
    where
        P: PacketKind
    {
        self.reader.read_raw_packet::<P>()
    }

    fn read_raw_untyped_packet(&mut self) -> ReadResult<(Id, &[u8])> {
        self.reader.read_raw_untyped_packet()
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

#[cfg(any(feature = "futures-io", feature = "tokio-io"))]
#[async_trait]
impl<R, W> CraftAsyncReader for CraftConnection<R, W>
where
    CraftReader<R>: CraftAsyncReader,
    R: Send + Sync,
    CraftWriter<W>: CraftAsyncWriter,
    W: Send + Sync,
{
    #[cfg(not(feature = "gat"))]
    async fn read_packet_async<'a, P>(&'a mut self) -> ReadResult<<P as RawPacket<'a>>::Packet>
    where
        P: RawPacket<'a>,
    {
        self.reader.read_packet_async::<P>().await
    }

    #[cfg(feature = "gat")]
    async fn read_packet_async<P>(&mut self) -> ReadResult<<P::RawPacket<'_> as RawPacket<'_>>::Packet>
    where
        P: PacketKind
    {
        self.reader.read_packet_async::<P>().await
    }

    #[cfg(not(feature = "gat"))]
    async fn read_raw_packet_async<'a, P>(&'a mut self) -> ReadResult<P>
    where
        P: RawPacket<'a>,
    {
        self.reader.read_raw_packet_async::<P>().await
    }

    #[cfg(feature = "gat")]
    async fn read_raw_packet_async<P>(&mut self) -> ReadResult<P::RawPacket<'_>>
    where
        P: PacketKind
    {
        self.reader.read_raw_packet_async::<P>().await
    }

    async fn read_raw_untyped_packet_async(&mut self) -> ReadResult<(Id, &[u8])> {
        self.reader.read_raw_untyped_packet_async().await
    }
}

#[cfg(any(feature = "futures-io", feature = "tokio-io"))]
#[async_trait]
impl<R, W> CraftAsyncWriter for CraftConnection<R, W>
where
    CraftReader<R>: CraftAsyncReader,
    R: Send + Sync,
    CraftWriter<W>: CraftAsyncWriter,
    W: Send + Sync,
{
    async fn write_packet_async<P>(&mut self, packet: P) -> WriteResult<()>
    where
        P: Packet + Send + Sync,
    {
        self.writer.write_packet_async(packet).await
    }

    async fn write_raw_packet_async<'a, P>(&mut self, packet: P) -> WriteResult<()>
    where
        P: RawPacket<'a> + Send + Sync,
    {
        self.writer.write_raw_packet_async(packet).await
    }
}

impl<R, W> CraftConnection<R, W> {
    pub fn into_split(self) -> (CraftReader<R>, CraftWriter<W>) {
        (self.reader, self.writer)
    }

    pub fn split(&mut self) -> (&mut CraftReader<R>, &mut CraftWriter<W>) {
        (&mut self.reader, &mut self.writer)
    }
}