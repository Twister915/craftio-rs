use crate::connection::CraftConnection;
use crate::reader::CraftReader;
use crate::writer::CraftWriter;
use mcproto_rs::protocol::{PacketDirection, State};
use std::io::BufReader as StdBufReader;
use std::net::TcpStream;

#[cfg(any(feature = "futures-io", feature = "tokio-io"))]
use crate::{CraftAsyncReader, CraftAsyncWriter};

#[cfg(feature = "tokio-io")]
use tokio::{
    net::{
        TcpStream as TokioTcpStream,
        tcp::{
            OwnedReadHalf as TokioReadHalf,
            OwnedWriteHalf as TokioWriteHalf,
        },
        ToSocketAddrs as TokioToSocketAddrs,
    },
    io::{
        BufReader as TokioBufReader,
        Error as TokioIoError,
    },
};

pub const BUF_SIZE: usize = 8192;

pub type CraftTcpConnection = CraftConnection<StdBufReader<TcpStream>, TcpStream>;

impl CraftTcpConnection {
    pub fn connect_server_std<A>(to: A) -> Result<Self, std::io::Error> where A: std::net::ToSocketAddrs {
        Self::from_std(TcpStream::connect(to)?, PacketDirection::ClientBound)
    }

    pub fn wrap_client_stream_std(stream: TcpStream) -> Result<Self, std::io::Error> {
        Self::from_std(stream, PacketDirection::ServerBound)
    }

    pub fn from_std(
        s1: TcpStream,
        read_direction: PacketDirection,
    ) -> Result<Self, std::io::Error> {
        Self::from_std_with_state(s1, read_direction, State::Handshaking)
    }

    pub fn from_std_with_state(
        s1: TcpStream,
        read_direction: PacketDirection,
        state: State,
    ) -> Result<Self, std::io::Error> {
        let write = s1.try_clone()?;
        let read = StdBufReader::with_capacity(BUF_SIZE, s1);

        Ok(Self {
            reader: CraftReader::wrap_with_state(read, read_direction, state),
            writer: CraftWriter::wrap_with_state(write, read_direction.opposite(), state),
        })
    }
}

#[cfg(feature = "tokio-io")]
pub type CraftTokioConnection = CraftConnection<TokioBufReader<TokioReadHalf>, TokioWriteHalf>;

#[cfg(feature = "tokio-io")]
impl CraftTokioConnection {
    pub async fn connect_server_tokio<A>(
        to: A
    ) -> Result<Self, TokioIoError>
    where
        A: TokioToSocketAddrs
    {
        let conn = TokioTcpStream::connect(to).await?;
        conn.set_nodelay(true)?;
        let (reader, writer) = conn.into_split();
        let reader = TokioBufReader::with_capacity(BUF_SIZE, reader);
        Ok(Self::from_async((reader, writer), PacketDirection::ClientBound))
    }
}

#[cfg(feature = "tokio-io")]
pub type CraftUnbufferedTokioConnection = CraftConnection<TokioReadHalf, TokioWriteHalf>;

#[cfg(feature = "tokio-io")]
impl CraftUnbufferedTokioConnection {
    pub async fn connect_server_tokio_unbuffered<A>(
        to: A
    ) -> Result<Self, TokioIoError>
    where
        A: TokioToSocketAddrs
    {
        let conn = TokioTcpStream::connect(to).await?;
        conn.set_nodelay(true)?;

        Ok(Self::from_async(
            conn.into_split(),
            PacketDirection::ClientBound,
        ))
    }
}

#[cfg(any(feature = "futures-io", feature = "tokio-io"))]
impl<R, W> CraftConnection<R, W>
where
    CraftReader<R>: CraftAsyncReader,
    CraftWriter<W>: CraftAsyncWriter,
{
    pub fn from_async(tuple: (R, W), read_direction: PacketDirection) -> Self {
        Self::from_async_with_state(tuple, read_direction, State::Handshaking)
    }

    pub fn from_async_with_state(
        tuple: (R, W),
        read_direction: PacketDirection,
        state: State,
    ) -> Self {
        let (reader, writer) = tuple;
        Self {
            reader: CraftReader::wrap_with_state(reader, read_direction, state),
            writer: CraftWriter::wrap_with_state(writer, read_direction.opposite(), state),
        }
    }
}
