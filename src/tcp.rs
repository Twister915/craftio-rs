use crate::connection::CraftConnection;
use crate::reader::CraftReader;
use crate::writer::CraftWriter;
use mcproto_rs::protocol::{PacketDirection, State};
use std::io::BufReader as StdBufReader;
use std::net::TcpStream;

#[cfg(feature = "async")]
use futures::io::{AsyncRead, AsyncWrite, BufReader as AsyncBufReader};

pub const BUF_SIZE: usize = 8192;

pub type CraftTcpConnection = CraftConnection<StdBufReader<TcpStream>, TcpStream>;

impl CraftConnection<StdBufReader<TcpStream>, TcpStream> {
    pub fn connect_server_std(to: String) -> Result<Self, std::io::Error> {
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

#[cfg(feature = "async")]
impl<R, W> CraftConnection<AsyncBufReader<R>, W>
where
    R: AsyncRead + Send + Sync + Unpin,
    W: AsyncWrite + Send + Sync + Unpin,
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
        let reader = AsyncBufReader::with_capacity(BUF_SIZE, reader);
        Self {
            reader: CraftReader::wrap_with_state(reader, read_direction, state),
            writer: CraftWriter::wrap_with_state(writer, read_direction.opposite(), state),
        }
    }
}
