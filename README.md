# craftio-rs

Version 0.1.0, by [Twister915](https://github.com/Twister915)!

craftio-rs is a library which let's you read & write packets defined in [mcproto-rs](https://github.com/Twister915/mcproto-rs) 
to real Minecraft servers/clients.

You can use this library to implement anything from a simple server status ping client, BungeeCord-like proxy, a bot 
to join your favorite server, or an entire Minecraft server or client implementation.

The protocol definition is managed in a separate crate, mentioned above, called [mcproto-rs](https://github.com/Twister915/mcproto-rs)
which defines a set of traits to support custom protocol implementations, and also defines all packets for a few of the 
versions of Minecraft.

This crate optionally implements the following features:
* `compression` (using the [flate2](https://crates.io/crates/flate2) crate)
* `encryption` (using the [aes](https://crates.io/crates/aes) crate) with a fast implementation of CFB-8
* `futures-io` enables reading/writing to implementors of the `AsyncRead`/`AsyncWrite` traits from the 
  [futures](https://crates.io/crates/futures) crate
* `tokio-io` enables reading/writing to implementors of the `AsyncRead`/`AsyncWrite` traits from the 
  [tokio](https://crates.io/crates/tokio) crate

# Usage

```toml
[dependencies]
craftio-rs = "0.1"
```

This library can be used to connect to servers or host client connections. It implements all features of the Minecraft
protocol, and these features can be disabled for simpler use-cases (such as hitting servers to gather status information).

You can also use an async based I/O implementation, or a blocking I/O implementation.

## Connecting to a Server

To connect to a Minecraft server, you can write something like this:

```rust
let mut conn = CraftTokioConnection::connect_server_tokio("localhost:25565").await?;
conn.write_packet_async(Packet578::Handshake(HandshakeSpec { ... })).await?;
conn.set_state(State::Login);
...
```

This `CraftTokioConnection` struct is actually a type alias for the more general `CraftConnection<R, W>` type which wraps
any `R` (reader) and `W` (writer) type supported by `CraftReader` and `CraftWriter`. More detail on these types below.

You can also connect using a blocking socket from `std::net` like this:

```rust
let mut conn = CraftTcpConnection::connect_server_std("localhost:25565")?;
conn.write_packet(Packet578::Handshake(HandshakeSpec { ... }))?;
conn.set_state(State::Login);
...
```

## Serving Clients

You can use `CraftConnection::from_std_with_state(your_client, PacketDirection::ServerBound, State::Handshaking)` to wrap
a blocking `TcpStream`, and you can use `CraftConnection::from_async_with_state((client_read_half, client_write_half), PacketDirection::ServerBound, State::Handshaking)`
to wrap an async `TcpStream`. In the async case you must split your connection into reader/writer halves before passing it to the 
`CraftConnection`.

In all cases it is recommended to first wrap the reader in a buffering reader implementation of your choice. This is because
this crate typically reads the packet length (first 5 bytes) as one call, then the entire packet body as another call. If
you choose to not use a buffering implementation, these two calls could have an undesirable overhead, because both may actually
require an operating system call.

# Types

There are two structs which implement the behavior of this crate: `CraftReader<R>` and `CraftWriter<W>`.

They are defined to implement the `CraftAsyncReader`/`CraftSyncReader` and `CraftAsyncWriter`/`CraftSyncWriter` traits
when wrapping `R`/`W` types which implement the `craftio_rs::AsyncReadExact`/`std::io::Read` and 
`craftio_rs::AsyncWriteExact`/`std::io::Write` traits respectively.

This crate provides implementations of `craftio_rs::AsyncReadExact` and `craftio_rs::AsyncWriteExact` for implementors of
the `tokio::io::AsyncRead`/`tokio::io::AsyncWrite` and `futures::AsyncRead`/`futures::AsyncWrite` traits when you enable 
the `tokio-io` and `futures-io` features respectively.

## Performance

A `CraftReader<R>` and `CraftWriter<W>` hold some buffers, both of which are lazily allocated `Vec<u8>`s:
* `raw_buf` which is a buffer for packet bytes
* `compress_buf`/`decompress_buf`. When compression is enabled (both as a crate-feature called `compression` and after 
  a call to `.set_compression_threshold` with a `Some(> 0)` value) this buffer is used to store a compressed packet 
  (in the case of a writer) or the decompressed packet (in the case of a reader).

These buffers can be eagerly allocated using calls to `.ensure_buf_capacity(usize)` and `.ensure_compression_buf_capacity(usize)`, 
but they cannot yet be provided by the user.

### Motivation

This library was designed when I was working on these three projects: a replacement for BungeeCord, a bot client that can
join servers for me, and a tool to ping a list of servers quickly and print their status. This crate tries to avoid dynamic
allocation, but does have some buffers to make serialization/deserialization fast. These allocations are done lazily by
default, but can be done eagerly (described below) if desired.

When implementing something like a game server, or a proxy like BungeeCord, you are dealing with tens to hundreds of joins
per second in the maximum case, so the dynamic allocation is not going to dramatically impact performance. Therefore,
lazily allocation and growing of the buffers aren't going to impact your flame-graph.

However, in the case of trying to ping servers, I really wanted to ensure we only allocate once per connection half. To
that end, you can eagerly allocate a large-enough buffer and also limit the max packet size to prevent it from growing
any further (call `.set_max_packet_size` and `.ensure_buf_capacity`).

A great feature would be allowing the user to provide a `&mut Vec<u8>` which can be used by the wrapper types until the
connection is closed. This way, in a many-worker model (like a ping tool), you can simply allocate a buffer for each worker,
which you re-use for each subsequent connection. This does not exist yet.

## Adapting to different I/O implementations

To add your favorite I/O library, you can either implement the std I/O traits (`std::io::Read` and `std::io::Write`) or 
for an async implementation you can implement the traits provided by this crate (`AsyncReadExact` and `AsyncWriteExact`).

# Todo

* Allow user to provide buffers which they already allocated for `raw_buf`
* See if we can stop managing the `Vec<u8>` ourselves and just use `BufReader` traits that already exist?
* Extract the offset tracking from `CraftReader` struct.