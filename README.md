# litep2p

[![License](https://img.shields.io/badge/License-MIT-blue.svg)](LICENSE) [![Crates.io](https://img.shields.io/crates/v/litep2p.svg)](https://crates.io/crates/litep2p) [![docs.rs](https://img.shields.io/docsrs/litep2p.svg)](https://docs.rs/litep2p/latest/litep2p/)

`litep2p` is a [`libp2p`](https://libp2p.io/)-compatible *peer-to-peer (P2P)* networking library

## Features

* Supported protocols:
  * `/ipfs/ping/1.0.0`
  * `/ipfs/identify/1.0.0`
  * `/ipfs/kad/1.0.0`
  * `/ipfs/bitswap/1.2.0`
  * Multicast DNS
  * Notification protocol
  * Request-response protocol
  * API for creating custom protocols 
* Supported transports:
  * TCP
  * QUIC
  * WebRTC
  * WebSocket (WS + WSS)

## Usage

`litep2p` has taken a different approach with API design and as such is not a drop-in replacement for [`rust-libp2p`](https://github.com/libp2p/rust-libp2p/). Below is a sample usage of the library:

```rust
use futures::StreamExt;
use litep2p::{
    config::Litep2pConfigBuilder,
    protocol::{libp2p::ping, request_response::ConfigBuilder},
    transport::{
        quic::config::TransportConfig as QuicTransportConfig,
        tcp::config::TransportConfig as TcpTransportConfig,
    },
    types::protocol::ProtocolName,
    Litep2p,
};

// simple example which enables `/ipfs/ping/1.0.0` and `/request/1` protocols
// and TCP and QUIC transports and starts polling events
#[tokio::main]
async fn main() {
    // enable IPFS PING protocol
    let (ping_config, mut ping_event_stream) = ping::Config::default();

    // enable `/request/1` request-response protocol
    let (req_resp_config, mut req_resp_handle) =
        ConfigBuilder::new(ProtocolName::from("/request/1"))
            .with_max_size(1024)
            .build();

    // build `Litep2pConfig` object
    let config = Litep2pConfigBuilder::new()
        .with_tcp(TcpTransportConfig {
            listen_address: "/ip6/::1/tcp/0".parse().unwrap(),
            yamux_config: yamux::Config::default(),
        })
        .with_quic(QuicTransportConfig {
            listen_address: "/ip4/127.0.0.1/udp/0/quic-v1".parse().unwrap(),
        })
        .with_libp2p_ping(ping_config)
        .with_request_response_protocol(req_resp_config)
        .build();

    // build `Litep2p` object
    let mut litep2p = Litep2p::new(config).await.unwrap();

    loop {
        tokio::select! {
            _event = litep2p.next_event() => {},
            _event = req_resp_handle.next() => {},
            _event = ping_event_stream.next() => {},
        }
    }
}
```

See[`examples`](https://github.com/altonen/litep2p/tree/master/examples) for more details on how to use the library

## Copying

MIT license