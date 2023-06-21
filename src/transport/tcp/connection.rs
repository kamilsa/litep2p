// Copyright 2023 litep2p developers
//
// Permission is hereby granted, free of charge, to any person obtaining a
// copy of this software and associated documentation files (the "Software"),
// to deal in the Software without restriction, including without limitation
// the rights to use, copy, modify, merge, publish, distribute, sublicense,
// and/or sell copies of the Software, and to permit persons to whom the
// Software is furnished to do so, subject to the following conditions:
//
// The above copyright notice and this permission notice shall be included in
// all copies or substantial portions of the Software.
//
// THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS
// OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
// FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
// AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
// LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING
// FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER
// DEALINGS IN THE SOFTWARE.

use crate::{
    config::Role,
    crypto::noise::{self, Encrypted, NoiseConfiguration},
    error::{Error, SubstreamError},
    multistream_select::{dialer_select_proto, listener_select_proto, Negotiated, Version},
    peer_id::PeerId,
    protocol::{ProtocolEvent, ProtocolSet},
    transport::tcp::{socket_addr_to_multi_addr, LOG_TARGET},
    types::protocol::ProtocolName,
    TransportContext,
};

use futures::{
    future::BoxFuture,
    stream::{FuturesUnordered, StreamExt},
    AsyncRead, AsyncWrite,
};
use multiaddr::Multiaddr;
use tokio::net::TcpStream;
use tokio_util::compat::{
    Compat, FuturesAsyncReadCompatExt, TokioAsyncReadCompatExt, TokioAsyncWriteCompatExt,
};

use std::{fmt, io, net::SocketAddr, pin::Pin};

// TODO: introduce `NegotiatingConnection` to clean up this code a bit?

/// TCP connection.
pub struct TcpConnection {
    /// Connection ID.
    _connection_id: usize,

    /// Protocol context.
    context: ProtocolSet,

    /// Yamux connection.
    connection: yamux::ControlledConnection<Encrypted<Compat<TcpStream>>>,

    /// Yamux control.
    control: yamux::Control,

    /// Remote peer ID.
    peer: PeerId,

    /// Next substream ID.
    next_substream_id: usize,

    /// Remote address.
    address: Multiaddr,

    /// Pending substreams.
    pending_substreams: FuturesUnordered<BoxFuture<'static, crate::Result<Substream>>>,
}

impl fmt::Debug for TcpConnection {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("TcpConnection")
            .field("peer", &self.peer)
            .field("next_substream_id", &self.next_substream_id)
            .finish()
    }
}

impl TcpConnection {
    /// Open connection to remote peer at `address`.
    pub async fn open_connection(
        context: TransportContext,
        connection_id: usize,
        address: SocketAddr,
        peer: Option<PeerId>,
    ) -> crate::Result<Self> {
        tracing::debug!(
            target: LOG_TARGET,
            ?address,
            ?peer,
            "open connection to remote peer",
        );

        let noise_config = NoiseConfiguration::new(&context.keypair, Role::Dialer);
        let stream = TcpStream::connect(address).await?;
        Self::negotiate_connection(stream, connection_id, context, noise_config, address).await
    }

    /// Open substream for `protocol`.
    pub async fn open_substream(
        mut control: yamux::Control,
        substream: usize,
        protocol: ProtocolName,
    ) -> crate::Result<Substream> {
        tracing::debug!(target: LOG_TARGET, ?substream, ?protocol, "open substream");

        let stream = match control.open_stream().await {
            Ok(stream) => {
                tracing::trace!(target: LOG_TARGET, ?substream, "substream opened");
                stream
            }
            Err(error) => {
                tracing::debug!(
                    target: LOG_TARGET,
                    ?substream,
                    ?error,
                    "failed to open substream"
                );
                return Err(Error::YamuxError(substream, error));
            }
        };

        let (io, protocol) =
            Self::negotiate_protocol(stream, &Role::Dialer, vec![&protocol]).await?;

        Ok(Substream {
            io: io.inner(),
            _substream: substream,
            protocol,
        })
    }

    /// Accept a new connection.
    pub async fn accept_connection(
        context: TransportContext,
        stream: TcpStream,
        connection_id: usize,
        address: SocketAddr,
    ) -> crate::Result<Self> {
        tracing::debug!(target: LOG_TARGET, ?address, "accept connection");

        let noise_config = NoiseConfiguration::new(&context.keypair, Role::Listener);
        Self::negotiate_connection(stream, connection_id, context, noise_config, address).await
    }

    /// Accept substream.
    pub async fn accept_substream(
        stream: yamux::Stream,
        substream: usize,
        protocols: Vec<ProtocolName>,
    ) -> crate::Result<Substream> {
        tracing::trace!(target: LOG_TARGET, ?substream, "accept inbound substream");

        let protocols = protocols
            .iter()
            .map(|protocol| &**protocol)
            .collect::<Vec<&str>>();
        let (io, protocol) = Self::negotiate_protocol(stream, &Role::Listener, protocols).await?;

        tracing::trace!(
            target: LOG_TARGET,
            ?substream,
            "substream accepted and negotiated"
        );

        Ok(Substream {
            io: io.inner(),
            _substream: substream,
            protocol,
        })
    }

    /// Negotiate protocol.
    async fn negotiate_protocol<S: AsyncRead + AsyncWrite + Unpin>(
        stream: S,
        role: &Role,
        protocols: Vec<&str>,
    ) -> crate::Result<(Negotiated<S>, ProtocolName)> {
        tracing::trace!(target: LOG_TARGET, ?protocols, "negotiating protocols");

        let (protocol, socket) = match role {
            Role::Dialer => dialer_select_proto(stream, protocols, Version::V1).await?,
            Role::Listener => listener_select_proto(stream, protocols).await?,
        };

        tracing::trace!(target: LOG_TARGET, ?protocol, "protocol negotiated");

        Ok((socket, ProtocolName::from(protocol.to_string())))
    }

    /// Negotiate noise + yamux for the connection.
    async fn negotiate_connection(
        stream: TcpStream,
        connection_id: usize,
        context: TransportContext,
        noise_config: NoiseConfiguration,
        address: SocketAddr,
    ) -> crate::Result<Self> {
        tracing::trace!(
            target: LOG_TARGET,
            role = ?noise_config.role,
            "negotiate connection",
        );

        let stream = TokioAsyncReadCompatExt::compat(stream).into_inner();
        let stream = TokioAsyncWriteCompatExt::compat_write(stream);
        let role = noise_config.role;

        // negotiate `noise`
        let (stream, _) =
            Self::negotiate_protocol(stream, &noise_config.role, vec!["/noise"]).await?;

        tracing::trace!(
            target: LOG_TARGET,
            "`multistream-select` and `noise` negotiated"
        );

        // perform noise handshake
        let (stream, peer) = noise::handshake(stream.inner(), noise_config).await?;
        tracing::trace!(target: LOG_TARGET, "noise handshake done");
        let stream: Encrypted<Compat<TcpStream>> = stream;

        // negotiate `yamux`
        let (stream, _) = Self::negotiate_protocol(stream, &role, vec!["/yamux/1.0.0"]).await?;
        tracing::trace!(target: LOG_TARGET, "`yamux` negotiated");

        let connection =
            yamux::Connection::new(stream.inner(), yamux::Config::default(), role.into());
        let (control, connection) = yamux::Control::new(connection);
        let context = ProtocolSet::from_transport_context(peer, context).await?;

        Ok(Self {
            peer,
            context,
            control,
            connection,
            _connection_id: connection_id,
            next_substream_id: 0usize,
            pending_substreams: FuturesUnordered::new(),
            address: socket_addr_to_multi_addr(&address),
        })
    }

    /// Get next substream ID.
    fn next_substream_id(&mut self) -> usize {
        let substream = self.next_substream_id;
        self.next_substream_id += 1;
        substream
    }

    /// Get remote peer ID.
    pub(crate) fn peer(&self) -> &PeerId {
        &self.peer
    }

    /// Get remote address.
    pub(crate) fn address(&self) -> &Multiaddr {
        &self.address
    }

    /// Start connection event loop.
    pub(crate) async fn start(mut self) -> crate::Result<()> {
        loop {
            tokio::select! {
                substream = self.connection.next() => match substream {
                    Some(Ok(stream)) => {
                        let substream = self.next_substream_id();
                        let protocols = self.context.protocols.keys().cloned().collect();

                        self.pending_substreams.push(Box::pin(async move {
                            Self::accept_substream(stream, substream, protocols).await
                        }));
                    },
                    Some(Err(error)) => {
                        tracing::error!(target: LOG_TARGET, ?error, "failed to poll inbound substream");
                        return Err(Error::SubstreamError(SubstreamError::YamuxError(error)));
                    }
                    None => return Err(Error::SubstreamError(SubstreamError::ConnectionClosed)),
                },
                substream = self.pending_substreams.select_next_some(), if !self.pending_substreams.is_empty() => {
                    match substream {
                        Err(error) => tracing::debug!(target: LOG_TARGET, ?error, "failed to negotiate substream"),
                        Ok(substream) => {
                            let protocol = substream.protocol.clone();
                            let substream = FuturesAsyncReadCompatExt::compat(substream);

                            if let Err(error) = self.context
                                .report_substream_open(protocol, self.peer, substream)
                                .await
                            {
                                tracing::error!(
                                    target: LOG_TARGET,
                                    ?error,
                                    "failed to register opened substream to protocol"
                                );
                            }
                        }
                    }
                }
                protocol = self.context.next_event() => match protocol {
                    Some(ProtocolEvent::OpenSubstream { protocol }) => {
                        let control = self.control.clone();
                        let substream = self.next_substream_id();

                        tracing::trace!(
                            target: LOG_TARGET,
                            ?protocol,
                            substream_id = substream,
                            "open substream"
                        );

                        self.pending_substreams.push(Box::pin(async move {
                            Self::open_substream(control, substream, protocol).await
                        }));
                    }
                    None => {
                        tracing::error!(target: LOG_TARGET, "protocols have exited, shutting down connection");
                        return Ok(())
                    }
                }
            }
        }
    }
}

// TODO: this is not needed anymore
#[derive(Debug)]
pub struct Substream {
    /// Substream ID.
    _substream: usize,

    /// Protocol name.
    protocol: ProtocolName,

    /// Yamux substream.
    io: yamux::Stream,
}

impl AsyncRead for Substream {
    fn poll_read(
        self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
        buf: &mut [u8],
    ) -> std::task::Poll<io::Result<usize>> {
        let inner = Pin::into_inner(self);
        Pin::new(&mut inner.io).poll_read(cx, buf)
    }
}

impl AsyncWrite for Substream {
    fn poll_write(
        self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
        buf: &[u8],
    ) -> std::task::Poll<io::Result<usize>> {
        let inner = Pin::into_inner(self);
        Pin::new(&mut inner.io).poll_write(cx, buf)
    }

    fn poll_flush(
        self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
    ) -> std::task::Poll<io::Result<()>> {
        let inner = Pin::into_inner(self);
        Pin::new(&mut inner.io).poll_flush(cx)
    }

    fn poll_close(
        self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
    ) -> std::task::Poll<io::Result<()>> {
        let inner = Pin::into_inner(self);
        Pin::new(&mut inner.io).poll_close(cx)
    }
}
