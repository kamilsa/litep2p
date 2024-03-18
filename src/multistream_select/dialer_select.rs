// Copyright 2017 Parity Technologies (UK) Ltd.
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

//! Protocol negotiation strategies for the peer acting as the dialer.

use crate::{
    codec::unsigned_varint::UnsignedVarint,
    error::{self, Error},
    multistream_select::{
        protocol::{HeaderLine, Message, MessageIO, Protocol, ProtocolError},
        Negotiated, NegotiationError, Version,
    },
    types::protocol::ProtocolName,
};

use bytes::BytesMut;
use futures::prelude::*;
use rustls::internal::msgs::hsjoiner::HandshakeJoiner;
use std::{
    convert::TryFrom as _,
    iter, mem,
    pin::Pin,
    task::{Context, Poll},
};

const LOG_TARGET: &str = "litep2p::multistream-select";

/// Returns a `Future` that negotiates a protocol on the given I/O stream
/// for a peer acting as the _dialer_ (or _initiator_).
///
/// This function is given an I/O stream and a list of protocols and returns a
/// computation that performs the protocol negotiation with the remote. The
/// returned `Future` resolves with the name of the negotiated protocol and
/// a [`Negotiated`] I/O stream.
///
/// Within the scope of this library, a dialer always commits to a specific
/// multistream-select [`Version`], whereas a listener always supports
/// all versions supported by this library. Frictionless multistream-select
/// protocol upgrades may thus proceed by deployments with updated listeners,
/// eventually followed by deployments of dialers choosing the newer protocol.
pub fn dialer_select_proto<R, I>(
    inner: R,
    protocols: I,
    version: Version,
) -> DialerSelectFuture<R, I::IntoIter>
where
    R: AsyncRead + AsyncWrite,
    I: IntoIterator,
    I::Item: AsRef<[u8]>,
{
    let protocols = protocols.into_iter().peekable();
    DialerSelectFuture {
        version,
        protocols,
        state: State::SendHeader {
            io: MessageIO::new(inner),
        },
    }
}

/// A `Future` returned by [`dialer_select_proto`] which negotiates
/// a protocol iteratively by considering one protocol after the other.
#[pin_project::pin_project]
pub struct DialerSelectFuture<R, I: Iterator> {
    // TODO: It would be nice if eventually N = I::Item = Protocol.
    protocols: iter::Peekable<I>,
    state: State<R, I::Item>,
    version: Version,
}

enum State<R, N> {
    SendHeader {
        io: MessageIO<R>,
    },
    SendProtocol {
        io: MessageIO<R>,
        protocol: N,
        header_received: bool,
    },
    FlushProtocol {
        io: MessageIO<R>,
        protocol: N,
        header_received: bool,
    },
    AwaitProtocol {
        io: MessageIO<R>,
        protocol: N,
        header_received: bool,
    },
    Done,
}

impl<R, I> Future for DialerSelectFuture<R, I>
where
    // The Unpin bound here is required because we produce
    // a `Negotiated<R>` as the output. It also makes
    // the implementation considerably easier to write.
    R: AsyncRead + AsyncWrite + Unpin,
    I: Iterator,
    I::Item: AsRef<[u8]>,
{
    type Output = Result<(I::Item, Negotiated<R>), NegotiationError>;

    fn poll(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Self::Output> {
        let this = self.project();

        loop {
            match mem::replace(this.state, State::Done) {
                State::SendHeader { mut io } => {
                    match Pin::new(&mut io).poll_ready(cx)? {
                        Poll::Ready(()) => {}
                        Poll::Pending => {
                            *this.state = State::SendHeader { io };
                            return Poll::Pending;
                        }
                    }

                    let h = HeaderLine::from(*this.version);
                    if let Err(err) = Pin::new(&mut io).start_send(Message::Header(h)) {
                        return Poll::Ready(Err(From::from(err)));
                    }

                    let protocol = this.protocols.next().ok_or(NegotiationError::Failed)?;

                    // The dialer always sends the header and the first protocol
                    // proposal in one go for efficiency.
                    *this.state = State::SendProtocol {
                        io,
                        protocol,
                        header_received: false,
                    };
                }

                State::SendProtocol {
                    mut io,
                    protocol,
                    header_received,
                } => {
                    match Pin::new(&mut io).poll_ready(cx)? {
                        Poll::Ready(()) => {}
                        Poll::Pending => {
                            *this.state = State::SendProtocol {
                                io,
                                protocol,
                                header_received,
                            };
                            return Poll::Pending;
                        }
                    }

                    let p = Protocol::try_from(protocol.as_ref())?;
                    if let Err(err) = Pin::new(&mut io).start_send(Message::Protocol(p.clone())) {
                        return Poll::Ready(Err(From::from(err)));
                    }
                    tracing::debug!(target: LOG_TARGET, "Dialer: Proposed protocol: {}", p);

                    if this.protocols.peek().is_some() {
                        *this.state = State::FlushProtocol {
                            io,
                            protocol,
                            header_received,
                        }
                    } else {
                        match this.version {
                            Version::V1 =>
                                *this.state = State::FlushProtocol {
                                    io,
                                    protocol,
                                    header_received,
                                },
                            // This is the only effect that `V1Lazy` has compared to `V1`:
                            // Optimistically settling on the only protocol that
                            // the dialer supports for this negotiation. Notably,
                            // the dialer expects a regular `V1` response.
                            Version::V1Lazy => {
                                tracing::debug!(
                                    target: LOG_TARGET,
                                    "Dialer: Expecting proposed protocol: {}",
                                    p
                                );
                                let hl = HeaderLine::from(Version::V1Lazy);
                                let io = Negotiated::expecting(io.into_reader(), p, Some(hl));
                                return Poll::Ready(Ok((protocol, io)));
                            }
                        }
                    }
                }

                State::FlushProtocol {
                    mut io,
                    protocol,
                    header_received,
                } => match Pin::new(&mut io).poll_flush(cx)? {
                    Poll::Ready(()) =>
                        *this.state = State::AwaitProtocol {
                            io,
                            protocol,
                            header_received,
                        },
                    Poll::Pending => {
                        *this.state = State::FlushProtocol {
                            io,
                            protocol,
                            header_received,
                        };
                        return Poll::Pending;
                    }
                },

                State::AwaitProtocol {
                    mut io,
                    protocol,
                    header_received,
                } => {
                    let msg = match Pin::new(&mut io).poll_next(cx)? {
                        Poll::Ready(Some(msg)) => msg,
                        Poll::Pending => {
                            *this.state = State::AwaitProtocol {
                                io,
                                protocol,
                                header_received,
                            };
                            return Poll::Pending;
                        }
                        // Treat EOF error as [`NegotiationError::Failed`], not as
                        // [`NegotiationError::ProtocolError`], allowing dropping or closing an I/O
                        // stream as a permissible way to "gracefully" fail a negotiation.
                        Poll::Ready(None) => return Poll::Ready(Err(NegotiationError::Failed)),
                    };

                    match msg {
                        Message::Header(v)
                            if v == HeaderLine::from(*this.version) && !header_received =>
                        {
                            *this.state = State::AwaitProtocol {
                                io,
                                protocol,
                                header_received: true,
                            };
                        }
                        Message::Protocol(ref p) if p.as_ref() == protocol.as_ref() => {
                            tracing::debug!(
                                target: LOG_TARGET,
                                "Dialer: Received confirmation for protocol: {}",
                                p
                            );
                            let io = Negotiated::completed(io.into_inner());
                            return Poll::Ready(Ok((protocol, io)));
                        }
                        Message::NotAvailable => {
                            tracing::debug!(
                                target: LOG_TARGET,
                                "Dialer: Received rejection of protocol: {}",
                                String::from_utf8_lossy(protocol.as_ref())
                            );
                            let protocol = this.protocols.next().ok_or(NegotiationError::Failed)?;
                            *this.state = State::SendProtocol {
                                io,
                                protocol,
                                header_received,
                            }
                        }
                        _ => return Poll::Ready(Err(ProtocolError::InvalidMessage.into())),
                    }
                }

                State::Done => panic!("State::poll called after completion"),
            }
        }
    }
}

/// `multistream-select` handshake result for dialer.
#[derive(Debug)]
pub enum HandshakeResult {
    /// Handshake is not complete, data missing.
    NotReady,

    /// Handshake has succeeded.
    ///
    /// The returned tuple contains the negotiated protocol and response
    /// that must be sent to remote peer.
    Succeeded(ProtocolName),
}

/// Handshake state.
#[derive(Debug)]
enum HandshakeState {
    /// Wainting to receive any response from remote peer.
    WaitingResponse,

    /// Waiting to receive the actual application protocol from remote peer.
    WaitingProtocol,
}

/// `multistream-select` dialer handshake state.
#[derive(Debug)]
pub struct DialerState {
    /// Proposed main protocol.
    protocol: ProtocolName,

    /// Fallback names of the main protocol.
    fallback_names: Vec<ProtocolName>,

    /// Dialer handshake state.
    state: HandshakeState,
}

// TODO: tests
impl DialerState {
    /// Propose protocol to remote peer.
    ///
    /// Return [`DialerState`] which is used to drive forward the negotiation and an encoded
    /// `multistream-select` message that contains the protocol proposal for the substream.
    pub fn propose(
        protocol: ProtocolName,
        fallback_names: Vec<ProtocolName>,
    ) -> crate::Result<(Self, Vec<u8>)> {
        // encode `/multistream-select/1.0.0` header
        let mut bytes = BytesMut::with_capacity(64);
        let message = Message::Header(HeaderLine::V1);
        let _ = message.encode(&mut bytes).map_err(|_| Error::InvalidData)?;
        let mut header = UnsignedVarint::encode(bytes)?;

        // encode proposed protocol
        let mut proto_bytes = BytesMut::with_capacity(512);
        let message = Message::Protocol(Protocol::try_from(protocol.as_bytes()).unwrap());
        let _ = message.encode(&mut proto_bytes).map_err(|_| Error::InvalidData)?;
        let proto_bytes = UnsignedVarint::encode(proto_bytes)?;

        // TODO: add fallback names

        header.append(&mut proto_bytes.into());

        Ok((
            Self {
                protocol,
                fallback_names,
                state: HandshakeState::WaitingResponse,
            },
            header,
        ))
    }

    /// Register response to [`DialerState`].
    pub fn register_response(&mut self, payload: Vec<u8>) -> crate::Result<HandshakeResult> {
        let Message::Protocols(protocols) =
            Message::decode(payload.into()).map_err(|_| Error::InvalidData)?
        else {
            return Err(Error::NegotiationError(
                error::NegotiationError::MultistreamSelectError(NegotiationError::Failed),
            ));
        };

        let mut protocol_iter = protocols.into_iter();
        loop {
            match (&self.state, protocol_iter.next()) {
                (HandshakeState::WaitingResponse, None) => return Err(Error::InvalidState),
                (HandshakeState::WaitingResponse, Some(protocol)) => {
                    let header = Protocol::try_from(&b"/multistream/1.0.0"[..])
                        .expect("valid multitstream-select header");

                    if protocol == header {
                        self.state = HandshakeState::WaitingProtocol;
                    } else {
                        return Err(Error::NegotiationError(
                            error::NegotiationError::MultistreamSelectError(
                                NegotiationError::Failed,
                            ),
                        ));
                    }
                }
                (HandshakeState::WaitingProtocol, Some(protocol)) => {
                    if self.protocol.as_bytes() == protocol.as_ref() {
                        return Ok(HandshakeResult::Succeeded(self.protocol.clone()));
                    }

                    // TODO: zzz
                    for fallback in &self.fallback_names {
                        if fallback.as_bytes() == protocol.as_ref() {
                            return Ok(HandshakeResult::Succeeded(self.protocol.clone()));
                        }
                    }

                    return Err(Error::NegotiationError(
                        error::NegotiationError::MultistreamSelectError(NegotiationError::Failed),
                    ));
                }
                (HandshakeState::WaitingProtocol, None) => {
                    return Ok(HandshakeResult::NotReady);
                }
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::multistream_select::listener_select_proto;
    use std::time::Duration;
    use tokio::net::{TcpListener, TcpStream};

    #[tokio::test]
    async fn select_proto_basic() {
        async fn run(version: Version) {
            let (client_connection, server_connection) = futures_ringbuf::Endpoint::pair(100, 100);

            let server = tokio::spawn(async move {
                let protos = vec!["/proto1", "/proto2"];
                let (proto, mut io) =
                    listener_select_proto(server_connection, protos).await.unwrap();
                assert_eq!(proto, "/proto2");

                let mut out = vec![0; 32];
                let n = io.read(&mut out).await.unwrap();
                out.truncate(n);
                assert_eq!(out, b"ping");

                io.write_all(b"pong").await.unwrap();
                io.flush().await.unwrap();
            });

            let client = tokio::spawn(async move {
                let protos = vec!["/proto3", "/proto2"];
                let (proto, mut io) =
                    dialer_select_proto(client_connection, protos, version).await.unwrap();
                assert_eq!(proto, "/proto2");

                io.write_all(b"ping").await.unwrap();
                io.flush().await.unwrap();

                let mut out = vec![0; 32];
                let n = io.read(&mut out).await.unwrap();
                out.truncate(n);
                assert_eq!(out, b"pong");
            });

            server.await;
            client.await;
        }

        run(Version::V1).await;
        run(Version::V1Lazy).await;
    }

    /// Tests the expected behaviour of failed negotiations.
    #[tokio::test]
    async fn negotiation_failed() {
        async fn run(
            version: Version,
            dial_protos: Vec<&'static str>,
            dial_payload: Vec<u8>,
            listen_protos: Vec<&'static str>,
        ) {
            let (client_connection, server_connection) = futures_ringbuf::Endpoint::pair(100, 100);

            let server = tokio::spawn(async move {
                let io = match tokio::time::timeout(
                    Duration::from_secs(2),
                    listener_select_proto(server_connection, listen_protos),
                )
                .await
                .unwrap()
                {
                    Ok((_, io)) => io,
                    Err(NegotiationError::Failed) => return,
                    Err(NegotiationError::ProtocolError(e)) => {
                        panic!("Unexpected protocol error {e}")
                    }
                };
                match io.complete().await {
                    Err(NegotiationError::Failed) => {}
                    _ => panic!(),
                }
            });

            let client = tokio::spawn(async move {
                let mut io = match tokio::time::timeout(
                    Duration::from_secs(2),
                    dialer_select_proto(client_connection, dial_protos, version),
                )
                .await
                .unwrap()
                {
                    Err(NegotiationError::Failed) => return,
                    Ok((_, io)) => io,
                    Err(_) => panic!(),
                };

                // The dialer may write a payload that is even sent before it
                // got confirmation of the last proposed protocol, when `V1Lazy`
                // is used.
                io.write_all(&dial_payload).await.unwrap();
                match io.complete().await {
                    Err(NegotiationError::Failed) => {}
                    _ => panic!(),
                }
            });

            server.await;
            client.await;
        }

        // Incompatible protocols.
        run(Version::V1, vec!["/proto1"], vec![1], vec!["/proto2"]).await;
        run(Version::V1Lazy, vec!["/proto1"], vec![1], vec!["/proto2"]).await;
    }

    #[tokio::test]
    async fn v1_lazy_do_not_wait_for_negotiation_on_poll_close() {
        let (client_connection, _server_connection) =
            futures_ringbuf::Endpoint::pair(1024 * 1024, 1);

        let client = tokio::spawn(async move {
            // Single protocol to allow for lazy (or optimistic) protocol negotiation.
            let protos = vec!["/proto1"];
            let (proto, mut io) =
                dialer_select_proto(client_connection, protos, Version::V1Lazy).await.unwrap();
            assert_eq!(proto, "/proto1");

            // In Libp2p the lazy negotation of protocols can be closed at any time,
            // even if the negotiation is not yet done.

            // However, for the Litep2p the negotation must conclude before closing the
            // lazy negotation of protocol. We'll wait for the close until the
            // server has produced a message, in this test that means forever.
            io.close().await.unwrap();
        });

        assert!(tokio::time::timeout(Duration::from_secs(10), client).await.is_err());
    }
}
