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

//! TCP transport types.

use crate::peer_id::PeerId;

use futures::stream::FuturesUnordered;
use multiaddr::Multiaddr;
use tokio::{net::TcpStream, sync::mpsc::Receiver};
use yamux::{Control, Stream};

use std::io::Error;

/// Type representing pending outbound connections.
pub type PendingConnections =
    FuturesUnordered<Pin<Box<dyn Future<Output = Result<TcpStream, Error>> + Send>>>;

/// Type representing pending negotiations.
pub type PendingNegotiations = FuturesUnordered<
    Pin<Box<dyn Future<Output = crate::Result<(Receiver<Stream>, PeerId)>> + Send>>,
>;

/// TCP transport events.
#[derive(Debug)]
pub enum TcpTransportEvent {
    /// Open connection to remote peer.
    OpenConnection(Multiaddr),

    /// Close connection to remote peer.
    CloseConnection(PeerId),
}

/// Context returned to [`crate::transport::tcp::TcpTransport`] after the negotation of protocols
/// have finished.
pub struct ConnectionContext {
    /// Peer ID of remote.
    peer: PeerId,

    /// `yamux` controller.
    control: Control,

    /// RX channel for receiving `yamux` substreams.
    rx: Receiver<Stream>,
}
