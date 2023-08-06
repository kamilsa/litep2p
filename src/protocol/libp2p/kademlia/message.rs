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
    codec::unsigned_varint::UnsignedVarint,
    peer_id::PeerId,
    protocol::libp2p::kademlia::{schema, types::KademliaPeer},
};

use bytes::BytesMut;
use multiaddr::Multiaddr;
use prost::Message;

/// Logging target for the file.
const LOG_TARGET: &str = "ifps::kademlia::message";

/// Kademlia message.
#[derive(Debug)]
pub(super) enum KademliaMessage {
    /// Found peer.
    FindNode {
        /// Found peers.
        peers: Vec<KademliaPeer>,
    },
}

impl KademliaMessage {
    /// Create `FIND_NODE` message for `peer` and encode it using `UnsignedVarint`.
    pub(super) fn find_node(peer: PeerId) -> Vec<u8> {
        let message = schema::kademlia::Message {
            key: peer.to_bytes(),
            r#type: schema::kademlia::MessageType::FindNode.into(),
            cluster_level_raw: 10,
            ..Default::default()
        };

        let mut buf = Vec::with_capacity(message.encoded_len());
        message
            .encode(&mut buf)
            .expect("Vec<u8> to provide needed capacity");

        buf
    }

    /// Create `GET_VALUE` message.
    pub(super) fn get_value() -> Vec<u8> {
        todo!();
    }

    /// Create `PUT_VALUE` message.
    pub(super) fn put_value() -> Vec<u8> {
        todo!();
    }

    /// Get [`KademliaMessage`] from bytes.
    pub fn from_bytes(bytes: BytesMut) -> Option<Self> {
        match schema::kademlia::Message::decode(bytes) {
            Ok(message) => match message.r#type {
                4 => {
                    let peers = message
                        .closer_peers
                        .iter()
                        .filter_map(|peer| KademliaPeer::try_from(peer).ok())
                        .collect();

                    Some(Self::FindNode { peers })
                }
                _ => {
                    todo!("unsupported message type");
                }
            },
            Err(error) => {
                tracing::debug!(target: LOG_TARGET, ?error, "failed to decode message");
                None
            }
        }
    }
}