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

use crate::{codec::unsigned_varint::UnsignedVarint, error::Error, transport::webrtc::schema};

use prost::Message;
use str0m::channel::ChannelId;
use tokio::sync::mpsc::Sender;
use tokio_util::codec::{Decoder, Encoder};

/// Substream context.
#[derive(Debug)]
pub struct SubstreamContext {
    /// `str0m` channel id.
    pub channel_id: ChannelId,

    /// TX channel for sending messages to the protocol.
    pub tx: Sender<Vec<u8>>,
}

impl SubstreamContext {
    /// Create new [`SubstreamContext`].
    pub fn new(channel_id: ChannelId, tx: Sender<Vec<u8>>) -> Self {
        Self { channel_id, tx }
    }
}

/// WebRTC mesage.
#[derive(Debug)]
pub struct WebRtcMessage {
    /// Payload.
    pub payload: Option<Vec<u8>>,

    // Flags.
    pub flags: Option<i32>,
}

impl WebRtcMessage {
    /// Encode WebRTC message.
    pub fn encode(payload: Vec<u8>, flag: Option<i32>) -> Vec<u8> {
        let protobuf_payload = schema::webrtc::Message {
            message: (!payload.is_empty()).then_some(payload),
            flag,
        };
        let mut payload = Vec::with_capacity(protobuf_payload.encoded_len());
        protobuf_payload
            .encode(&mut payload)
            .expect("Vec<u8> to provide needed capacity");

        let mut out_buf = bytes::BytesMut::with_capacity(payload.len() + 4);
        // TODO: set correct size
        let mut codec = UnsignedVarint::new(None);
        let _result = codec.encode(payload.into(), &mut out_buf);

        out_buf.into()
    }

    /// Decode payload into [`WebRtcMessage`].
    pub fn decode(payload: &[u8]) -> crate::Result<Self> {
        // TODO: set correct size
        let mut codec = UnsignedVarint::new(None);
        let mut data = bytes::BytesMut::from(payload);
        let result = codec.decode(&mut data)?.ok_or(Error::InvalidData)?;

        match schema::webrtc::Message::decode(result) {
            Ok(message) => Ok(Self {
                payload: message.message,
                flags: message.flag,
            }),
            Err(_) => return Err(Error::InvalidData),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn with_payload_no_flags() {
        let message = WebRtcMessage::encode("Hello, world!".as_bytes().to_vec(), None);
        let decoded = WebRtcMessage::decode(&message).unwrap();

        assert_eq!(decoded.payload, Some("Hello, world!".as_bytes().to_vec()));
        assert_eq!(decoded.flags, None);
    }

    #[test]
    fn with_payload_and_flags() {
        let message = WebRtcMessage::encode("Hello, world!".as_bytes().to_vec(), Some(1i32));
        let decoded = WebRtcMessage::decode(&message).unwrap();

        assert_eq!(decoded.payload, Some("Hello, world!".as_bytes().to_vec()));
        assert_eq!(decoded.flags, Some(1i32));
    }

    #[test]
    fn no_payload_with_flags() {
        let message = WebRtcMessage::encode(vec![], Some(2i32));
        let decoded = WebRtcMessage::decode(&message).unwrap();

        assert_eq!(decoded.payload, None);
        assert_eq!(decoded.flags, Some(2i32));
    }
}
