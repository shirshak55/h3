//! Extensions for the HTTP/3 protocol.

use std::str::FromStr;

use bytes::{Buf, BufMut, Bytes};
use http::HeaderName;

use crate::proto::varint::{BufExt, BufMutExt, VarInt};

/// Describes the `:protocol` pseudo-header for extended connect
///
/// See: <https://www.rfc-editor.org/rfc/rfc8441#section-4>
#[derive(Copy, PartialEq, Debug, Clone)]
pub struct Protocol(ProtocolInner);

impl Protocol {
    /// WebTransport protocol
    pub const WEB_TRANSPORT: Protocol = Protocol(ProtocolInner::WebTransport);
    /// RFC 9298 protocol
    pub const CONNECT_UDP: Protocol = Protocol(ProtocolInner::ConnectUdp);

    /// Return a &str representation of the `:protocol` pseudo-header value
    #[inline]
    pub fn as_str(&self) -> &str {
        match self.0 {
            ProtocolInner::WebTransport => "webtransport",
            ProtocolInner::ConnectUdp => "connect-udp",
        }
    }
}

#[derive(Copy, PartialEq, Debug, Clone)]
enum ProtocolInner {
    WebTransport,
    ConnectUdp,
}

/// Error when parsing the protocol
pub struct InvalidProtocol;

impl FromStr for Protocol {
    type Err = InvalidProtocol;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s {
            "webtransport" => Ok(Self(ProtocolInner::WebTransport)),
            "connect-udp" => Ok(Self(ProtocolInner::ConnectUdp)),
            _ => Err(InvalidProtocol),
        }
    }
}

/// The names of a message's header fields in the order its field section carries them,
/// repeats included, which a `HeaderMap` loses by grouping a repeated name's values.
///
/// The server inserts one into each request it receives, and encodes a response sent
/// with one in its order: each listed name takes the next value of that name, and values
/// it doesn't list follow in map order. Trailers carry theirs beside the map, through
/// [`RequestStream::poll_recv_trailers_with_order`] and
/// [`RequestStream::send_trailers_with_order`].
///
/// [`RequestStream::poll_recv_trailers_with_order`]: crate::server::RequestStream::poll_recv_trailers_with_order
/// [`RequestStream::send_trailers_with_order`]: crate::server::RequestStream::send_trailers_with_order
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct HeaderOrder(pub Vec<HeaderName>);

/// The order of a request's pseudo-header fields (`:method`, `:scheme`, `:authority`,
/// `:path`, `:protocol`): the order a server received them in, as a request extension,
/// or the order a client sends them in, when its request carries one. Those it doesn't
/// list follow in the default order.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct PseudoOrder(pub Vec<&'static str>);

/// How the peer used its QPACK encoder stream, as read so far. Only read while this endpoint
/// advertises a QPACK dynamic table capacity above 0.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
#[non_exhaustive]
pub struct QpackEncoderUse {
    /// The first 16 Set Dynamic Table Capacity values, in order
    pub capacities: Vec<u64>,
    /// Insert With Name Reference instructions naming a static table entry
    pub inserts_static_name: u64,
    /// Insert With Name Reference instructions naming a dynamic table entry
    pub inserts_dynamic_name: u64,
    /// Insert With Literal Name instructions
    pub inserts_literal_name: u64,
    /// Duplicate instructions
    pub duplicates: u64,
    /// Field sections received with a Required Insert Count above 0
    pub dynamic_sections: u64,
    /// Field sections that waited for encoder-stream instructions (blocked streams)
    pub blocked_sections: u64,
}

/// A frame on a control stream after SETTINGS: one the peer sent, as recorded, or one a client
/// sends ([`crate::client::Builder::control_frames`]).
#[derive(Clone, Debug, PartialEq, Eq)]
#[non_exhaustive]
pub enum ControlFrame {
    /// PRIORITY_UPDATE (RFC 9218) for a request stream (type 0xf0700) or, with `push`, a push
    /// (0xf0701): the prioritized element's ID and its Priority Field Value
    PriorityUpdate {
        /// The frame is the push variant (0xf0701)
        push: bool,
        /// The Prioritized Element ID: a request stream ID or a push ID
        id: u64,
        /// The Priority Field Value, e.g. `u=0, i`
        priority: Bytes,
    },
    /// MAX_PUSH_ID
    MaxPushId(u64),
    /// CANCEL_PUSH
    CancelPush(u64),
    /// GOAWAY
    Goaway(u64),
    /// A frame of a reserved (GREASE) or other unknown type with a `len`-byte payload. A
    /// recorded one keeps the first 256 payload bytes in `payload`; a sent one is `payload`
    /// padded with zeros to `len` (or cut to it).
    Other {
        /// The frame type
        ty: u64,
        /// The payload length
        len: u64,
        /// The payload, or its first bytes
        payload: Bytes,
    },
}

/// How many payload bytes of an unknown control frame are recorded
pub(crate) const CONTROL_PAYLOAD_RECORD_LIMIT: usize = 256;

impl ControlFrame {
    pub(crate) const PRIORITY_UPDATE_REQUEST: u64 = 0xf0700;
    pub(crate) const PRIORITY_UPDATE_PUSH: u64 = 0xf0701;

    /// The frame of type `ty` with a `len`-byte payload beginning with `payload`
    pub(crate) fn parse(ty: u64, len: u64, payload: Bytes) -> Self {
        let whole = payload.len() as u64 == len;
        let mut buf = payload.clone();
        let id = buf.get_var().ok().filter(|_| whole);
        match (ty, id) {
            (Self::PRIORITY_UPDATE_REQUEST | Self::PRIORITY_UPDATE_PUSH, Some(id)) => {
                Self::PriorityUpdate {
                    push: ty == Self::PRIORITY_UPDATE_PUSH,
                    id,
                    priority: buf,
                }
            }
            (0xd, Some(id)) if !buf.has_remaining() => Self::MaxPushId(id),
            (0x3, Some(id)) if !buf.has_remaining() => Self::CancelPush(id),
            (0x7, Some(id)) if !buf.has_remaining() => Self::Goaway(id),
            _ => Self::Other { ty, len, payload },
        }
    }

    /// Whether every value fits a variable-length integer
    pub(crate) fn is_valid(&self) -> bool {
        let values = match self {
            Self::PriorityUpdate { id, .. } => vec![*id],
            Self::MaxPushId(id) | Self::CancelPush(id) | Self::Goaway(id) => vec![*id],
            Self::Other { ty, len, .. } => vec![*ty, *len],
        };
        values.into_iter().all(|v| VarInt::from_u64(v).is_ok())
    }

    pub(crate) fn encode<B: BufMut>(&self, buf: &mut B) {
        let (ty, payload) = match self {
            Self::PriorityUpdate { push, id, priority } => {
                let mut payload = Vec::new();
                payload.write_var(*id);
                payload.extend_from_slice(priority);
                let ty = match push {
                    true => Self::PRIORITY_UPDATE_PUSH,
                    false => Self::PRIORITY_UPDATE_REQUEST,
                };
                (ty, payload)
            }
            Self::MaxPushId(id) | Self::CancelPush(id) | Self::Goaway(id) => {
                let ty = match self {
                    Self::MaxPushId(_) => 0xd,
                    Self::CancelPush(_) => 0x3,
                    _ => 0x7,
                };
                let mut payload = Vec::new();
                payload.write_var(*id);
                (ty, payload)
            }
            Self::Other { ty, len, payload } => {
                let mut sent = payload.to_vec();
                sent.resize(*len as usize, 0);
                (*ty, sent)
            }
        };
        buf.write_var(ty);
        buf.write_var(payload.len() as u64);
        buf.put_slice(&payload);
    }
}
