//! Extensions for the HTTP/3 protocol.

use std::{
    borrow::Cow,
    str::FromStr,
    sync::{
        atomic::{AtomicUsize, Ordering},
        Arc,
    },
    task::{ready, Context, Poll},
};

use bytes::{Buf, BufMut, Bytes};
use futures_util::task::AtomicWaker;
use http::HeaderName;
use tokio::sync::mpsc;

use crate::{
    proto::varint::{BufExt, BufMutExt, VarInt},
    quic::StreamId,
};

/// Describes the `:protocol` pseudo-header for extended connect: any protocol token (RFC 9110
/// §5.6.2), such as `websocket` (RFC 9220), `webtransport` or `connect-udp` (RFC 9298)
///
/// See: <https://www.rfc-editor.org/rfc/rfc8441#section-4>
#[derive(PartialEq, Eq, Hash, Debug, Clone)]
pub struct Protocol(Cow<'static, str>);

impl Protocol {
    /// WebTransport protocol
    pub const WEB_TRANSPORT: Protocol = Protocol(Cow::Borrowed("webtransport"));
    /// RFC 9298 protocol
    pub const CONNECT_UDP: Protocol = Protocol(Cow::Borrowed("connect-udp"));

    /// Return a &str representation of the `:protocol` pseudo-header value
    #[inline]
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

/// Error when parsing the protocol: a value that is not a token
pub struct InvalidProtocol;

impl FromStr for Protocol {
    type Err = InvalidProtocol;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        let tchar = |c: u8| c.is_ascii_alphanumeric() || b"!#$%&'*+-.^_`|~".contains(&c);
        match !s.is_empty() && s.bytes().all(tchar) {
            true => Ok(Self(Cow::Owned(s.to_owned()))),
            false => Err(InvalidProtocol),
        }
    }
}

/// A WebTransport stream (draft-ietf-webtrans-http3) the peer opened, handed over with its
/// header read: the session it belongs to (the ID of its CONNECT request's stream), the
/// bytes read past the header, and whether the stream had ended by then
pub enum WebTransportStream<Bidi, Recv> {
    /// A bidirectional stream, its WEBTRANSPORT_STREAM signal read
    Bidi {
        /// Its session's CONNECT stream ID
        session_id: u64,
        /// The bytes read past the header
        read: Bytes,
        /// Whether the peer had finished the stream
        finished: bool,
        /// The stream
        stream: Bidi,
    },
    /// A unidirectional stream, its stream type read
    Uni {
        /// Its session's CONNECT stream ID
        session_id: u64,
        /// The bytes read past the header
        read: Bytes,
        /// Whether the peer had finished the stream
        finished: bool,
        /// The stream
        stream: Recv,
    },
}

/// A unidirectional stream of a type HTTP/3 doesn't know (a reserved (GREASE) one, for
/// one) the peer opened, handed over with its type read (see `subscribe_unknown_streams`)
pub struct UnknownStream<Recv> {
    /// Its stream type
    pub ty: u64,
    /// The bytes read past the type
    pub read: Bytes,
    /// Whether the peer had finished the stream
    pub finished: bool,
    /// The stream
    pub stream: Recv,
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
    /// A frame of a reserved (GREASE) or other unknown type with a `len`-byte payload; one
    /// sent must carry all of it.
    Other {
        /// The frame type
        ty: u64,
        /// The payload length
        len: u64,
        /// The payload
        payload: Bytes,
    },
}

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

    /// How many bytes the frame holds, for a budget of frames held
    pub(crate) fn size(&self) -> usize {
        match self {
            Self::PriorityUpdate { priority, .. } => priority.len(),
            Self::Other { payload, .. } => payload.len(),
            _ => 0,
        }
    }

    /// Whether every value fits a variable-length integer, and an unknown frame carries its
    /// whole payload
    pub(crate) fn is_valid(&self) -> bool {
        let values = match self {
            Self::PriorityUpdate { id, .. } => vec![*id],
            Self::MaxPushId(id) | Self::CancelPush(id) | Self::Goaway(id) => vec![*id],
            Self::Other { ty, len, payload } if payload.len() as u64 == *len => vec![*ty, *len],
            Self::Other { .. } => return false,
        };
        values.into_iter().all(|v| VarInt::from_u64(v).is_ok())
    }

    pub(crate) fn encode<B: BufMut>(&self, buf: &mut B) {
        let mut fields = Vec::new();
        let (ty, payload): (u64, &[u8]) = match self {
            Self::PriorityUpdate { push, id, priority } => {
                fields.write_var(*id);
                fields.extend_from_slice(priority);
                let ty = match push {
                    true => Self::PRIORITY_UPDATE_PUSH,
                    false => Self::PRIORITY_UPDATE_REQUEST,
                };
                (ty, &fields)
            }
            Self::MaxPushId(id) | Self::CancelPush(id) | Self::Goaway(id) => {
                let ty = match self {
                    Self::MaxPushId(_) => 0xd,
                    Self::CancelPush(_) => 0x3,
                    _ => 0x7,
                };
                fields.write_var(*id);
                (ty, &fields)
            }
            Self::Other { ty, payload, .. } => (*ty, payload),
        };
        buf.write_var(ty);
        buf.write_var(payload.len() as u64);
        buf.put_slice(payload);
    }
}

/// The largest field section an endpoint accepts, whatever SETTINGS_MAX_FIELD_SECTION_SIZE
/// it sends (none, or a larger one): a section is read and decoded whole.
pub const MAX_FIELD_SECTION_SIZE: u64 = 16 << 20;

/// The peer's control-stream frames after SETTINGS, as the connection reads them (see
/// `subscribe_control_frames`). While the frames sent here and not received yet hold
/// [`ControlFrames::BUDGET`] bytes, the connection reads no more of the control stream, so
/// the peer's flow control holds it back, as it holds back a peer whose frames aren't read.
pub struct ControlFrames {
    pub(crate) frames: mpsc::UnboundedReceiver<ControlFrame>,
    pub(crate) held: Arc<HeldFrames>,
}

impl ControlFrames {
    /// How many bytes the frames not received yet may hold before the control stream is read
    /// on: their payloads, and [`HeldFrames::OVERHEAD`] each.
    pub const BUDGET: usize = 64 * 1024;

    /// Receives the next frame; `None` once the connection ended.
    pub async fn recv(&mut self) -> Option<ControlFrame> {
        std::future::poll_fn(|cx| self.poll_recv(cx)).await
    }

    /// Polls for the next frame; `None` once the connection ended.
    pub fn poll_recv(&mut self, cx: &mut Context<'_>) -> Poll<Option<ControlFrame>> {
        let frame = ready!(self.frames.poll_recv(cx));
        if let Some(frame) = &frame {
            self.held.release(frame);
        }
        Poll::Ready(frame)
    }

    /// The next frame read already, if any.
    pub fn try_recv(&mut self) -> Option<ControlFrame> {
        let frame = self.frames.try_recv().ok()?;
        self.held.release(&frame);
        Some(frame)
    }
}

/// The bytes of the frames sent to a [`ControlFrames`] and not received yet, and the waker of
/// the connection waiting for them to be received.
#[derive(Default)]
pub(crate) struct HeldFrames {
    bytes: AtomicUsize,
    reader: AtomicWaker,
}

impl HeldFrames {
    /// What a frame held counts for beyond its payload.
    pub(crate) const OVERHEAD: usize = 64;

    fn cost(frame: &ControlFrame) -> usize {
        frame.size() + Self::OVERHEAD
    }

    pub(crate) fn hold(&self, frame: &ControlFrame) {
        self.bytes.fetch_add(Self::cost(frame), Ordering::AcqRel);
    }

    pub(crate) fn release(&self, frame: &ControlFrame) {
        self.bytes.fetch_sub(Self::cost(frame), Ordering::AcqRel);
        self.reader.wake();
    }

    /// Whether the connection may read on, else woken once frames are received.
    pub(crate) fn poll_room(&self, cx: &mut Context<'_>) -> bool {
        self.reader.register(cx.waker());
        self.bytes.load(Ordering::Acquire) < ControlFrames::BUDGET
    }
}

/// A server push a client that sent MAX_PUSH_ID saw, and cancelled
#[derive(Clone, Debug, PartialEq, Eq)]
#[non_exhaustive]
pub enum PushEvent {
    /// A PUSH_PROMISE on the request stream `stream`, with the promised request's field lines
    /// (name, value) in order. The client answered with CANCEL_PUSH.
    Promise {
        /// The push ID
        push_id: u64,
        /// The request stream the promise came on
        stream: StreamId,
        /// The promised request's field lines
        fields: Vec<(Bytes, Bytes)>,
    },
    /// A push stream, which the client stopped reading (STOP_SENDING H3_REQUEST_CANCELLED)
    Stream {
        /// The push ID
        push_id: u64,
        /// The push stream
        stream: StreamId,
    },
    /// A CANCEL_PUSH from the server
    Cancelled {
        /// The push ID
        push_id: u64,
    },
}
