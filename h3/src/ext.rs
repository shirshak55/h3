//! Extensions for the HTTP/3 protocol.

use std::str::FromStr;

use http::HeaderName;

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
