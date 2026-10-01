//! HTTP/3 client builder

use std::{
    marker::PhantomData,
    sync::{atomic::AtomicUsize, Arc},
};

use bytes::{Buf, Bytes};

use crate::{
    config::Config,
    connection::ConnectionInner,
    error::ConnectionError,
    quic::{self},
    shared_state::SharedState,
};

use super::connection::{Connection, SendRequest};

/// Start building a new HTTP/3 client
pub fn builder() -> Builder {
    Builder::new()
}

/// Create a new HTTP/3 client with default settings
pub async fn new<C, O>(
    conn: C,
) -> Result<(Connection<C, Bytes>, SendRequest<O, Bytes>), ConnectionError>
where
    C: quic::Connection<Bytes, OpenStreams = O>,
    O: quic::OpenStreams<Bytes>,
{
    //= https://www.rfc-editor.org/rfc/rfc9114#section-3.3
    //= type=implication
    //# Clients SHOULD NOT open more than one HTTP/3 connection to a given IP
    //# address and UDP port, where the IP address and port might be derived
    //# from a URI, a selected alternative service ([ALTSVC]), a configured
    //# proxy, or name resolution of any of these.
    Builder::new().build(conn).await
}

/// HTTP/3 client builder
///
/// Set the configuration for a new client.
///
/// # Examples
/// ```rust
/// # use h3::quic;
/// # async fn doc<C, O, B>(quic: C)
/// # where
/// #   C: quic::Connection<B, OpenStreams = O>,
/// #   O: quic::OpenStreams<B>,
/// #   B: bytes::Buf,
/// # {
/// let h3_conn = h3::client::builder()
///     .max_field_section_size(8192)
///     .build(quic)
///     .await
///     .expect("Failed to build connection");
/// # }
/// ```
pub struct Builder {
    config: Config,
}

impl Builder {
    pub(super) fn new() -> Self {
        Builder {
            config: Default::default(),
        }
    }

    // Not public API, just used in unit tests
    #[doc(hidden)]
    #[cfg(test)]
    pub fn send_settings(&mut self, value: bool) -> &mut Self {
        self.config.send_settings = value;
        self
    }

    /// Set the maximum header size this client is willing to accept
    ///
    /// See [header size constraints] section of the specification for details.
    ///
    /// [header size constraints]: https://www.rfc-editor.org/rfc/rfc9114.html#name-header-size-constraints
    pub fn max_field_section_size(&mut self, value: u64) -> &mut Self {
        self.config.settings.max_field_section_size = value;
        self
    }

    /// Just like in HTTP/2, HTTP/3 also uses the concept of "grease"
    /// to prevent potential interoperability issues in the future.
    /// In HTTP/3, the concept of grease is used to ensure that the protocol can evolve
    /// and accommodate future changes without breaking existing implementations.
    pub fn send_grease(&mut self, enabled: bool) -> &mut Self {
        self.config.send_grease = enabled;
        self.config.send_grease_frame = enabled;
        self.config.send_grease_stream = enabled;
        self
    }

    /// Send a reserved frame on the first request stream
    pub fn send_grease_frame(&mut self, enabled: bool) -> &mut Self {
        self.config.send_grease_frame = enabled;
        self
    }

    /// Open a unidirectional stream of a reserved type carrying a reserved frame
    pub fn send_grease_stream(&mut self, enabled: bool) -> &mut Self {
        self.config.send_grease_stream = enabled;
        self
    }

    /// Send a reserved frame on the control stream right after the SETTINGS frame, of a random
    /// type with a 6-byte payload. [`Builder::control_frames`] sends one of a given type and
    /// payload instead.
    pub fn send_control_grease_frame(&mut self, enabled: bool) -> &mut Self {
        self.config.send_control_grease_frame = enabled;
        self
    }

    /// Send these frames on the control stream after SETTINGS (and the reserved frame of
    /// [`Builder::send_control_grease_frame`]), in this order: a client's recorded frames, such
    /// as a reserved (GREASE) [`ControlFrame::Other`] with its type and payload length, or
    /// MAX_PUSH_ID. After a MAX_PUSH_ID the client tolerates the server's pushes, cancelling
    /// them. A frame with a value that is not a valid variable-length integer fails
    /// [`Builder::build`].
    ///
    /// [`ControlFrame::Other`]: crate::ext::ControlFrame::Other
    pub fn control_frames(
        &mut self,
        frames: impl IntoIterator<Item = crate::ext::ControlFrame>,
    ) -> &mut Self {
        self.config.control_frames = frames.into_iter().collect();
        self
    }

    /// Deliver the pushes the server makes after this client's MAX_PUSH_ID
    /// ([`Builder::control_frames`]) through [`Connection::subscribe_pushes`], instead of
    /// cancelling them: each PUSH_PROMISE as a [`PushedRequest`] with its [`PushedResponse`].
    /// Without a MAX_PUSH_ID nothing is delivered.
    ///
    /// [`PushedRequest`]: super::PushedRequest
    /// [`PushedResponse`]: super::PushedResponse
    pub fn deliver_pushes(&mut self, enabled: bool) -> &mut Self {
        self.config.deliver_pushes = enabled;
        self
    }

    /// Send these (identifier, value) pairs, in this order, as the SETTINGS frame instead of
    /// the generated ones.
    ///
    /// The client then enforces and reports the MAX_FIELD_SECTION_SIZE, extended CONNECT,
    /// datagram and WebTransport values they carry, overriding the other builder settings.
    /// QPACK settings are sent as given and honoured as by [`Builder::qpack_max_table_capacity`]
    /// and [`Builder::qpack_blocked_streams`].
    pub fn raw_settings(&mut self, settings: impl IntoIterator<Item = (u64, u64)>) -> &mut Self {
        self.config.raw_settings = Some(settings.into_iter().collect());
        self
    }

    /// Advertise SETTINGS_QPACK_MAX_TABLE_CAPACITY: above 0, field sections are decoded with a
    /// QPACK dynamic table of up to this many bytes, built from the peer's encoder stream, and
    /// acknowledged on the decoder stream. 0 (the default) decodes without one, as before.
    ///
    /// The connection must be driven (polled) for the encoder stream to be read.
    pub fn qpack_max_table_capacity(&mut self, value: u64) -> &mut Self {
        self.config.settings.qpack_max_table_capacity = value;
        self
    }

    /// Advertise SETTINGS_QPACK_BLOCKED_STREAMS: how many streams may wait for the QPACK encoder
    /// instructions their field sections depend on. More is a QPACK_DECOMPRESSION_FAILED
    /// connection error.
    pub fn qpack_blocked_streams(&mut self, value: u64) -> &mut Self {
        self.config.settings.qpack_blocked_streams = value;
        self
    }

    /// Encode field sections with the peer's QPACK dynamic table: once its SETTINGS allow a
    /// capacity above 0, send Set Dynamic Table Capacity with the smaller of that and
    /// `capacity`, then insert fields on the encoder stream and reference them, within the
    /// peer's blocked-streams limit, and read its decoder stream. 0 (the default) encodes
    /// without a dynamic table, as before.
    ///
    /// A field without an exact static-table match is referenced if an identical entry exists,
    /// else inserted (unless it takes more than half the capacity, or is `:path`,
    /// `content-length`, `date`, `etag`, `last-modified`, `if-modified-since`, `if-none-match`,
    /// `authorization` or `proxy-authorization`) and referenced, else sent as a literal with a
    /// static or dynamic name reference when one exists. Strings are Huffman-encoded. Entries
    /// are evicted oldest first, only once acknowledged and unreferenced.
    ///
    /// The connection must be driven (polled) for the encoder stream to be written.
    pub fn qpack_encoder_capacity(&mut self, capacity: u64) -> &mut Self {
        self.config.qpack_encoder_capacity = capacity;
        self
    }

    /// Open the QPACK decoder stream before the encoder stream, as Chrome does, so it takes
    /// the lower stream ID. By default the encoder stream is opened first.
    pub fn qpack_decoder_stream_first(&mut self, enabled: bool) -> &mut Self {
        self.config.qpack_decoder_stream_first = enabled;
        self
    }

    /// Write each QPACK stream's type only with its first instruction, as Chrome does, so a
    /// stream that never carries one is never seen by the peer. By default both stream types
    /// are written right after SETTINGS.
    pub fn qpack_lazy_stream_types(&mut self, enabled: bool) -> &mut Self {
        self.config.qpack_lazy_stream_types = enabled;
        self
    }

    /// Hold back the control stream's SETTINGS and frames, the QPACK streams' types and the
    /// reserved stream until [`Connection::start`], as from a client whose SETTINGS arrive
    /// after its first request: requests can be sent at once, their field sections encoded
    /// without the QPACK dynamic table, and responses are decoded without one until then. The
    /// streams are opened (taking their IDs) at once.
    pub fn defer_settings(&mut self, enabled: bool) -> &mut Self {
        self.config.defer_settings = enabled;
        self
    }

    /// Indicates that the client supports HTTP/3 datagrams
    ///
    /// See: <https://www.rfc-editor.org/rfc/rfc9297#section-2.1.1>
    pub fn enable_datagram(&mut self, enabled: bool) -> &mut Self {
        self.config.settings.enable_datagram = enabled;
        self
    }

    /// Enables the extended CONNECT protocol required for various HTTP/3 extensions.
    pub fn enable_extended_connect(&mut self, value: bool) -> &mut Self {
        self.config.settings.enable_extended_connect = value;
        self
    }

    /// The configuration, its settings taken from the raw SETTINGS when given
    pub(super) fn config(&self) -> Config {
        let mut config = self.config.clone();
        if let Some(raw) = &config.raw_settings {
            config.settings = raw.into();
        }
        config
    }

    /// Create a new HTTP/3 client from a `quic` connection
    pub async fn build<C, O, B>(
        &mut self,
        quic: C,
    ) -> Result<(Connection<C, B>, SendRequest<O, B>), ConnectionError>
    where
        C: quic::Connection<B, OpenStreams = O>,
        O: quic::OpenStreams<B>,
        B: Buf,
    {
        let open = quic.opener();
        let shared = SharedState::default();

        let conn_state = Arc::new(shared);

        let inner = ConnectionInner::new(quic, conn_state.clone(), self.config()).await?;
        let send_request = SendRequest {
            open,
            conn_state,
            max_field_section_size: inner.config.settings.max_field_section_size,
            sender_count: Arc::new(AtomicUsize::new(1)),
            send_grease_frame: inner.config.send_grease_frame,
            _buf: PhantomData,
        };

        Ok((
            Connection {
                inner,
                sent_closing: None,
                recv_closing: None,
            },
            send_request,
        ))
    }
}
