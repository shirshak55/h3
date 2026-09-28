//! Builder of HTTP/3 server connections.
//!
//! Use this struct to create a new [`Connection`].
//! Settings for the [`Connection`] can be provided here.
//!
//! # Example
//!
//! ```rust
//! fn doc<C,B>(conn: C)
//! where
//! C: h3::quic::Connection<B>,
//! B: bytes::Buf,
//! {
//!     let mut server_builder = h3::server::builder();
//!     // Set the maximum header size
//!     server_builder.max_field_section_size(1000);
//!     // do not send grease types
//!     server_builder.send_grease(false);
//!     // Build the Connection
//!     let mut h3_conn = server_builder.build(conn);
//! }
//! ```

use std::{collections::HashSet, result::Result, sync::Arc};

use bytes::Buf;

use tokio::sync::mpsc;

use crate::{
    config::Config,
    connection::ConnectionInner,
    error::ConnectionError,
    quic::{self},
    shared_state::SharedState,
};

use super::connection::Connection;

/// Create a builder of HTTP/3 server connections
///
/// This function creates a [`Builder`] that carries settings that can
/// be shared between server connections.
pub fn builder() -> Builder {
    Builder::new()
}

/// Builder of HTTP/3 server connections.
pub struct Builder {
    pub(crate) config: Config,
}

impl Builder {
    /// Creates a new [`Builder`] with default settings.
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

    /// Send grease values to the Client.
    /// See [setting](https://www.rfc-editor.org/rfc/rfc9114.html#settings-parameters), [frame](https://www.rfc-editor.org/rfc/rfc9114.html#frame-reserved) and [stream](https://www.rfc-editor.org/rfc/rfc9114.html#stream-grease) for more information.
    #[inline]
    pub fn send_grease(&mut self, value: bool) -> &mut Self {
        self.config.send_grease = value;
        self.config.send_grease_frame = value;
        self.config.send_grease_stream = value;
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

    /// Indicates to the peer that WebTransport is supported.
    ///
    /// See: [establishing a webtransport session](https://datatracker.ietf.org/doc/html/draft-ietf-webtrans-http3/#section-3.1)
    ///
    ///
    /// **Server**:
    /// Supporting for webtransport also requires setting `enable_extended_connect` `enable_datagram`
    /// and `max_webtransport_sessions`.
    #[inline]
    pub fn enable_webtransport(&mut self, value: bool) -> &mut Self {
        self.config.settings.enable_webtransport = value;
        self
    }

    /// Enables the extended CONNECT protocol required for various HTTP/3 extensions.
    pub fn enable_extended_connect(&mut self, value: bool) -> &mut Self {
        self.config.settings.enable_extended_connect = value;
        self
    }

    /// Limits the maximum number of WebTransport sessions
    pub fn max_webtransport_sessions(&mut self, value: u64) -> &mut Self {
        self.config.settings.max_webtransport_sessions = value;
        self
    }

    /// Indicates that the client or server supports HTTP/3 datagrams
    ///
    /// See: <https://www.rfc-editor.org/rfc/rfc9297#section-2.1.1>
    pub fn enable_datagram(&mut self, value: bool) -> &mut Self {
        self.config.settings.enable_datagram = value;
        self
    }
}

impl Builder {
    /// Build an HTTP/3 connection from a QUIC connection
    ///
    /// This method creates a [`Connection`] instance with the settings in the [`Builder`].
    pub async fn build<C, B>(&self, conn: C) -> Result<Connection<C, B>, ConnectionError>
    where
        C: quic::Connection<B>,
        B: Buf,
    {
        let (sender, receiver) = mpsc::unbounded_channel();
        let shared = SharedState::default();

        Ok(Connection {
            inner: ConnectionInner::new(conn, Arc::new(shared), self.config.clone()).await?,
            max_field_section_size: self.config.settings.max_field_section_size,
            request_end_send: sender,
            request_end_recv: receiver,
            ongoing_streams: HashSet::new(),
            sent_closing: None,
            recv_closing: None,
            last_accepted_stream: None,
        })
    }
}
