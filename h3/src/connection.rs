use std::{
    collections::{HashMap, VecDeque},
    convert::TryFrom,
    marker::PhantomData,
    sync::Arc,
    task::{Context, Poll},
};

use bytes::{Buf, Bytes, BytesMut};
use futures_util::{future, ready};
use http::{HeaderMap, HeaderName};
use stream::WriteBuf;
use tokio::sync::{mpsc, oneshot};

#[cfg(feature = "tracing")]
use tracing::{instrument, warn};

use crate::{
    client::{PromisedPush, PushDelivery, PushedRequest, PushedResponse, RecvEvent},
    config::Config,
    error::{
        connection_error_creators::{
            CloseRawQuicConnection, CloseStream, HandleFrameStreamErrorOnRequestStream,
        },
        internal_error::{ErrorOrigin, InternalConnectionError},
        Code, ConnectionError, StreamError,
    },
    ext::{
        ControlFrame, ControlFrames, HeaderOrder, HeldFrames, UnknownStream, WebTransportStream,
    },
    frame::{FrameProtocolError, FrameStream, FrameStreamError},
    proto::{
        coding::Encode,
        frame::{self, Frame, PayloadLen},
        headers::Header,
        stream::StreamType,
        varint::VarInt,
    },
    qpack,
    quic::{self, RecvStream, SendStream, StreamErrorIncoming, StreamId},
    shared_state::{ConnectionState, PushEnd, PushPending, QpackStreamEnd, SharedState},
    stream::{self, AcceptRecvStream, AcceptedRecvStream, BufRecvStream, Queued, UniStreamHeader},
    webtransport::SessionId,
};

/// How many of the peer's unidirectional streams and control frames are recorded.
const PEER_RECORD_LIMIT: usize = 16;

/// How many payload bytes the peer's control frames recorded may hold.
const PEER_RECORD_BYTES: usize = 64 * 1024;

/// How many bytes of frames or instructions one of our unidirectional streams may hold that
/// the transport didn't take
const STREAM_BACKLOG: usize = 1 << 20;

#[allow(missing_docs)]
pub struct AcceptedStreams<C, B>
where
    C: quic::Connection<B>,
    B: Buf,
{
    #[allow(missing_docs)]
    pub wt_uni_streams: Vec<(SessionId, BufRecvStream<C::RecvStream, B>)>,
}

impl<B, C> Default for AcceptedStreams<C, B>
where
    C: quic::Connection<B>,
    B: Buf,
{
    fn default() -> Self {
        Self {
            wt_uni_streams: Default::default(),
        }
    }
}

struct QpackStreams<C, B>
where
    C: quic::Connection<B>,
    B: Buf,
{
    decoder_send: Option<C::SendStream>,
    decoder_recv: Option<AcceptedRecvStream<C::RecvStream, B>>,
    encoder_send: Option<C::SendStream>,
    encoder_recv: Option<AcceptedRecvStream<C::RecvStream, B>>,
}

/// A server push a client delivering pushes is pairing
enum PushPairing<R, B> {
    /// The promise was delivered: its response waits for the push stream
    Promised(oneshot::Sender<FrameStream<R, B>>),
    /// The push stream arrived before its promise
    Stream(FrameStream<R, B>),
}

#[allow(missing_docs)]
pub struct ConnectionInner<C, B>
where
    C: quic::Connection<B>,
    B: Buf,
{
    pub shared: Arc<SharedState>,
    /// TODO: breaking encapsulation just to see if we can get this to work, will fix before merging
    pub conn: C,
    control_send: C::SendStream,
    control_recv: Option<FrameStream<C::RecvStream, B>>,
    qpack_streams: QpackStreams<C, B>,
    /// Buffers incoming uni/recv streams which have yet to be claimed.
    ///
    /// This is opposed to discarding them by returning in `poll_accept_recv`, which may cause them to be missed by something else polling.
    ///
    /// See: <https://datatracker.ietf.org/doc/html/draft-ietf-webtrans-http3/#section-4.5>
    ///
    /// In WebTransport over HTTP/3, the client MAY send its SETTINGS frame, as well as
    /// multiple WebTransport CONNECT requests, WebTransport data streams and WebTransport
    /// datagrams, all within a single flight. As those can arrive out of order, a WebTransport
    /// server could be put into a situation where it receives a stream or a datagram without a
    /// corresponding session. Similarly, a client may receive a server-initiated stream or a
    /// datagram before receiving the CONNECT response headers from the server.To handle this
    /// case, WebTransport endpoints SHOULD buffer streams and datagrams until those can be
    /// associated with an established session. To avoid resource exhaustion, the endpoints
    /// MUST limit the number of buffered streams and datagrams. When the number of buffered
    /// streams is exceeded, a stream SHALL be closed by sending a RESET_STREAM and/or
    /// STOP_SENDING with the H3_WEBTRANSPORT_BUFFERED_STREAM_REJECTED error code. When the
    /// number of buffered datagrams is exceeded, a datagram SHALL be dropped. It is up to an
    /// implementation to choose what stream or datagram to discard.
    accepted_streams: AcceptedStreams<C, B>,
    pending_recv_streams: Vec<Option<AcceptRecvStream<C::RecvStream, B>>>,
    got_peer_settings: bool,
    peer_settings: Option<Vec<(u64, u64)>>,
    peer_uni_streams: Vec<(StreamId, u64)>,
    /// The first frames after SETTINGS on the peer's control stream
    peer_control_frames: Vec<ControlFrame>,
    /// Whether the next of those is recorded: none is once one was not
    recording_control_frames: bool,
    /// Receives every frame after SETTINGS on the peer's control stream
    control_frames_tx: Option<(mpsc::UnboundedSender<ControlFrame>, Arc<HeldFrames>)>,
    /// Receives the unidirectional streams of unknown types the peer opens
    unknown_streams_tx: Option<mpsc::UnboundedSender<UnknownStream<C::RecvStream>>>,
    /// Receives the WebTransport streams the peer opens
    webtransport_tx:
        Option<mpsc::UnboundedSender<WebTransportStream<C::BidiStream, C::RecvStream>>>,
    /// The server's bidirectional streams whose WEBTRANSPORT_STREAM signal is being read
    webtransport_bidi: Vec<FrameStream<C::BidiStream, B>>,
    /// Decoding with a QPACK dynamic table: the peer's encoder stream is read
    qpack_decoding: bool,
    /// Decoder-stream instructions being written
    decoder_queue: Queued,
    /// Encoding with the peer's QPACK dynamic table: its decoder stream is read
    qpack_encoding: bool,
    /// Encoder-stream instructions being written
    encoder_queue: Queued,
    /// The QPACK streams' types were written
    decoder_typed: bool,
    encoder_typed: bool,
    /// Control-stream frames being written after SETTINGS
    control_queue: Queued,
    /// The server's pushes being paired, by push ID
    pushes: HashMap<u64, PushPairing<C::RecvStream, B>>,
    /// Delivers the pushes paired
    pushes_tx: Option<mpsc::UnboundedSender<PushDelivery<C::RecvStream, B>>>,
    /// SETTINGS and the rest written on the unidirectional streams are held back until
    /// [`Self::start`]
    deferred: bool,
    pub(crate) handled_connection_error: Option<ConnectionError>,
    pub send_grease_frame: bool,
    // tells if the grease steam should be sent
    send_grease_stream_flag: bool,
    // step of the grease sending poll fn
    grease_step: GreaseStatus<C::SendStream, B>,
    pub config: Config,
}

impl<B, C> ConnectionState for ConnectionInner<C, B>
where
    C: quic::Connection<B>,
    B: Buf,
{
    fn shared_state(&self) -> &SharedState {
        &self.shared
    }
}

enum GreaseStatus<S, B>
where
    S: SendStream<B>,
    B: Buf,
{
    /// Grease stream is not started
    NotStarted(PhantomData<B>),
    /// Grease steam is started without data
    Started(Option<S>),
    /// Grease stream is started with data
    DataPrepared(Option<S>),
    /// Data is sent on grease stream
    DataSent(S),
    /// Grease stream is finished
    Finished,
}

impl<B, C> ConnectionInner<C, B>
where
    C: quic::Connection<B>,
    B: Buf,
{
    /// Sends the settings and initializes the control streams
    #[cfg_attr(feature = "tracing", instrument(skip_all, level = "trace"))]
    pub async fn send_control_stream_headers(&mut self) -> Result<(), ConnectionError> {
        #[cfg(test)]
        if !self.config.send_settings {
            return Ok(());
        }

        let settings = frame::Settings::try_from(self.config.clone()).map_err(|_err| {
            // TODO: converting a config to settings should never fail
            //       it should be impossible to construct a config which cannot be represented as settings
            self.handle_connection_error(InternalConnectionError::new(
                Code::H3_INTERNAL_ERROR,
                "error when creating settings frame".to_string(),
            ))
        })?;

        #[cfg(feature = "tracing")]
        tracing::debug!("Sending server settings: {:#x?}", settings);

        //= https://www.rfc-editor.org/rfc/rfc9114#section-3.2
        //# After the QUIC connection is
        //# established, a SETTINGS frame MUST be sent by each endpoint as the
        //# initial frame of their respective HTTP control stream.

        //= https://www.rfc-editor.org/rfc/rfc9114#section-6.2.1
        //# Each side MUST initiate a single control stream at the beginning of
        //# the connection and send its SETTINGS frame as the first frame on this
        //# stream.

        //= https://www.rfc-editor.org/rfc/rfc9114#section-7.2.4
        //# A SETTINGS frame MUST be sent as the first frame of
        //# each control stream (see Section 6.2.1) by each peer, and it MUST NOT
        //# be sent subsequently.

        //= https://www.rfc-editor.org/rfc/rfc9114#section-7.2.4
        //= type=implication
        //# SETTINGS frames MUST NOT be sent on any stream other than the control
        //# stream.

        //= https://www.rfc-editor.org/rfc/rfc9114#section-7.2.4.2
        //= type=implication
        //# Endpoints MUST NOT require any data to be received from
        //# the peer prior to sending the SETTINGS frame; settings MUST be sent
        //# as soon as the transport is ready to send data.

        let mut control_header = Vec::new();
        UniStreamHeader::Control(settings).encode(&mut control_header);
        if self.config.send_control_grease_frame {
            Frame::<B>::Grease.encode(&mut control_header);
        }
        if !self.config.control_frames.iter().all(|f| f.is_valid()) {
            return Err(self.handle_connection_error(InternalConnectionError::new(
                Code::H3_INTERNAL_ERROR,
                "a control frame value is not a valid variable-length integer".to_string(),
            )));
        }
        for frame in &self.config.control_frames {
            frame.encode(&mut control_header);
        }

        let mut decoder_send = Option::take(&mut self.qpack_streams.decoder_send);
        let mut encoder_send = Option::take(&mut self.qpack_streams.encoder_send);
        let lazy = self.config.qpack_lazy_stream_types;

        let control = stream::write_encoded(&mut self.control_send, &control_header);
        let decoder = async {
            if let Some(stream) = decoder_send.as_mut().filter(|_| !lazy) {
                let _ = stream::write(stream, WriteBuf::from(UniStreamHeader::Decoder)).await;
            }
        };
        let encoder = async {
            if let Some(stream) = encoder_send.as_mut().filter(|_| !lazy) {
                let _ = stream::write(stream, WriteBuf::from(UniStreamHeader::Encoder)).await;
            }
        };
        // The QPACK streams' types go out in the order the streams were opened.
        let control = if self.config.qpack_decoder_stream_first {
            future::join3(control, decoder, encoder).await.0
        } else {
            future::join3(control, encoder, decoder).await.0
        };

        self.qpack_streams.decoder_send = decoder_send;
        self.qpack_streams.encoder_send = encoder_send;

        match control {
            Ok(control) => Ok(control),
            Err(StreamErrorIncoming::ConnectionErrorIncoming { connection_error }) => {
                Err(self.handle_connection_error(connection_error))
            }
            Err(StreamErrorIncoming::StreamTerminated {
                error_code: err, ..
            }) => Err(self
                //= https://www.rfc-editor.org/rfc/rfc9114#section-6.2.1
                //# If either control
                //# stream is closed at any point, this MUST be treated as a connection
                //# error of type H3_CLOSED_CRITICAL_STREAM.
                .handle_connection_error(InternalConnectionError::new(
                    Code::H3_CLOSED_CRITICAL_STREAM,
                    format!(
                        "control stream was requested to stop sending with error code {}",
                        err
                    ),
                ))),
            Err(StreamErrorIncoming::Unknown(error)) => {
                Err(self.handle_connection_error(InternalConnectionError::new(
                    Code::H3_CLOSED_CRITICAL_STREAM,
                    format!("an error occurred on the control stream {}", error),
                )))
            }
        }
    }

    /// Initiates the connection and opens a control stream
    #[cfg_attr(feature = "tracing", instrument(skip_all, level = "trace"))]
    pub async fn new(
        mut conn: C,
        shared: Arc<SharedState>,
        config: Config,
    ) -> Result<Self, ConnectionError> {
        //= https://www.rfc-editor.org/rfc/rfc9114#section-6.2
        //# Endpoints SHOULD create the HTTP control stream as well as the
        //# unidirectional streams required by mandatory extensions (such as the
        //# QPACK encoder and decoder streams) first, and then create additional

        // start streams
        let control_send = future::poll_fn(|cx| conn.poll_open_send(cx)).await;
        let (qpack_encoder, qpack_decoder) = if config.qpack_decoder_stream_first {
            let decoder = future::poll_fn(|cx| conn.poll_open_send(cx)).await;
            (future::poll_fn(|cx| conn.poll_open_send(cx)).await, decoder)
        } else {
            (
                future::poll_fn(|cx| conn.poll_open_send(cx)).await,
                future::poll_fn(|cx| conn.poll_open_send(cx)).await,
            )
        };

        let control_send = match control_send {
            Err(StreamErrorIncoming::ConnectionErrorIncoming { connection_error }) => {
                return Err(conn.handle_quic_error_raw(connection_error));
            }
            Err(StreamErrorIncoming::StreamTerminated {
                error_code: err, ..
            }) => {
                return Err(
                    //= https://www.rfc-editor.org/rfc/rfc9114#section-6.2.1
                    //# If either control
                    //# stream is closed at any point, this MUST be treated as a connection
                    //# error of type H3_CLOSED_CRITICAL_STREAM.
                    conn.close_raw_connection_with_h3_error(InternalConnectionError::new(
                        Code::H3_CLOSED_CRITICAL_STREAM,
                        format!(
                            "control stream was requested to stop sending with error code {}",
                            err,
                        ),
                    )),
                );
            }
            Err(StreamErrorIncoming::Unknown(error)) => {
                return Err(
                    conn.close_raw_connection_with_h3_error(InternalConnectionError::new(
                        Code::H3_CLOSED_CRITICAL_STREAM,
                        format!("an error occurred on the control stream {}", error),
                    )),
                );
            }
            Ok(control_send) => control_send,
        };

        let qpack_streams = QpackStreams {
            decoder_send: qpack_decoder.ok(),
            decoder_recv: None,
            encoder_send: qpack_encoder.ok(),
            encoder_recv: None,
        };

        //= https://www.rfc-editor.org/rfc/rfc9114#section-6.2.1
        //= type=implication
        //# The
        //# sender MUST NOT close the control stream, and the receiver MUST NOT
        //# request that the sender close the control stream.
        let mut conn_inner = Self {
            shared,
            conn,
            control_send: control_send,
            control_recv: None,
            qpack_streams,
            handled_connection_error: None,
            pending_recv_streams: Vec::with_capacity(3),
            got_peer_settings: false,
            peer_settings: None,
            peer_uni_streams: Vec::new(),
            peer_control_frames: Vec::new(),
            recording_control_frames: true,
            control_frames_tx: None,
            unknown_streams_tx: None,
            webtransport_tx: None,
            webtransport_bidi: Vec::new(),
            qpack_decoding: config.settings.qpack_max_table_capacity > 0,
            decoder_queue: Queued::default(),
            qpack_encoding: config.qpack_encoder_capacity > 0,
            encoder_queue: Queued::default(),
            decoder_typed: !config.qpack_lazy_stream_types,
            encoder_typed: !config.qpack_lazy_stream_types,
            control_queue: Queued::default(),
            pushes: HashMap::new(),
            pushes_tx: None,
            deferred: config.defer_settings,
            send_grease_frame: config.send_grease_frame,
            // send grease stream if configured
            send_grease_stream_flag: config.send_grease_stream,
            config,
            accepted_streams: Default::default(),
            // start at first step
            grease_step: GreaseStatus::NotStarted(PhantomData),
        };
        conn_inner.apply_config();
        if !conn_inner.deferred {
            conn_inner.send_control_stream_headers().await?;
        }

        Ok(conn_inner)
    }

    /// Sets up the QPACK dynamic table use and the pushes tolerated as the configuration says
    fn apply_config(&mut self) {
        if self.qpack_decoding {
            let settings = &self.config.settings;
            self.shared.qpack().enable_decoding(
                usize::try_from(settings.qpack_max_table_capacity).unwrap_or(usize::MAX),
                usize::try_from(settings.qpack_blocked_streams).unwrap_or(usize::MAX),
            );
        }
        if let Some(max_push_id) = self
            .config
            .control_frames
            .iter()
            .rev()
            .find_map(|f| match f {
                ControlFrame::MaxPushId(id) => Some(*id),
                _ => None,
            })
        {
            self.shared.set_max_push_id(max_push_id);
        }
        self.shared.set_deliver_pushes(self.config.deliver_pushes);
        if self.qpack_encoding {
            let capacity = self.config.qpack_encoder_capacity;
            self.shared
                .qpack()
                .enable_encoding(usize::try_from(capacity).unwrap_or(usize::MAX));
        }
    }

    /// Sends what [`Config::defer_settings`] held back, configured by `config` in place of the
    /// connection's configuration: the SETTINGS and control frames, the QPACK streams' types
    /// and dynamic table use, and the reserved stream. Does nothing once they were sent.
    pub async fn start(&mut self, config: Config) -> Result<(), ConnectionError> {
        if !self.deferred {
            return Ok(());
        }
        self.deferred = false;
        // The QPACK streams took their IDs in the order the connection was built with.
        if config.qpack_decoder_stream_first != self.config.qpack_decoder_stream_first {
            std::mem::swap(
                &mut self.qpack_streams.decoder_send,
                &mut self.qpack_streams.encoder_send,
            );
        }
        self.qpack_decoding = config.settings.qpack_max_table_capacity > 0;
        self.qpack_encoding = config.qpack_encoder_capacity > 0;
        self.decoder_typed = !config.qpack_lazy_stream_types;
        self.encoder_typed = !config.qpack_lazy_stream_types;
        self.send_grease_frame = config.send_grease_frame;
        self.send_grease_stream_flag = config.send_grease_stream;
        self.config = config;
        self.apply_config();
        if self.qpack_encoding && self.got_peer_settings {
            let peer = self.settings();
            let (capacity, blocked) = (peer.qpack_max_table_capacity, peer.qpack_blocked_streams);
            self.shared.qpack().on_peer_settings(capacity, blocked);
        }
        self.send_control_stream_headers().await?;
        // Otherwise opened after the peer's next control frame, which may not come.
        if self.send_grease_stream_flag {
            future::poll_fn(|cx| self.poll_grease_stream(cx)).await;
        }
        Ok(())
    }

    /// Send GOAWAY with specified max_id, iff max_id is smaller than the previous one.
    #[cfg_attr(feature = "tracing", instrument(skip_all, level = "trace"))]
    pub async fn shutdown<T>(
        &mut self,
        sent_closing: &mut Option<T>,
        max_id: T,
    ) -> Result<(), ConnectionError>
    where
        T: From<VarInt> + PartialOrd<T> + Copy,
        VarInt: From<T>,
    {
        if let Some(sent_id) = sent_closing {
            if *sent_id <= max_id {
                return Ok(());
            }
        }

        *sent_closing = Some(max_id);
        self.set_closing();
        // A GOAWAY can't go ahead of the SETTINGS held back.
        if self.deferred {
            return Ok(());
        }

        // Frames queued for the control stream go first, and none may be half-written.
        let out = self.shared.control_out().split();
        self.control_queue.data.extend_from_slice(&out);
        if let Err(e) =
            future::poll_fn(|cx| self.control_queue.poll_write(&mut self.control_send, cx)).await
        {
            return Err(self.critical_stream_error(e, "control"));
        }

        //= https://www.rfc-editor.org/rfc/rfc9114#section-3.3
        //# When either endpoint chooses to close the HTTP/3
        //# connection, the terminating endpoint SHOULD first send a GOAWAY frame
        //# (Section 5.2) so that both endpoints can reliably determine whether
        //# previously sent frames have been processed and gracefully complete or
        //# terminate any necessary remaining tasks.
        match stream::write(&mut self.control_send, Frame::Goaway(max_id.into())).await {
            Ok(()) => Ok(()),
            Err(StreamErrorIncoming::ConnectionErrorIncoming { connection_error }) => {
                Err(self.handle_connection_error(connection_error))
            }
            Err(StreamErrorIncoming::StreamTerminated {
                error_code: err, ..
            }) => Err(self
                //= https://www.rfc-editor.org/rfc/rfc9114#section-6.2.1
                //# If either control
                //# stream is closed at any point, this MUST be treated as a connection
                //# error of type H3_CLOSED_CRITICAL_STREAM.
                .handle_connection_error(InternalConnectionError::new(
                    Code::H3_CLOSED_CRITICAL_STREAM,
                    format!(
                        "control stream was requested to stop sending with error code {}",
                        err
                    ),
                ))),
            Err(StreamErrorIncoming::Unknown(error)) => {
                Err(self.handle_connection_error(InternalConnectionError::new(
                    Code::H3_CLOSED_CRITICAL_STREAM,
                    format!("an error occurred on the control stream {}", error),
                )))
            }
        }
    }

    #[allow(missing_docs)]
    #[cfg_attr(feature = "tracing", instrument(skip_all, level = "trace"))]
    pub fn poll_accept_bi(
        &mut self,
        cx: &mut Context<'_>,
    ) -> Poll<Result<C::BidiStream, ConnectionError>> {
        let _ = self.poll_connection_error(cx)?;

        // Accept the request by accepting the next bidirectional stream
        // .into().into() converts the impl QuicError into crate::error::Error.
        // The `?` operator doesn't work here for some reason.
        self.conn
            .poll_accept_bidi(cx)
            .map_err(|e| self.handle_connection_error(e))
    }

    /// Polls incoming streams
    ///
    /// Accepted streams which are not control, decoder, or encoder streams are buffer in `accepted_recv_streams`
    #[cfg_attr(feature = "tracing", instrument(skip_all, level = "trace"))]
    pub fn poll_accept_recv(&mut self, cx: &mut Context<'_>) -> Result<(), ConnectionError> {
        let _ = self.poll_connection_error(cx)?;

        // Push streams taken once the pending streams are no longer borrowed
        let mut pushed = Vec::new();
        // Get all currently pending streams
        loop {
            match self
                .conn
                .poll_accept_recv(cx)
                .map_err(|e| self.handle_connection_error(e))?
            {
                Poll::Ready(stream) => self
                    .pending_recv_streams
                    .push(Some(AcceptRecvStream::new(stream))),
                Poll::Pending => break,
            }
        }

        for stream in self.pending_recv_streams.iter_mut().filter(|s| s.is_some()) {
            let resolved = match stream.as_mut().expect("this cannot be None").poll_type(cx) {
                Poll::Ready(Err(stream::PollTypeError::IncomingError(e))) => {
                    return Err(self.handle_connection_error(e));
                }
                Poll::Ready(Err(stream::PollTypeError::InternalError(e))) => {
                    return Err(self.handle_connection_error(e));
                }
                Poll::Ready(Err(stream::PollTypeError::EndOfStream)) =>
                //= https://www.rfc-editor.org/rfc/rfc9114#section-6.2
                //# A receiver MUST tolerate unidirectional streams being
                //# closed or reset prior to the reception of the unidirectional stream
                //# header.
                {
                    // remove the stream if it was closed before the header was received
                    let _ = stream.take();
                    continue;
                }
                Poll::Ready(Ok(())) => stream.take().expect("this cannot be None"),
                Poll::Pending => continue,
            };

            let (_, ty) = resolved.id_and_type();
            if self.peer_uni_streams.len() < PEER_RECORD_LIMIT {
                self.peer_uni_streams.push(resolved.id_and_type());
            }

            match resolved.into_stream() {
                //= https://www.rfc-editor.org/rfc/rfc9114#section-6.2.1
                //# Only one control stream per peer is permitted;
                //# receipt of a second stream claiming to be a control stream MUST be
                //# treated as a connection error of type H3_STREAM_CREATION_ERROR.
                AcceptedRecvStream::Control(mut s) => {
                    if self.control_recv.is_some() {
                        return Err(self.handle_connection_error(InternalConnectionError::new(
                            Code::H3_STREAM_CREATION_ERROR,
                            "got two control streams".to_string(),
                        )));
                    }
                    s.record_frame_types(PEER_RECORD_LIMIT);
                    s.keep_frames();
                    self.control_recv = Some(s);
                }
                enc @ AcceptedRecvStream::Encoder(_) => {
                    if let Some(_prev) = self.qpack_streams.encoder_recv.replace(enc) {
                        return Err(self.handle_connection_error(InternalConnectionError::new(
                            Code::H3_STREAM_CREATION_ERROR,
                            "got two encoder streams".to_string(),
                        )));
                    }
                }
                dec @ AcceptedRecvStream::Decoder(_) => {
                    if let Some(_prev) = self.qpack_streams.decoder_recv.replace(dec) {
                        return Err(self.handle_connection_error(InternalConnectionError::new(
                            Code::H3_STREAM_CREATION_ERROR,
                            "got two decoder streams".to_string(),
                        )));
                    }
                }
                AcceptedRecvStream::Push(push_id, stream) if self.shared.delivers_pushes() => {
                    pushed.push((push_id, stream));
                }
                //= https://www.rfc-editor.org/rfc/rfc9114#section-7.2.3
                //# The
                //# client SHOULD abort reading the stream with an error code of
                //# H3_REQUEST_CANCELLED.
                AcceptedRecvStream::Push(push_id, mut stream) if self.shared.accepts_pushes() => {
                    let id = stream.id();
                    stream.stop_sending(Code::H3_REQUEST_CANCELLED);
                    self.shared.qpack().cancel_stream(id.into_inner());
                    if let Err(error) = self.shared.push_stream(push_id, id) {
                        return Err(self.handle_connection_error(error));
                    }
                }
                // A stream no one receives any more is dropped, which stops it.
                AcceptedRecvStream::WebTransportUni(id, s) if self.webtransport_tx.is_some() => {
                    let (read, finished, stream) = s.into_parts();
                    if let Some(tx) = &self.webtransport_tx {
                        let _ = tx.send(WebTransportStream::Uni {
                            session_id: id.into_inner(),
                            read,
                            finished,
                            stream,
                        });
                    }
                }
                AcceptedRecvStream::WebTransportUni(id, s)
                    if self.config.settings.enable_webtransport =>
                {
                    // Store until someone else picks it up, like a webtransport session which is
                    // not yet established.
                    self.accepted_streams.wt_uni_streams.push((id, s))
                }

                //= https://www.rfc-editor.org/rfc/rfc9114#section-6.2.3
                //= type=implication
                //# Endpoints MUST NOT consider these streams to have any meaning upon
                //# receipt.
                AcceptedRecvStream::Unknown(stream) if self.unknown_streams_tx.is_some() => {
                    let (read, finished, stream) = stream.into_parts();
                    let unknown = UnknownStream {
                        ty,
                        read,
                        finished,
                        stream,
                    };
                    if let Some(Err(unsent)) =
                        self.unknown_streams_tx.as_ref().map(|tx| tx.send(unknown))
                    {
                        let mut stream = unsent.0.stream;
                        stream.stop_sending(Code::H3_STREAM_CREATION_ERROR.value());
                    }
                }
                AcceptedRecvStream::Unknown(mut stream) => {
                    //= https://www.rfc-editor.org/rfc/rfc9114#section-6.2
                    //# Recipients of unknown stream types MUST
                    //# either abort reading of the stream or discard incoming data without
                    //# further processing.

                    //= https://www.rfc-editor.org/rfc/rfc9114#section-6.2
                    //# If reading is aborted, the recipient SHOULD use
                    //# the H3_STREAM_CREATION_ERROR error code or a reserved error code
                    //# (Section 8.1).

                    //= https://www.rfc-editor.org/rfc/rfc9114#section-6.2
                    //= type=implication
                    //# The recipient MUST NOT consider unknown stream types
                    //# to be a connection error of any kind.

                    stream.stop_sending(Code::H3_STREAM_CREATION_ERROR.value());
                }
                _ => (),
            };
        }

        // Remove all None values
        self.pending_recv_streams.retain(|s| s.is_some());

        for (push_id, stream) in pushed {
            self.accept_push_stream(push_id, stream)?;
        }

        Ok(())
    }

    /// Takes the push stream `stream` for `push_id`: handed to its promise's response, or
    /// kept until the promise arrives.
    fn accept_push_stream(
        &mut self,
        push_id: u64,
        stream: FrameStream<C::RecvStream, B>,
    ) -> Result<(), ConnectionError> {
        let id = stream.id();
        //= https://www.rfc-editor.org/rfc/rfc9114#section-4.6
        //# A client MUST treat receipt of a push stream with a push ID that is greater than
        //# the maximum push ID as a connection error of type H3_ID_ERROR.
        if self.shared.max_push_id().map_or(true, |max| push_id > max) {
            return Err(self.handle_connection_error(InternalConnectionError::new(
                Code::H3_ID_ERROR,
                format!("push stream {id} with push ID {push_id} above MAX_PUSH_ID"),
            )));
        }
        //= https://www.rfc-editor.org/rfc/rfc9114#section-4.6
        //# If a push stream header includes a push ID that was used in another push stream
        //# header, the client MUST treat this as a connection error of type H3_ID_ERROR.
        match self.shared.push_stream(push_id, id) {
            Ok(true) => (),
            Ok(false) => {
                return Err(self.handle_connection_error(InternalConnectionError::new(
                    Code::H3_ID_ERROR,
                    format!("push stream {id} repeats push ID {push_id}"),
                )))
            }
            Err(error) => return Err(self.handle_connection_error(error)),
        }
        // The server cancelled the push before its promise arrived, or this client cancelled
        // it.
        if self.shared.take_server_cancelled(push_id) || self.shared.push_cancelled(push_id) {
            self.stop_push_stream(stream);
            return Ok(());
        }
        match self.pushes.remove(&push_id) {
            Some(PushPairing::Promised(response)) => {
                // The response was dropped: the push is cancelled.
                if let Err(stream) = response.send(stream) {
                    self.stop_push_stream(stream);
                }
            }
            Some(PushPairing::Stream(_)) => unreachable!("a repeated push ID fails above"),
            None => {
                self.pushes.insert(push_id, PushPairing::Stream(stream));
            }
        }
        Ok(())
    }

    /// Stops reading a push stream whose push is cancelled.
    fn stop_push_stream(&mut self, mut stream: FrameStream<C::RecvStream, B>) {
        stream.stop_sending(Code::H3_REQUEST_CANCELLED);
        self.shared.qpack().cancel_stream(stream.id().into_inner());
    }

    /// Pairs the promises the request streams decoded with their push streams, delivering
    /// them to [`Self::subscribe_pushes`]'s receiver in the order the streams saw them.
    fn poll_pushes(&mut self) {
        for pending in self.shared.take_pending_pushes() {
            match pending {
                PushPending::Promised {
                    push_id,
                    stream,
                    request,
                    size,
                } => {
                    let Some(tx) = &self.pushes_tx else {
                        // No receiver: cancelled as a client that delivers none cancels it.
                        self.shared.push_taken(size);
                        self.cancel_pairing(push_id, true);
                        continue;
                    };
                    let max_field_section_size = self.config.settings.max_field_section_size;
                    let response = match self.pushes.remove(&push_id) {
                        // Cancelled by the server before it was delivered: its response
                        // fails as one cancelled after, its promise delivered in band paired.
                        _ if self.shared.take_server_cancelled(push_id) => PushedResponse::awaited(
                            push_id,
                            oneshot::channel().1,
                            size,
                            self.shared.clone(),
                            max_field_section_size,
                        ),
                        Some(PushPairing::Stream(stream)) => PushedResponse::arrived(
                            push_id,
                            stream,
                            size,
                            self.shared.clone(),
                            max_field_section_size,
                        ),
                        _ => {
                            let (arrived, awaited) = oneshot::channel();
                            self.pushes.insert(push_id, PushPairing::Promised(arrived));
                            PushedResponse::awaited(
                                push_id,
                                awaited,
                                size,
                                self.shared.clone(),
                                max_field_section_size,
                            )
                        }
                    };
                    let promised = PushedRequest {
                        push_id,
                        stream,
                        request,
                        response,
                    };
                    // Dropped unreceived, the request cancels its push.
                    if tx.send(PushDelivery::Promised(promised)).is_err() {
                        self.pushes_tx = None;
                    }
                }
                PushPending::Cancel(push_id) => self.cancel_pairing(push_id, false),
                PushPending::Ended(stream) => {
                    if let Some(tx) = &self.pushes_tx {
                        let _ = tx.send(PushDelivery::Ended(stream));
                    }
                }
            }
        }
        // A response dropped before its push stream arrived cancelled its push.
        self.pushes
            .retain(|_, pairing| !matches!(pairing, PushPairing::Promised(tx) if tx.is_closed()));
    }

    /// Drops the pairing of `push_id`: its push stream, if it arrived, is stopped, else
    /// CANCEL_PUSH is sent when `cancel`.
    fn cancel_pairing(&mut self, push_id: u64, cancel: bool) {
        match self.pushes.remove(&push_id) {
            Some(PushPairing::Stream(stream)) => self.stop_push_stream(stream),
            Some(PushPairing::Promised(_)) => (),
            None if cancel => self
                .shared
                .send_control_frame(&ControlFrame::CancelPush(push_id)),
            None => (),
        }
    }

    /// The server cancelled `push_id` (CANCEL_PUSH): its response, if delivered, fails; its
    /// push stream, if it arrived, is stopped.
    pub(crate) fn push_cancelled(&mut self, push_id: u64) -> Result<(), InternalConnectionError> {
        //= https://www.rfc-editor.org/rfc/rfc9114#section-7.2.3
        //# If a CANCEL_PUSH frame is received that
        //# references a push ID greater than currently allowed on the
        //# connection, this MUST be treated as a connection error of type
        //# H3_ID_ERROR.
        if self.shared.max_push_id().map_or(true, |max| push_id > max) {
            return Err(InternalConnectionError::new(
                Code::H3_ID_ERROR,
                format!("CANCEL_PUSH with push ID {push_id} above MAX_PUSH_ID"),
            ));
        }
        match self.pushes.remove(&push_id) {
            Some(PushPairing::Promised(_)) => (),
            Some(PushPairing::Stream(stream)) => self.stop_push_stream(stream),
            None => self.shared.server_cancelled(push_id)?,
        }
        Ok(())
    }

    /// Receives the server's pushes as they are promised, when this client delivers them
    /// ([`crate::client::Builder::deliver_pushes`]), replacing any previous receiver.
    pub fn subscribe_pushes(&mut self) -> mpsc::UnboundedReceiver<PushDelivery<C::RecvStream, B>> {
        let (tx, rx) = mpsc::unbounded_channel();
        self.pushes_tx = Some(tx);
        rx
    }

    /// Receives the WebTransport streams the peer opens from now on, whether or not
    /// WebTransport was negotiated, replacing any previous receiver: unidirectional ones
    /// (and, on a client, the server's bidirectional ones) as the connection reads their
    /// headers.
    pub fn subscribe_webtransport(
        &mut self,
    ) -> mpsc::UnboundedReceiver<WebTransportStream<C::BidiStream, C::RecvStream>> {
        let (tx, rx) = mpsc::unbounded_channel();
        self.webtransport_tx = Some(tx);
        rx
    }

    /// Receives the unidirectional streams of types HTTP/3 doesn't know (reserved (GREASE)
    /// ones among them) the peer opens from now on, replacing any previous receiver, rather
    /// than stopping them (H3_STREAM_CREATION_ERROR), as RFC 9114 §6.2 lets a receiver
    /// either stop or ignore them.
    pub fn subscribe_unknown_streams(
        &mut self,
    ) -> mpsc::UnboundedReceiver<UnknownStream<C::RecvStream>> {
        let (tx, rx) = mpsc::unbounded_channel();
        self.unknown_streams_tx = Some(tx);
        rx
    }

    /// Whether WebTransport streams go to a subscriber ([`Self::subscribe_webtransport`])
    pub(crate) fn delivers_webtransport(&self) -> bool {
        self.webtransport_tx.is_some()
    }

    /// Accepts the server's bidirectional streams, which only WebTransport opens, and hands
    /// each to the subscriber once its WEBTRANSPORT_STREAM signal is read. Another first
    /// frame is a connection error.
    pub(crate) fn poll_webtransport_bidi(
        &mut self,
        cx: &mut Context<'_>,
    ) -> Result<(), ConnectionError> {
        while let Poll::Ready(stream) = self.poll_accept_bi(cx) {
            let mut stream = FrameStream::new(BufRecvStream::new(stream?));
            stream.expect_webtransport_signal();
            self.webtransport_bidi.push(stream);
        }
        let mut index = 0;
        while index < self.webtransport_bidi.len() {
            match self.webtransport_bidi[index].poll_next(cx) {
                Poll::Pending => index += 1,
                Poll::Ready(Ok(Some(Frame::WebTransportStream(session_id)))) => {
                    let stream = self.webtransport_bidi.swap_remove(index);
                    let (read, finished, stream) = stream.into_inner().into_parts();
                    if let Some(tx) = &self.webtransport_tx {
                        let _ = tx.send(WebTransportStream::Bidi {
                            session_id: session_id.into_inner(),
                            read,
                            finished,
                            stream,
                        });
                    }
                }
                // Ended or reset before its signal: only that stream ends.
                Poll::Ready(
                    Ok(None)
                    | Err(
                        FrameStreamError::UnexpectedEnd
                        | FrameStreamError::Quic(StreamErrorIncoming::StreamTerminated { .. }),
                    ),
                ) => {
                    drop(self.webtransport_bidi.swap_remove(index));
                }
                Poll::Ready(Err(FrameStreamError::Quic(
                    StreamErrorIncoming::ConnectionErrorIncoming { connection_error },
                ))) => return Err(self.handle_connection_error(connection_error)),
                Poll::Ready(_) => {
                    return Err(self.handle_connection_error(InternalConnectionError::new(
                        Code::H3_STREAM_CREATION_ERROR,
                        "client received a server-initiated bidirectional stream other than WebTransport"
                            .to_string(),
                    )));
                }
            }
        }
        Ok(())
    }

    /// Waits for the control stream to be received and reads subsequent frames.
    #[cfg_attr(feature = "tracing", instrument(skip_all, level = "trace"))]
    pub fn poll_control(
        &mut self,
        cx: &mut Context<'_>,
    ) -> Poll<Result<Frame<PayloadLen>, ConnectionError>> {
        // check if a connection error occurred on a stream
        let checked = match self.poll_connection_error(cx) {
            Poll::Ready(Err(error)) => Err(error),
            _ => self
                .poll_accept_recv(cx)
                .and_then(|()| self.poll_qpack(cx))
                .and_then(|()| self.poll_control_send(cx)),
        };
        // The peer closing the connection: the control-stream frames it sent before are read
        // first, as they arrived before its close.
        let closed = match checked {
            Err(error @ ConnectionError::Remote(_)) if self.control_recv.is_some() => Some(error),
            Err(error) => return Poll::Ready(Err(error)),
            Ok(()) => None,
        };

        let recv = {
            // TODO
            self.poll_pushes();
            if let Some(v) = &mut self.control_recv {
                v
            } else {
                // Try later
                return Poll::Pending;
            }
        };

        // A subscriber holding as many frames as it may: the stream is read on once it took
        // some.
        if self
            .control_frames_tx
            .as_ref()
            .is_some_and(|(tx, _)| tx.is_closed())
        {
            self.control_frames_tx = None;
        }
        if let Some((_, held)) = &self.control_frames_tx {
            if !held.poll_room(cx) {
                return match closed {
                    Some(error) => Poll::Ready(Err(error)),
                    None => Poll::Pending,
                };
            }
        }

        let polled = recv.poll_next(cx);
        for (ty, len, payload) in recv.take_frames() {
            if ty == frame::FrameType::SETTINGS.value() {
                continue;
            }
            let frame = ControlFrame::parse(ty, len, payload);
            // Applied before the frame is broadcast, so a subscriber woken by it finds the
            // push IDs it allows.
            if let ControlFrame::MaxPushId(max) = frame {
                if let Err(error) = self.shared.set_peer_max_push_id(max) {
                    return Poll::Ready(Err(self.handle_connection_error(error)));
                }
            }
            if self.recording_control_frames {
                let recorded: usize = self
                    .peer_control_frames
                    .iter()
                    .map(ControlFrame::size)
                    .sum();
                self.recording_control_frames = self.peer_control_frames.len() < PEER_RECORD_LIMIT
                    && recorded + frame.size() <= PEER_RECORD_BYTES;
                if self.recording_control_frames {
                    self.peer_control_frames.push(frame.clone());
                }
            }
            if let Some((tx, held)) = &self.control_frames_tx {
                held.hold(&frame);
                if let Err(unsent) = tx.send(frame) {
                    held.release(&unsent.0);
                }
            }
        }

        if let Some(error) = closed.filter(|_| !matches!(polled, Poll::Ready(Ok(Some(_))))) {
            return Poll::Ready(Err(error));
        }

        let res = match ready!(polled) {
            Err(FrameStreamError::Quic(StreamErrorIncoming::ConnectionErrorIncoming {
                connection_error,
            })) => return Poll::Ready(Err(self.handle_connection_error(connection_error))),
            Err(FrameStreamError::Quic(StreamErrorIncoming::StreamTerminated {
                error_code: err,
                ..
            })) =>
            //= https://www.rfc-editor.org/rfc/rfc9114#section-6.2.1
            //# If either control
            //# stream is closed at any point, this MUST be treated as a connection
            //# error of type H3_CLOSED_CRITICAL_STREAM.
            // TODO: Add Test, that reset also triggers this
            {
                return Poll::Ready(Err(self.handle_connection_error(
                    InternalConnectionError::new(
                        Code::H3_CLOSED_CRITICAL_STREAM,
                        format!("control stream was reset with error code {}", err),
                    ),
                )));
            }
            Err(FrameStreamError::Quic(StreamErrorIncoming::Unknown(error))) => {
                return Poll::Ready(Err(self.handle_connection_error(
                    InternalConnectionError::new(
                        Code::H3_CLOSED_CRITICAL_STREAM,
                        format!("an error occurred on the control stream {}", error),
                    ),
                )));
            }
            Err(FrameStreamError::UnexpectedEnd) =>
            //= https://www.rfc-editor.org/rfc/rfc9114#section-7.1
            //# When a stream terminates cleanly, if the last frame on the stream was
            //# truncated, this MUST be treated as a connection error of type
            //# H3_FRAME_ERROR.
            {
                return Poll::Ready(Err(self.handle_connection_error(
                    InternalConnectionError::new(
                        Code::H3_FRAME_ERROR,
                        "received incomplete frame".to_string(),
                    ),
                )));
            }
            Err(FrameStreamError::Proto(frame_error)) => {
                return Poll::Ready(Err(self.handle_connection_error(
                    InternalConnectionError::got_frame_error(frame_error),
                )));
            }
            Ok(None) =>
            //= https://www.rfc-editor.org/rfc/rfc9114#section-6.2.1
            //# If either control
            //# stream is closed at any point, this MUST be treated as a connection
            //# error of type H3_CLOSED_CRITICAL_STREAM.
            {
                return Poll::Ready(Err(self.handle_connection_error(
                    InternalConnectionError::new(
                        Code::H3_CLOSED_CRITICAL_STREAM,
                        "control stream was closed".to_string(),
                    ),
                )));
            }
            Ok(Some(Frame::Settings(settings))) => {
                if !self.got_peer_settings {
                    // Received settings frame

                    self.got_peer_settings = true;
                    self.peer_settings = Some(settings.iter().collect());
                    let settings_config: crate::config::Settings = (&settings).into();
                    if self.qpack_encoding {
                        self.shared.qpack().on_peer_settings(
                            settings_config.qpack_max_table_capacity,
                            settings_config.qpack_blocked_streams,
                        );
                        self.waker().wake();
                    }
                    self.set_settings(settings_config);

                    Frame::Settings(settings)
                } else {
                    //= https://www.rfc-editor.org/rfc/rfc9114#section-7.2.4
                    //# If an endpoint receives a second SETTINGS
                    //# frame on the control stream, the endpoint MUST respond with a
                    //# connection error of type H3_FRAME_UNEXPECTED.
                    return Poll::Ready(Err(self.handle_connection_error(
                        InternalConnectionError::new(
                            Code::H3_FRAME_UNEXPECTED,
                            "second settings frame received".to_string(),
                        ),
                    )));
                }
            }
            Ok(Some(frame)) if !self.got_peer_settings => {
                // We received a frame before the settings frame
                //= https://www.rfc-editor.org/rfc/rfc9114#section-6.2.1
                //# If the first frame of the control stream is any other frame
                //# type, this MUST be treated as a connection error of type
                //# H3_MISSING_SETTINGS.
                return Poll::Ready(Err(self.handle_connection_error(
                    InternalConnectionError::new(
                        Code::H3_MISSING_SETTINGS,
                        format!("received frame {:?} before settings", frame),
                    ),
                )));
            }
            Ok(Some(
                frame @ Frame::Goaway(_)
                | frame @ Frame::CancelPush(_)
                | frame @ Frame::MaxPushId(_),
            )) => {
                // handle these frames in client/server imples
                frame
            }
            Ok(Some(frame)) => {
                // All other frames are not allowed on the control stream
                // Unknown frames are not covered by the Frame enum and poll_next will just ignore them
                //= https://www.rfc-editor.org/rfc/rfc9114#section-7.2.1
                //= type=implication
                //# DATA frames MUST be associated with an HTTP request or response.

                //= https://www.rfc-editor.org/rfc/rfc9114#section-7.2.1
                //# If
                //# a DATA frame is received on a control stream, the recipient MUST
                //# respond with a connection error of type H3_FRAME_UNEXPECTED.

                //= https://www.rfc-editor.org/rfc/rfc9114#section-7.2.2
                //# If a HEADERS frame is received on a control stream, the recipient
                //# MUST respond with a connection error of type H3_FRAME_UNEXPECTED.
                return Poll::Ready(Err(self.handle_connection_error(
                    InternalConnectionError::new(
                        Code::H3_FRAME_UNEXPECTED,
                        format!("received unexpected frame {:?} on control stream", frame),
                    ),
                )));
            }
        };

        if self.send_grease_stream_flag {
            //= https://www.rfc-editor.org/rfc/rfc9114#section-6.2.3
            //# They MAY also be
            //# sent on connections where no data is currently being transferred.
            ready!(self.poll_grease_stream(cx));
        }

        Poll::Ready(Ok(res))
    }

    /// Reads the peer's QPACK encoder and decoder streams into the dynamic table states and
    /// writes the queued QPACK instructions, when a dynamic table is used.
    fn poll_qpack(&mut self, cx: &mut Context<'_>) -> Result<(), ConnectionError> {
        if self.qpack_decoding {
            self.poll_qpack_decoding(cx)?;
        }
        if self.qpack_encoding {
            self.poll_qpack_encoding(cx)?;
        }
        Ok(())
    }

    /// Reads the peer's encoder stream and writes our decoder stream.
    fn poll_qpack_decoding(&mut self, cx: &mut Context<'_>) -> Result<(), ConnectionError> {
        if let Some(AcceptedRecvStream::Encoder(stream)) = &mut self.qpack_streams.encoder_recv {
            let read: Result<(), ErrorOrigin> = loop {
                if stream.buf_mut().has_remaining() {
                    if let Err(e) = self.shared.qpack().on_encoder_stream(stream.buf_mut()) {
                        break Err(InternalConnectionError::new(
                            Code::QPACK_ENCODER_STREAM_ERROR,
                            format!("QPACK encoder stream: {}", e),
                        )
                        .into());
                    }
                }
                match stream.poll_read(cx) {
                    Poll::Pending => break Ok(()),
                    Poll::Ready(Ok(false)) => (),
                    Poll::Ready(Err(StreamErrorIncoming::ConnectionErrorIncoming {
                        connection_error,
                    })) => break Err(connection_error.into()),
                    //= https://www.rfc-editor.org/rfc/rfc9204#section-4.2
                    //# Closure of either unidirectional stream type MUST be treated as a
                    //# connection error of type H3_CLOSED_CRITICAL_STREAM.
                    Poll::Ready(Ok(true) | Err(_)) => {
                        break Err(InternalConnectionError::new(
                            Code::H3_CLOSED_CRITICAL_STREAM,
                            "QPACK encoder stream was closed".to_string(),
                        )
                        .into())
                    }
                }
            };
            read.map_err(|e| self.handle_connection_error(e))?;
        }

        let out = self.shared.qpack().decoder_out.split();
        if !out.is_empty() && !self.decoder_typed {
            StreamType::DECODER.encode(&mut self.decoder_queue.data);
            self.decoder_typed = true;
        }
        self.decoder_queue.data.extend_from_slice(&out);
        let Some(stream) = &mut self.qpack_streams.decoder_send else {
            if self.decoder_queue.data.is_empty() {
                return Ok(());
            }
            return Err(self.handle_connection_error(InternalConnectionError::new(
                Code::H3_INTERNAL_ERROR,
                "no QPACK decoder stream to write to".to_string(),
            )));
        };
        match self.decoder_queue.poll_write(stream, cx) {
            Poll::Ready(Err(e)) => Err(self.critical_stream_error(e, "QPACK decoder")),
            _ => self.backlog(self.decoder_queue.data.len(), "QPACK decoder"),
        }
    }

    /// Reads the peer's decoder stream and writes our encoder stream.
    fn poll_qpack_encoding(&mut self, cx: &mut Context<'_>) -> Result<(), ConnectionError> {
        if let Some(AcceptedRecvStream::Decoder(stream)) = &mut self.qpack_streams.decoder_recv {
            let read: Result<(), ErrorOrigin> = loop {
                if stream.buf_mut().has_remaining() {
                    if let Err(e) = self.shared.qpack().on_decoder_stream(stream.buf_mut()) {
                        break Err(InternalConnectionError::new(
                            Code::QPACK_DECODER_STREAM_ERROR,
                            format!("QPACK decoder stream: {}", e),
                        )
                        .into());
                    }
                }
                match stream.poll_read(cx) {
                    Poll::Pending => break Ok(()),
                    Poll::Ready(Ok(false)) => (),
                    Poll::Ready(Err(StreamErrorIncoming::ConnectionErrorIncoming {
                        connection_error,
                    })) => break Err(connection_error.into()),
                    //= https://www.rfc-editor.org/rfc/rfc9204#section-4.2
                    //# Closure of either unidirectional stream type MUST be treated as a
                    //# connection error of type H3_CLOSED_CRITICAL_STREAM.
                    Poll::Ready(Ok(true) | Err(_)) => {
                        break Err(InternalConnectionError::new(
                            Code::H3_CLOSED_CRITICAL_STREAM,
                            "QPACK decoder stream was closed".to_string(),
                        )
                        .into())
                    }
                }
            };
            read.map_err(|e| self.handle_connection_error(e))?;
        }

        let out = self.shared.qpack().encoder_out.split();
        if !out.is_empty() && !self.encoder_typed {
            StreamType::ENCODER.encode(&mut self.encoder_queue.data);
            self.encoder_typed = true;
        }
        self.encoder_queue.data.extend_from_slice(&out);
        let Some(stream) = &mut self.qpack_streams.encoder_send else {
            if self.encoder_queue.data.is_empty() {
                return Ok(());
            }
            return Err(self.handle_connection_error(InternalConnectionError::new(
                Code::H3_INTERNAL_ERROR,
                "no QPACK encoder stream to write to".to_string(),
            )));
        };
        match self.encoder_queue.poll_write(stream, cx) {
            Poll::Ready(Err(e)) => Err(self.critical_stream_error(e, "QPACK encoder")),
            _ => self.backlog(self.encoder_queue.data.len(), "QPACK encoder"),
        }
    }

    /// Fails the connection once `held` bytes wait to be written on our `stream` past
    /// [`STREAM_BACKLOG`]: the peer's flow control holds the stream back while it keeps causing
    /// more.
    fn backlog(&mut self, held: usize, stream: &str) -> Result<(), ConnectionError> {
        if held <= STREAM_BACKLOG {
            return Ok(());
        }
        Err(self.handle_connection_error(InternalConnectionError::new(
            Code::H3_EXCESSIVE_LOAD,
            format!("the {stream} stream holds {held} bytes the peer's flow control didn't take"),
        )))
    }

    /// Writes the control-stream frames streams queued. Those queued while the transport
    /// holds earlier ones back are left queued, where they count against the backlog a sender
    /// may queue past (see [`SharedState::send_raw_control_frame`]).
    fn poll_control_send(&mut self, cx: &mut Context<'_>) -> Result<(), ConnectionError> {
        // Queued frames wait for the SETTINGS held back to go ahead of them.
        if self.deferred {
            return Ok(());
        }
        loop {
            if self.control_queue.data.is_empty() {
                let out = self.shared.control_out().split();
                self.control_queue.data.extend_from_slice(&out);
            }
            match self.control_queue.poll_write(&mut self.control_send, cx) {
                Poll::Ready(Err(e)) => return Err(self.critical_stream_error(e, "control")),
                Poll::Ready(Ok(())) if self.shared.control_out().is_empty() => {
                    self.shared.set_control_in_flight(false);
                    return Ok(());
                }
                Poll::Ready(Ok(())) => {}
                Poll::Pending => {
                    self.shared.set_control_in_flight(true);
                    let held = self.control_queue.data.len() + self.shared.control_out().len();
                    return self.backlog(held, "control");
                }
            }
        }
    }

    /// The connection error for a failure writing one of our critical unidirectional streams
    fn critical_stream_error(
        &mut self,
        error: StreamErrorIncoming,
        stream: &str,
    ) -> ConnectionError {
        match error {
            StreamErrorIncoming::ConnectionErrorIncoming { connection_error } => {
                self.handle_connection_error(connection_error)
            }
            error => self.handle_connection_error(InternalConnectionError::new(
                Code::H3_CLOSED_CRITICAL_STREAM,
                format!("an error occurred on the {} stream: {:?}", stream, error),
            )),
        }
    }

    /// How the peer used its QPACK encoder stream so far, when decoding with a dynamic table.
    pub fn peer_qpack_encoder(&self) -> Option<crate::ext::QpackEncoderUse> {
        self.shared.qpack().encoder_use()
    }

    #[cfg_attr(feature = "tracing", instrument(skip_all, level = "trace"))]
    pub(crate) fn process_goaway<T>(
        &mut self,
        recv_closing: &mut Option<T>,
        id: VarInt,
    ) -> Result<(), ConnectionError>
    where
        T: From<VarInt> + Copy,
        VarInt: From<T>,
    {
        {
            //= https://www.rfc-editor.org/rfc/rfc9114#section-5.2
            //# An endpoint MAY send multiple GOAWAY frames indicating different
            //# identifiers, but the identifier in each frame MUST NOT be greater
            //# than the identifier in any previous frame, since clients might
            //# already have retried unprocessed requests on another HTTP connection.

            //= https://www.rfc-editor.org/rfc/rfc9114#section-5.2
            //# Like the server,
            //# the client MAY send subsequent GOAWAY frames so long as the specified
            //# push ID is no greater than any previously sent value.
            if let Some(prev_id) = recv_closing.map(VarInt::from) {
                if prev_id < id {
                    //= https://www.rfc-editor.org/rfc/rfc9114#section-5.2
                    //# Receiving a GOAWAY containing a larger identifier than previously
                    //# received MUST be treated as a connection error of type H3_ID_ERROR.
                    return Err(self.handle_connection_error(InternalConnectionError::new(
                        Code::H3_ID_ERROR,
                        format!(
                            "received a GoAway ({}) greater than the former one ({})",
                            id, prev_id
                        ),
                    )));
                }
            }
            *recv_closing = Some(id.into());
            self.set_closing();
            Ok(())
        }
    }

    // start grease stream and send data
    #[cfg_attr(feature = "tracing", instrument(skip_all, level = "trace"))]
    fn poll_grease_stream(&mut self, cx: &mut Context<'_>) -> Poll<()> {
        if matches!(self.grease_step, GreaseStatus::NotStarted(_)) {
            self.grease_step = match self.conn.poll_open_send(cx) {
                Poll::Pending => return Poll::Pending,
                Poll::Ready(Err(_)) => {
                    // could not create grease stream
                    // don't try again
                    self.send_grease_stream_flag = false;

                    #[cfg(feature = "tracing")]
                    warn!("grease stream creation failed with");

                    return Poll::Ready(());
                }
                Poll::Ready(Ok(stream)) => GreaseStatus::Started(Some(stream)),
            };
        };
        //= https://www.rfc-editor.org/rfc/rfc9114#section-6.2.3
        //# Stream types of the format 0x1f * N + 0x21 for non-negative integer
        //# values of N are reserved to exercise the requirement that unknown
        //# types be ignored.  These streams have no semantics, and they can be
        //# sent when application-layer padding is desired.  They MAY also be
        //# sent on connections where no data is currently being transferred.
        if let GreaseStatus::Started(stream) = &mut self.grease_step {
            if let Some(stream) = stream {
                if stream
                    .send_data((StreamType::grease(), Frame::Grease))
                    .is_err()
                {
                    self.send_grease_stream_flag = false;

                    #[cfg(feature = "tracing")]
                    warn!("write data on grease stream failed with");

                    return Poll::Ready(());
                };
            }
            self.grease_step = GreaseStatus::DataPrepared(stream.take());
        };

        if let GreaseStatus::DataPrepared(stream) = &mut self.grease_step {
            if let Some(stream) = stream {
                match stream.poll_ready(cx) {
                    Poll::Ready(Ok(_)) => (),
                    Poll::Pending => return Poll::Pending,
                    Poll::Ready(Err(_)) => {
                        // could not write grease frame
                        // don't try again
                        self.send_grease_stream_flag = false;

                        #[cfg(feature = "tracing")]
                        warn!("write data on grease stream failed with");

                        return Poll::Ready(());
                    }
                };
            }
            self.grease_step = GreaseStatus::DataSent(match stream.take() {
                Some(stream) => stream,
                None => {
                    // this should never happen
                    self.send_grease_stream_flag = false;
                    return Poll::Ready(());
                }
            });
        };

        //= https://www.rfc-editor.org/rfc/rfc9114#section-6.2.3
        //= type=implication
        //# When sending a reserved stream type,
        //# the implementation MAY either terminate the stream cleanly or reset
        //# it.
        if let GreaseStatus::DataSent(stream) = &mut self.grease_step {
            //= https://www.rfc-editor.org/rfc/rfc9114#section-6.2.3
            //= type=exception
            //# When resetting the stream, either the H3_NO_ERROR error code or
            //# a reserved error code (Section 8.1) SHOULD be used.
            // We terminate the stream cleanly so no H3_NO_ERROR is needed
            match stream.poll_finish(cx) {
                Poll::Ready(Ok(_)) => (),
                Poll::Pending => return Poll::Pending,
                Poll::Ready(Err(_)) => {
                    // could not finish grease stream
                    // don't try again
                    self.send_grease_stream_flag = false;

                    #[cfg(feature = "tracing")]
                    warn!("finish grease stream failed with");

                    return Poll::Ready(());
                }
            };
            self.grease_step = GreaseStatus::Finished;
        };

        // grease stream is closed
        // don't do another one
        self.send_grease_stream_flag = false;
        Poll::Ready(())
    }

    #[allow(missing_docs)]
    #[cfg_attr(feature = "tracing", instrument(skip_all, level = "trace"))]
    pub fn accepted_streams_mut(&mut self) -> &mut AcceptedStreams<C, B> {
        &mut self.accepted_streams
    }

    /// The peer's SETTINGS as received, every (identifier, value) pair in wire order.
    pub fn peer_settings_raw(&self) -> Option<&[(u64, u64)]> {
        self.peer_settings.as_deref()
    }

    /// The first unidirectional streams the peer opened, as (stream ID, stream type).
    pub fn peer_uni_streams(&self) -> &[(StreamId, u64)] {
        &self.peer_uni_streams
    }

    /// The types of the first frames on the peer's control stream, in wire order.
    pub fn peer_control_frame_types(&self) -> &[u64] {
        self.control_recv
            .as_ref()
            .map_or(&[], |control| control.frame_types())
    }

    /// The first frames after SETTINGS on the peer's control stream, in wire order.
    pub fn peer_control_frames(&self) -> &[ControlFrame] {
        &self.peer_control_frames
    }

    /// Receives every frame after SETTINGS on the peer's control stream as it is read from now
    /// on, with its whole payload, replacing any previous receiver: the stream is read only
    /// while the receiver takes them (see [`ControlFrames`]).
    pub fn subscribe_control_frames(&mut self) -> ControlFrames {
        let (tx, frames) = mpsc::unbounded_channel();
        let held = Arc::new(HeldFrames::default());
        self.control_frames_tx = Some((tx, Arc::clone(&held)));
        ControlFrames { frames, held }
    }
}

#[allow(missing_docs)]
pub struct RequestStream<S, B> {
    pub(super) stream: FrameStream<S, B>,
    pub(super) trailers: Option<Bytes>,
    pub(super) conn_state: Arc<SharedState>,
    pub(super) max_field_section_size: u64,
    send_grease_frame: bool,
    /// Cancels the stream's QPACK references unless it is read to its end
    pub(crate) qpack_end: Option<QpackStreamEnd>,
    /// Ends the pushes promised on the stream once it is dropped
    pub(crate) push_end: Option<PushEnd>,
    /// A PUSH_PROMISE (push ID, field section) being decoded
    promise: Option<(u64, Bytes)>,
    /// The promises decoded ahead of the frame a caller asked for (those before the
    /// response HEADERS, for one), in wire order, until a caller takes them
    promises: VecDeque<PromisedPush>,
}

/// The next frame of a request stream, or a PUSH_PROMISE delivered in its place
pub(crate) enum NextFrame {
    Frame(Option<Frame<PayloadLen>>),
    Promise(PromisedPush),
}

impl<S, B> RequestStream<S, B> {
    #[allow(missing_docs)]
    pub fn new(
        mut stream: FrameStream<S, B>,
        max_field_section_size: u64,
        conn_state: Arc<SharedState>,
        grease: bool,
    ) -> Self {
        stream.limit_field_sections(max_field_section_size);
        stream.refuse_control_frames();
        Self {
            stream,
            conn_state,
            max_field_section_size,
            trailers: None,
            send_grease_frame: grease,
            qpack_end: None,
            push_end: None,
            promise: None,
            promises: VecDeque::new(),
        }
    }

    /// Takes the promises decoded so far that no caller received in band: those ahead of
    /// the response HEADERS, in wire order.
    pub fn take_promises(&mut self) -> Vec<PromisedPush> {
        self.promises.drain(..).collect()
    }

    /// The stream was read to its end: no QPACK Stream Cancellation is due.
    fn ended(&mut self) {
        if let Some(end) = &mut self.qpack_end {
            end.ended = true;
        }
    }
}

impl QpackStreamEnd {
    /// Tracks `stream_id` when the connection decodes with a QPACK dynamic table.
    pub(crate) fn track(shared: &Arc<SharedState>, stream_id: StreamId) -> Option<Self> {
        shared.qpack().decoding().then(|| Self {
            shared: shared.clone(),
            stream_id: stream_id.into_inner(),
            ended: false,
        })
    }
}

impl<S, B> ConnectionState for RequestStream<S, B> {
    fn shared_state(&self) -> &SharedState {
        &self.conn_state
    }
}

impl<S, B> CloseStream for RequestStream<S, B> {}

impl<S, B> RequestStream<S, B>
where
    S: quic::RecvStream,
{
    /// The next frame. When this client sent MAX_PUSH_ID, a PUSH_PROMISE is decoded instead
    /// (acknowledging its QPACK references), recorded and cancelled or delivered; one
    /// delivered is kept for [`Self::take_promises`].
    pub(crate) fn poll_next_frame(
        &mut self,
        cx: &mut Context<'_>,
    ) -> Poll<Result<Option<Frame<PayloadLen>>, StreamError>> {
        loop {
            match ready!(self.poll_next_frame_or_promise(cx))? {
                NextFrame::Frame(frame) => return Poll::Ready(Ok(frame)),
                NextFrame::Promise(promise) => self.promises.push_back(promise),
            }
        }
    }

    /// The next frame, or a PUSH_PROMISE delivered to this client where it stood among the
    /// frames (see [`Self::poll_next_frame`]).
    fn poll_next_frame_or_promise(
        &mut self,
        cx: &mut Context<'_>,
    ) -> Poll<Result<NextFrame, StreamError>> {
        loop {
            if let Some((push_id, encoded)) = &self.promise {
                let stream = self.stream.id();
                let decoded = ready!(self.conn_state.poll_decode(
                    cx,
                    stream.into_inner(),
                    encoded,
                    self.max_field_section_size,
                ));
                let push_id = *push_id;
                self.promise = None;
                let fields = match decoded {
                    Ok(decoded) => decoded.fields,
                    Err(qpack::DecoderError::HeaderTooLong(_)) => Vec::new(),
                    Err(_) => {
                        return Poll::Ready(Err(self.handle_connection_error_on_stream(
                            InternalConnectionError::new(
                                Code::QPACK_DECOMPRESSION_FAILED,
                                "Failed to decode a push promise".to_string(),
                            ),
                        )));
                    }
                };
                match self.conn_state.promise(push_id, stream, fields) {
                    Ok(Some(request)) => {
                        return Poll::Ready(Ok(NextFrame::Promise(PromisedPush {
                            push_id,
                            request,
                        })))
                    }
                    Ok(None) => (),
                    Err(error) => {
                        return Poll::Ready(Err(self.handle_connection_error_on_stream(error)))
                    }
                }
            }

            match ready!(self.stream.poll_next(cx)) {
                Ok(Some(Frame::PushPromise(promise))) if self.conn_state.accepts_pushes() => {
                    self.promise = Some((promise.id, promise.encoded));
                }
                Ok(frame) => return Poll::Ready(Ok(NextFrame::Frame(frame))),
                Err(e) => {
                    //= https://www.rfc-editor.org/rfc/rfc9114#section-4.2.2
                    //# An HTTP/3 implementation MAY impose a limit on the maximum size of
                    //# the message header it will accept on an individual HTTP message.
                    if let FrameStreamError::Proto(FrameProtocolError::FieldSectionTooLarge {
                        ..
                    }) = e
                    {
                        self.stream.stop_sending(Code::H3_EXCESSIVE_LOAD);
                    }
                    return Poll::Ready(Err(self.handle_frame_stream_error_on_request_stream(e)));
                }
            }
        }
    }

    /// Receive some of the request body.
    #[cfg_attr(feature = "tracing", instrument(skip_all, level = "trace"))]
    pub fn poll_recv_data(
        &mut self,
        cx: &mut Context<'_>,
    ) -> Poll<Result<Option<impl Buf>, StreamError>> {
        loop {
            match ready!(self.poll_recv_event(cx)) {
                Ok(Some(RecvEvent::Data(data))) => return Poll::Ready(Ok(Some(data))),
                // Delivered to the connection's push receiver too.
                Ok(Some(RecvEvent::PushPromise(_))) => (),
                Ok(None) => return Poll::Ready(Ok(None)),
                Err(error) => return Poll::Ready(Err(error)),
            }
        }
    }

    /// Receive some of the body, or a PUSH_PROMISE where it stood among the body's DATA
    /// frames (one ahead of the HEADERS, decoded reading them, comes first).
    pub fn poll_recv_event(
        &mut self,
        cx: &mut Context<'_>,
    ) -> Poll<Result<Option<RecvEvent<impl Buf>>, StreamError>> {
        if let Some(promise) = self.promises.pop_front() {
            return Poll::Ready(Ok(Some(RecvEvent::PushPromise(promise))));
        }
        if !self.stream.has_data() {
            match ready!(self.poll_next_frame_or_promise(cx)) {
                Err(error) => return Poll::Ready(Err(error)),
                Ok(NextFrame::Promise(promise)) => {
                    return Poll::Ready(Ok(Some(RecvEvent::PushPromise(promise))));
                }
                Ok(NextFrame::Frame(None)) => {
                    self.ended();
                    return Poll::Ready(Ok(None));
                }
                Ok(NextFrame::Frame(Some(Frame::Headers(encoded)))) => {
                    self.trailers = Some(encoded);
                    // Received trailers, no more data expected
                    return Poll::Ready(Ok(None));
                }
                Ok(NextFrame::Frame(Some(Frame::Data { .. }))) => (),
                Ok(NextFrame::Frame(Some(other_frame))) => {
                    //= https://www.rfc-editor.org/rfc/rfc9114#section-4.1
                    //# Receipt of an invalid sequence of frames MUST be treated as a
                    //# connection error of type H3_FRAME_UNEXPECTED.

                    //= https://www.rfc-editor.org/rfc/rfc9114#section-7.2.3
                    //# Receiving a
                    //# CANCEL_PUSH frame on a stream other than the control stream MUST be
                    //# treated as a connection error of type H3_FRAME_UNEXPECTED.

                    //= https://www.rfc-editor.org/rfc/rfc9114#section-7.2.4
                    //# If an endpoint receives a SETTINGS frame on a different
                    //# stream, the endpoint MUST respond with a connection error of type
                    //# H3_FRAME_UNEXPECTED.

                    //= https://www.rfc-editor.org/rfc/rfc9114#section-7.2.6
                    //# A client MUST treat a GOAWAY frame on a stream other than
                    //# the control stream as a connection error of type H3_FRAME_UNEXPECTED.

                    //= https://www.rfc-editor.org/rfc/rfc9114#section-7.2.7
                    //# The MAX_PUSH_ID frame is always sent on the control stream.  Receipt
                    //# of a MAX_PUSH_ID frame on any other stream MUST be treated as a
                    //# connection error of type H3_FRAME_UNEXPECTED.

                    return Poll::Ready(Err(self.handle_connection_error_on_stream(
                        InternalConnectionError::new(
                            Code::H3_FRAME_UNEXPECTED,
                            format!("unexpected frame: {:?}", other_frame),
                        ),
                    )));
                }
            };
        }

        self.stream
            .poll_data(cx)
            .map_ok(|data| data.map(RecvEvent::Data))
            .map_err(|error| self.handle_frame_stream_error_on_request_stream(error))
    }

    /// Poll receive trailers.
    #[cfg_attr(feature = "tracing", instrument(skip_all, level = "trace"))]
    pub fn poll_recv_trailers(
        &mut self,
        cx: &mut Context<'_>,
    ) -> Poll<Result<Option<HeaderMap>, StreamError>> {
        self.poll_recv_trailers_with_order(cx)
            .map_ok(|trailers| trailers.map(|(trailers, _)| trailers))
    }

    /// Poll receive trailers and their fields' names in the order the trailer section
    /// carries them, repeats included.
    #[cfg_attr(feature = "tracing", instrument(skip_all, level = "trace"))]
    pub fn poll_recv_trailers_with_order(
        &mut self,
        cx: &mut Context<'_>,
    ) -> Poll<Result<Option<(HeaderMap, HeaderOrder)>, StreamError>> {
        let trailers = if let Some(encoded) = self.trailers.take() {
            encoded
        } else {
            match ready!(self.poll_next_frame(cx)) {
                Err(error) => return Poll::Ready(Err(error)),
                Ok(None) => {
                    self.ended();
                    return Poll::Ready(Ok(None));
                }
                Ok(Some(Frame::Headers(encoded))) => encoded,
                Ok(Some(other_frame)) => {
                    //= https://www.rfc-editor.org/rfc/rfc9114#section-4.1
                    //# Receipt of an invalid sequence of frames MUST be treated as a
                    //# connection error of type H3_FRAME_UNEXPECTED.

                    //= https://www.rfc-editor.org/rfc/rfc9114#section-7.2.3
                    //# Receiving a
                    //# CANCEL_PUSH frame on a stream other than the control stream MUST be
                    //# treated as a connection error of type H3_FRAME_UNEXPECTED.

                    //= https://www.rfc-editor.org/rfc/rfc9114#section-7.2.4
                    //# If an endpoint receives a SETTINGS frame on a different
                    //# stream, the endpoint MUST respond with a connection error of type
                    //# H3_FRAME_UNEXPECTED.

                    //= https://www.rfc-editor.org/rfc/rfc9114#section-7.2.6
                    //# A client MUST treat a GOAWAY frame on a stream other than
                    //# the control stream as a connection error of type H3_FRAME_UNEXPECTED.

                    //= https://www.rfc-editor.org/rfc/rfc9114#section-7.2.7
                    //# The MAX_PUSH_ID frame is always sent on the control stream.  Receipt
                    //# of a MAX_PUSH_ID frame on any other stream MUST be treated as a
                    //# connection error of type H3_FRAME_UNEXPECTED.
                    return Poll::Ready(Err(self.handle_connection_error_on_stream(
                        InternalConnectionError::new(
                            Code::H3_FRAME_UNEXPECTED,
                            format!("unexpected frame: {:?}", other_frame),
                        ),
                    )));
                }
            }
        };

        if !self.stream.is_eos() {
            // Get the trailing frame. After trailers no known frame is allowed.
            // But there still can be unknown frames.
            //= https://www.rfc-editor.org/rfc/rfc9114#section-4.1
            //# Receipt of an invalid sequence of frames MUST be treated as a
            //# connection error of type H3_FRAME_UNEXPECTED.

            match self.poll_next_frame(cx) {
                Poll::Ready(Err(error)) => return Poll::Ready(Err(error)),
                Poll::Ready(Ok(Some(trailing_frame))) => {
                    // Received a known frame after trailers -> fail.
                    return Poll::Ready(Err(self.handle_connection_error_on_stream(
                        InternalConnectionError::new(
                            Code::H3_FRAME_UNEXPECTED,
                            format!("unexpected frame: {:?}", trailing_frame),
                        ),
                    )));
                }
                // Stream is finished no problematic frames received
                Poll::Ready(Ok(None)) => (),
                Poll::Pending => {
                    // save the trailers and try again.
                    self.trailers = Some(trailers);
                    return Poll::Pending;
                }
            }
        }

        let decoded = match self.conn_state.poll_decode(
            cx,
            self.stream.id().into_inner(),
            &trailers,
            self.max_field_section_size,
        ) {
            Poll::Ready(decoded) => decoded,
            Poll::Pending => {
                self.trailers = Some(trailers);
                return Poll::Pending;
            }
        };
        self.ended();
        let qpack::Decoded { fields, .. } = match decoded {
            //= https://www.rfc-editor.org/rfc/rfc9114#section-4.2.2
            //# An HTTP/3 implementation MAY impose a limit on the maximum size of
            //# the message header it will accept on an individual HTTP message.
            Err(qpack::DecoderError::HeaderTooLong(cancel_size)) => {
                return Poll::Ready(Err(StreamError::HeaderTooBig {
                    actual_size: cancel_size,
                    max_size: self.max_field_section_size,
                }));
            }
            Ok(decoded) => decoded,
            Err(_e) => {
                return Poll::Ready(Err(self.handle_connection_error_on_stream(
                    InternalConnectionError {
                        code: Code::QPACK_DECOMPRESSION_FAILED,
                        message: "Failed to decode trailers".to_string(),
                    },
                )))
            }
        };

        let order = fields
            .iter()
            .filter_map(|field| HeaderName::from_bytes(&field.name).ok())
            .collect();

        Poll::Ready(Ok(Some((
            Header::try_from(fields)
                .map_err(|_e| {
                    self.stop_sending(Code::H3_MESSAGE_ERROR);
                    StreamError::StreamError {
                        code: Code::H3_MESSAGE_ERROR,
                        reason: "malformed request".to_string(),
                    }
                })?
                .into_fields(),
            HeaderOrder(order),
        ))))
    }

    #[allow(missing_docs)]
    #[cfg_attr(feature = "tracing", instrument(skip_all, level = "trace"))]
    pub fn stop_sending(&mut self, err_code: Code) {
        self.stream.stop_sending(err_code);
    }
}

impl<S, B> RequestStream<S, B>
where
    S: quic::SendStream<B>,
    B: Buf,
{
    /// Send some data on the response body.
    #[cfg_attr(feature = "tracing", instrument(skip_all, level = "trace"))]
    pub async fn send_data(&mut self, buf: B) -> Result<(), StreamError> {
        let frame = Frame::Data(buf);

        stream::write(&mut self.stream, frame)
            .await
            .map_err(|e| self.handle_quic_stream_error(e))?;
        Ok(())
    }

    /// Send a set of trailers to end the request.
    #[cfg_attr(feature = "tracing", instrument(skip_all, level = "trace"))]
    pub async fn send_trailers(&mut self, trailers: HeaderMap) -> Result<(), StreamError> {
        self.send_trailers_with_order(trailers, HeaderOrder::default())
            .await
    }

    /// Send a set of trailers to end the request, their fields in `order`.
    #[cfg_attr(feature = "tracing", instrument(skip_all, level = "trace"))]
    pub async fn send_trailers_with_order(
        &mut self,
        trailers: HeaderMap,
        order: HeaderOrder,
    ) -> Result<(), StreamError> {
        //= https://www.rfc-editor.org/rfc/rfc9114#section-4.2
        //= type=TODO
        //# Characters in field names MUST be
        //# converted to lowercase prior to their encoding.
        let mut block = BytesMut::new();

        let mut trailers = Header::trailer(trailers);
        trailers.set_order(order);
        let max_mem_size = self.settings().max_field_section_size;
        let mem_size = self
            .conn_state
            .encode(
                self.stream.send_id().into_inner(),
                trailers,
                &mut block,
                max_mem_size,
            )
            .map_err(|_e| {
                self.handle_connection_error_on_stream(InternalConnectionError {
                    code: Code::H3_INTERNAL_ERROR,
                    message: "Failed to encode trailers".to_string(),
                })
            })?;

        //= https://www.rfc-editor.org/rfc/rfc9114#section-4.2.2
        //# An implementation that
        //# has received this parameter SHOULD NOT send an HTTP message header
        //# that exceeds the indicated size, as the peer will likely refuse to
        //# process it.
        //= https://www.rfc-editor.org/rfc/rfc9114#section-7.2.4.2
        //# An HTTP implementation MUST NOT send frames or requests that would be
        //# invalid based on its current understanding of the peer's settings.

        if mem_size > max_mem_size {
            return Err(StreamError::HeaderTooBig {
                actual_size: mem_size,
                max_size: max_mem_size,
            });
        }

        stream::write(&mut self.stream, Frame::Headers(block.freeze()))
            .await
            .map_err(|e| self.handle_quic_stream_error(e))?;

        Ok(())
    }

    /// Stops a stream with an error code
    #[cfg_attr(feature = "tracing", instrument(skip_all, level = "trace"))]
    pub fn stop_stream(&mut self, code: Code) {
        self.stream.reset(code.into());
    }

    /// Stops a stream with an error code, the data sent so far still delivered: with
    /// RESET_STREAM_AT, where the peer can receive it
    #[cfg_attr(feature = "tracing", instrument(skip_all, level = "trace"))]
    pub fn stop_stream_at_sent(&mut self, code: Code) {
        self.stream.reset_at_sent(code.into());
    }

    #[allow(missing_docs)]
    #[cfg_attr(feature = "tracing", instrument(skip_all, level = "trace"))]
    pub async fn finish(&mut self) -> Result<(), StreamError> {
        self.send_grease().await?;

        future::poll_fn(|cx| self.stream.poll_finish(cx))
            .await
            .map_err(|e| self.handle_quic_stream_error(e))
    }

    /// Sends the connection's grease frame, if this stream still owes it.
    pub(crate) async fn send_grease(&mut self) -> Result<(), StreamError> {
        if self.send_grease_frame {
            // send a grease frame once per Connection
            //= https://www.rfc-editor.org/rfc/rfc9114#section-7.2.8
            //= type=implication
            //# Frame types of the format 0x1f * N + 0x21 for non-negative integer
            //# values of N are reserved to exercise the requirement that unknown
            //# types be ignored (Section 9).  These frames have no semantics, and
            //# they MAY be sent on any stream where frames are allowed to be sent.
            stream::write(&mut self.stream, Frame::Grease)
                .await
                .map_err(|e| self.handle_quic_stream_error(e))?;
            self.send_grease_frame = false;
        }
        Ok(())
    }
}

impl<S, B> RequestStream<S, B>
where
    S: quic::BidiStream<B>,
    B: Buf,
{
    #[cfg_attr(feature = "tracing", instrument(skip_all, level = "trace"))]
    pub(crate) fn split(
        self,
    ) -> (
        RequestStream<S::SendStream, B>,
        RequestStream<S::RecvStream, B>,
    ) {
        let (send, recv) = self.stream.split();

        (
            RequestStream {
                stream: send,
                trailers: None,
                conn_state: self.conn_state.clone(),
                max_field_section_size: 0,
                send_grease_frame: self.send_grease_frame,
                qpack_end: None,
                push_end: None,
                promise: None,
                promises: VecDeque::new(),
            },
            RequestStream {
                stream: recv,
                trailers: self.trailers,
                conn_state: self.conn_state,
                max_field_section_size: self.max_field_section_size,
                send_grease_frame: self.send_grease_frame,
                qpack_end: self.qpack_end,
                push_end: self.push_end,
                promise: self.promise,
                promises: self.promises,
            },
        )
    }
}
