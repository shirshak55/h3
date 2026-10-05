//! HTTP/3 server connection
//!
//! The [`Connection`] struct manages a connection from the side of the HTTP/3 server

use std::{
    collections::HashSet,
    future::poll_fn,
    option::Option,
    result::Result,
    task::{ready, Context, Poll},
};

use bytes::Buf;
use quic::RecvStream;
use quic::StreamId;
use tokio::sync::mpsc;

use crate::{
    connection::ConnectionInner,
    error::{internal_error::InternalConnectionError, Code, ConnectionError},
    frame::FrameStream,
    proto::{
        frame::{Frame, PayloadLen},
        push::PushId,
    },
    quic::{self, SendStream as _},
    shared_state::{ConnectionState, QpackStreamEnd, SharedState},
    stream::BufRecvStream,
};

#[cfg(feature = "tracing")]
use tracing::{instrument, trace};

use super::{push::PushOpener, request::RequestResolver};

/// Sends frames on a server's control stream (see [`Connection::control_sender`]).
#[derive(Clone)]
pub struct ControlSender(std::sync::Arc<SharedState>);

impl ControlSender {
    /// [`Connection::send_control_frame`]
    pub fn send(&self, frame: crate::ext::ControlFrame) -> Result<(), crate::error::StreamError> {
        self.0.send_raw_control_frame(&frame)
    }

    /// Resolves once the control-stream frames queued so far reached the transport, which
    /// takes them as the client's flow control lets it. [`Connection::accept`] writes them.
    pub async fn written(&self) {
        poll_fn(|cx| self.0.poll_control_written(cx)).await
    }
}

/// Server connection driver
///
/// The [`Connection`] struct manages a connection from the side of the HTTP/3 server
///
/// Create a new Instance with [`Connection::new()`].
/// Accept incoming requests with [`Connection::accept()`].
/// And shutdown a connection with [`Connection::shutdown()`].
pub struct Connection<C, B>
where
    C: quic::Connection<B>,
    B: Buf,
{
    /// TODO: temporarily break encapsulation for `WebTransportSession`
    pub inner: ConnectionInner<C, B>,
    pub(super) max_field_section_size: u64,
    // List of all incoming streams that are currently running.
    pub(super) ongoing_streams: HashSet<StreamId>,
    // Let the streams tell us when they are no longer running.
    pub(super) request_end_recv: mpsc::UnboundedReceiver<StreamId>,
    pub(super) request_end_send: mpsc::UnboundedSender<StreamId>,
    // Has a GOAWAY frame been sent? If so, this StreamId is the last we are willing to accept.
    pub(super) sent_closing: Option<StreamId>,
    // Has a GOAWAY frame been received? If so, this is PushId the last the remote will accept.
    pub(super) recv_closing: Option<PushId>,
    // The id of the last stream received by this connection.
    pub(super) last_accepted_stream: Option<StreamId>,
}

impl<C, B> ConnectionState for Connection<C, B>
where
    C: quic::Connection<B>,
    B: Buf,
{
    fn shared_state(&self) -> &SharedState {
        &self.inner.shared
    }
}

impl<C, B> Connection<C, B>
where
    C: quic::Connection<B>,
    B: Buf,
{
    /// Create a new HTTP/3 server connection with default settings
    ///
    /// Use a custom [`super::builder::Builder`] with [`super::builder::builder()`] to create a connection
    /// with different settings.
    /// Provide a Connection which implements [`quic::Connection`].
    #[cfg_attr(feature = "tracing", instrument(skip_all, level = "trace"))]
    pub async fn new(conn: C) -> Result<Self, ConnectionError> {
        super::builder::builder().build(conn).await
    }
}

#[cfg(feature = "i-implement-a-third-party-backend-and-opt-into-breaking-changes")]
/// Impls for extension implementation which are not stable
impl<C, B> Connection<C, B>
where
    C: quic::Connection<B>,
    B: Buf,
{
    #[cfg(feature = "i-implement-a-third-party-backend-and-opt-into-breaking-changes")]
    /// Create a [`RequestResolver`] to handle an incoming request.
    pub fn create_resolver(&self, stream: FrameStream<C::BidiStream, B>) -> RequestResolver<C, B> {
        self.create_resolver_internal(stream)
    }

    /// Polls the Connection and accepts an incoming request_streams
    #[cfg(feature = "i-implement-a-third-party-backend-and-opt-into-breaking-changes")]
    pub fn poll_accept_request_stream(
        &mut self,
        cx: &mut Context<'_>,
    ) -> Poll<Result<Option<C::BidiStream>, ConnectionError>> {
        self.poll_accept_request_stream_internal(cx)
    }
}

impl<C, B> Connection<C, B>
where
    C: quic::Connection<B>,
    B: Buf,
{
    /// Accept an incoming request.
    ///
    /// This method returns a [`RequestResolver`] which can be used to read the request and send the response.
    /// This method will return `None` when the connection receives a GOAWAY frame and all requests have been completed.
    #[cfg_attr(feature = "tracing", instrument(skip_all, level = "trace"))]
    pub async fn accept(&mut self) -> Result<Option<RequestResolver<C, B>>, ConnectionError> {
        // Accept the incoming stream
        let stream = match poll_fn(|cx| self.poll_accept_request_stream_internal(cx)).await? {
            Some(s) => FrameStream::new(BufRecvStream::new(s)),
            None => {
                // We always send a last GoAway frame to the client, so it knows which was the last
                // non-rejected request.
                self.shutdown(0).await?;
                return Ok(None);
            }
        };

        let resolver = self.create_resolver_internal(stream);

        // send the grease frame only once
        self.inner.send_grease_frame = false;

        Ok(Some(resolver))
    }

    fn create_resolver_internal(
        &self,
        mut stream: FrameStream<C::BidiStream, B>,
    ) -> RequestResolver<C, B> {
        stream.limit_field_sections(self.max_field_section_size);
        stream.refuse_control_frames();
        let qpack_end = QpackStreamEnd::track(&self.inner.shared, stream.send_id());
        RequestResolver {
            request_end: RequestEnd {
                request_end: self.request_end_send.clone(),
                stream_id: stream.send_id(),
            },
            frame_stream: stream,
            send_grease_frame: self.inner.send_grease_frame,
            max_field_section_size: self.max_field_section_size,
            shared: self.inner.shared.clone(),
            qpack_end,
        }
    }

    /// The peer's SETTINGS as received: every (identifier, value) pair in wire order, unknown
    /// and reserved (GREASE) identifiers included. `None` until the SETTINGS frame is read.
    pub fn peer_settings_raw(&self) -> Option<&[(u64, u64)]> {
        self.inner.peer_settings_raw()
    }

    /// The (stream ID, stream type) of the first 16 unidirectional streams the peer opened, in
    /// the order their types were read, reserved (GREASE) types included.
    pub fn peer_uni_streams(&self) -> &[(StreamId, u64)] {
        self.inner.peer_uni_streams()
    }

    /// The types of the first 16 frames on the peer's control stream, in wire order, unknown and
    /// reserved (GREASE) types included.
    pub fn peer_control_frame_types(&self) -> &[u64] {
        self.inner.peer_control_frame_types()
    }

    /// The first frames after SETTINGS on the client's control stream (up to 16, with up to
    /// 64 KiB of payloads), in wire order and with their contents: PRIORITY_UPDATE (request
    /// and push variants), MAX_PUSH_ID, CANCEL_PUSH, GOAWAY and reserved (GREASE) or other
    /// unknown frames.
    pub fn peer_control_frames(&self) -> &[crate::ext::ControlFrame] {
        self.inner.peer_control_frames()
    }

    /// Receives every frame after SETTINGS on the client's control stream as
    /// [`Connection::accept`] reads it, from now on (a PRIORITY_UPDATE when it arrives, for
    /// one), replacing any previous receiver. The stream is read only while the receiver takes
    /// them (see [`crate::ext::ControlFrames`]).
    pub fn subscribe_control_frames(&mut self) -> crate::ext::ControlFrames {
        self.inner.subscribe_control_frames()
    }

    /// Receives the unidirectional WebTransport streams the client opens from now on, as
    /// [`Connection::accept`] reads their headers, whether or not WebTransport was
    /// negotiated, replacing any previous receiver. Its bidirectional ones come from
    /// [`super::RequestResolver::resolve_stream`].
    pub fn subscribe_webtransport(
        &mut self,
    ) -> tokio::sync::mpsc::UnboundedReceiver<
        crate::ext::WebTransportStream<C::BidiStream, C::RecvStream>,
    > {
        self.inner.subscribe_webtransport()
    }

    /// How the client used its QPACK encoder stream so far: the dynamic table capacities it set,
    /// its inserts, and the field sections that referenced the table or waited for it. `None`
    /// unless this server advertises a dynamic table ([`super::Builder::qpack_max_table_capacity`]),
    /// as the encoder stream is only read then.
    pub fn peer_qpack_encoder(&self) -> Option<crate::ext::QpackEncoderUse> {
        self.inner.peer_qpack_encoder()
    }

    /// A handle to push on this connection: allocating push IDs under the client's
    /// MAX_PUSH_ID, opening push streams and cancelling pushes. The client's CANCEL_PUSH
    /// frames come through [`Connection::subscribe_control_frames`].
    pub fn push_opener(&self) -> PushOpener<C::OpenStreams, B> {
        PushOpener::new(
            self.inner.conn.opener(),
            self.inner.shared.clone(),
            self.request_end_send.clone(),
        )
    }

    /// Sends `frame` on the control stream as it is, changing none of this server's state: a
    /// reserved (GREASE) or unknown frame, for instance relaying one another peer sent (a
    /// GOAWAY goes through [`Connection::shutdown`], which rejects the requests it refuses).
    /// Fails once the connection failed, if a value doesn't fit a variable-length integer, or
    /// while the frames queued before and not written yet, as the client's flow control holds
    /// the control stream back, hold 64 KiB or more (H3_EXCESSIVE_LOAD). The connection is
    /// driven by [`Connection::accept`], which writes it.
    pub fn send_control_frame(
        &self,
        frame: crate::ext::ControlFrame,
    ) -> Result<(), crate::error::StreamError> {
        self.inner.shared.send_raw_control_frame(&frame)
    }

    /// A handle sending frames on the control stream as [`Connection::send_control_frame`]
    /// does, from any task, which tells when those sent reached the transport.
    pub fn control_sender(&self) -> ControlSender {
        ControlSender(self.inner.shared.clone())
    }

    /// Initiate a graceful shutdown, accepting `max_request` potentially still in-flight past
    /// the requests accepted: the GOAWAY sent names the first request stream after them, and
    /// requests from it on are rejected (H3_REQUEST_REJECTED)
    ///
    /// See [connection shutdown](https://www.rfc-editor.org/rfc/rfc9114.html#connection-shutdown) for more information.
    #[cfg_attr(feature = "tracing", instrument(skip_all, level = "trace"))]
    pub async fn shutdown(&mut self, max_requests: usize) -> Result<(), ConnectionError> {
        let max_id = match self.last_accepted_stream {
            Some(id) => id + (max_requests + 1),
            None => StreamId::FIRST_REQUEST + max_requests,
        };

        self.inner.shutdown(&mut self.sent_closing, max_id).await
    }

    /// Initiate a graceful shutdown with a GOAWAY naming `id`, which may name a request stream
    /// accepted already: requests from it on are rejected (H3_REQUEST_REJECTED) as they arrive,
    /// and those accepted are the application's to leave unprocessed
    #[cfg_attr(feature = "tracing", instrument(skip_all, level = "trace"))]
    pub async fn shutdown_at(&mut self, id: StreamId) -> Result<(), ConnectionError> {
        self.inner.shutdown(&mut self.sent_closing, id).await
    }

    /// Accepts an incoming bidirectional stream.
    ///
    /// This could be either a *Request* or a *WebTransportBiStream*, the first frame's type
    /// decides.
    #[cfg_attr(feature = "tracing", instrument(skip_all, level = "trace"))]
    fn poll_accept_request_stream_internal(
        &mut self,
        cx: &mut Context<'_>,
    ) -> Poll<Result<Option<C::BidiStream>, ConnectionError>> {
        let _ = self.poll_control(cx)?;
        let _ = self.poll_requests_completion(cx);
        loop {
            let conn = self.inner.poll_accept_bi(cx)?;
            return match conn {
                Poll::Pending => {
                    let done = if !self.inner.config.end_after_goaway {
                        false
                    } else if conn.is_pending() {
                        self.recv_closing.is_some() && self.poll_requests_completion(cx).is_ready()
                    } else {
                        self.poll_requests_completion(cx).is_ready()
                    };

                    if done {
                        Poll::Ready(Ok(None))
                    } else {
                        // Wait for all the requests to be finished, request_end_recv will wake
                        // us on each request completion.
                        Poll::Pending
                    }
                }
                Poll::Ready(mut s) => {
                    // When the connection is in a graceful shutdown procedure, reject all
                    // incoming requests not belonging to the grace interval. It's possible that
                    // some acceptable request streams arrive after rejected requests.
                    if let Some(max_id) = self.sent_closing {
                        if s.send_id() >= max_id {
                            s.stop_sending(Code::H3_REQUEST_REJECTED.value());
                            s.reset(Code::H3_REQUEST_REJECTED.value());
                            if self.inner.config.end_after_goaway
                                && self.poll_requests_completion(cx).is_ready()
                            {
                                break Poll::Ready(Ok(None));
                            }
                            continue;
                        }
                    }
                    self.last_accepted_stream = Some(s.send_id());
                    self.ongoing_streams.insert(s.send_id());
                    Poll::Ready(Ok(Some(s)))
                }
            };
        }
    }

    #[cfg_attr(feature = "tracing", instrument(skip_all, level = "trace"))]
    pub(crate) fn poll_control(
        &mut self,
        cx: &mut Context<'_>,
    ) -> Poll<Result<(), ConnectionError>> {
        while (self.poll_next_control(cx)?).is_ready() {}
        Poll::Pending
    }

    #[cfg_attr(feature = "tracing", instrument(skip_all, level = "trace"))]
    pub(crate) fn poll_next_control(
        &mut self,
        cx: &mut Context<'_>,
    ) -> Poll<Result<Frame<PayloadLen>, ConnectionError>> {
        let frame = ready!(self.inner.poll_control(cx))?;

        match &frame {
            Frame::Settings(_setting) => {
                #[cfg(feature = "tracing")]
                trace!("Got settings > {:?}", _setting);
                ()
            }
            &Frame::Goaway(id) => self.inner.process_goaway(&mut self.recv_closing, id)?,
            //= https://www.rfc-editor.org/rfc/rfc9114#section-7.2.7
            //# A MAX_PUSH_ID frame cannot reduce the maximum push
            //# ID; receipt of a MAX_PUSH_ID frame that contains a smaller value than
            //# previously received MUST be treated as a connection error of type
            //# H3_ID_ERROR.
            // Applied in `poll_control`, ahead of the frame's broadcast.
            Frame::MaxPushId(_) => (),
            //= https://www.rfc-editor.org/rfc/rfc9114#section-7.2.3
            //# If a server receives a CANCEL_PUSH frame for a push
            //# ID that has not yet been mentioned by a PUSH_PROMISE frame, this MUST
            //# be treated as a connection error of type H3_ID_ERROR.
            &Frame::CancelPush(id) => {
                if !self.inner.shared.push_id_promised(id.0) {
                    return Poll::Ready(Err(self.inner.handle_connection_error(
                        InternalConnectionError::new(
                            Code::H3_ID_ERROR,
                            format!("CANCEL_PUSH for push ID {} never promised", id.0),
                        ),
                    )));
                }
            }

            //= https://www.rfc-editor.org/rfc/rfc9114#section-7.2.5
            //# A server MUST treat the
            //# receipt of a PUSH_PROMISE frame as a connection error of type
            //# H3_FRAME_UNEXPECTED.
            frame => {
                return Poll::Ready(Err(self.inner.handle_connection_error(
                    InternalConnectionError::new(
                        Code::H3_FRAME_UNEXPECTED,
                        format!("on server control stream: {:?}", frame),
                    ),
                )));
            }
        }
        Poll::Ready(Ok(frame))
    }

    #[cfg_attr(feature = "tracing", instrument(skip_all, level = "trace"))]
    fn poll_requests_completion(&mut self, cx: &mut Context<'_>) -> Poll<()> {
        loop {
            match self.request_end_recv.poll_recv(cx) {
                // The channel is closed
                Poll::Ready(None) => return Poll::Ready(()),
                // A request has completed
                Poll::Ready(Some(id)) => {
                    self.ongoing_streams.remove(&id);
                }
                Poll::Pending => {
                    if self.ongoing_streams.is_empty() {
                        // Tell the caller there is not more ongoing requests.
                        // Still, the completion of future requests will wake us.
                        return Poll::Ready(());
                    } else {
                        return Poll::Pending;
                    }
                }
            }
        }
    }
}

impl<C, B> Drop for Connection<C, B>
where
    C: quic::Connection<B>,
    B: Buf,
{
    #[cfg_attr(feature = "tracing", instrument(skip_all, level = "trace"))]
    fn drop(&mut self) {
        self.inner.close_connection(
            Code::H3_NO_ERROR,
            "Connection was closed by the server".to_string(),
        );
    }
}

//= https://www.rfc-editor.org/rfc/rfc9114#section-6.1
//= type=TODO
//# In order to
//# permit these streams to open, an HTTP/3 server SHOULD configure non-
//# zero minimum values for the number of permitted streams and the
//# initial stream flow-control window.

//= https://www.rfc-editor.org/rfc/rfc9114#section-6.1
//= type=TODO
//# So as to not unnecessarily limit
//# parallelism, at least 100 request streams SHOULD be permitted at a
//# time.

pub(super) struct RequestEnd {
    pub(super) request_end: mpsc::UnboundedSender<StreamId>,
    pub(super) stream_id: StreamId,
}
