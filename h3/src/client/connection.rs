//! Client implementation of the HTTP/3 protocol

use std::{
    marker::PhantomData,
    sync::{atomic::AtomicUsize, Arc},
    task::{Context, Poll},
};

use bytes::{Buf, Bytes, BytesMut};
use futures_util::future;
use http::request;

#[cfg(feature = "tracing")]
use tracing::{info, instrument, trace};

use crate::{
    connection::{self, ConnectionInner},
    error::{
        connection_error_creators::{convert_to_connection_error, CloseStream},
        internal_error::InternalConnectionError,
        Code, ConnectionError, StreamError,
    },
    frame::FrameStream,
    proto::{frame::Frame, headers::Header, push::PushId},
    quic::{self, SendStream as _, StreamId},
    shared_state::{ConnectionState, PushEnd, QpackStreamEnd, SharedState},
    stream::{self, BufRecvStream},
};

use super::{push::PushDelivery, stream::RequestStream};

/// HTTP/3 request sender
///
/// [`send_request()`] initiates a new request and will resolve when it is ready to be sent
/// to the server. Then a [`RequestStream`] will be returned to send a request body (for
/// POST, PUT methods) and receive a response. After the whole body is sent, it is necessary
/// to call [`RequestStream::finish()`] to let the server know the request transfer is complete.
/// This includes the cases where no body is sent at all.
///
/// This struct is cloneable so multiple requests can be sent concurrently.
///
/// Existing instances are atomically counted internally, so whenever all of them have been
/// dropped, the connection will be automatically closed with HTTP/3 connection error code
/// `HTTP_NO_ERROR = 0`.
///
/// # Examples
///
/// ## Sending a request with no body
///
/// ```rust
/// # use h3::{quic, client::*};
/// # use http::{Request, Response};
/// # use bytes::Buf;
/// # async fn doc<T,B>(mut send_request: SendRequest<T, B>) -> Result<(), Box<dyn std::error::Error>>
/// # where
/// #     T: quic::OpenStreams<B>,
/// #     B: Buf,
/// # {
/// // Prepare the HTTP request to send to the server
/// let request = Request::get("https://www.example.com/").body(())?;
///
/// // Send the request to the server
/// let mut req_stream: RequestStream<_, _> = send_request.send_request(request).await?;
/// // Don't forget to end up the request by finishing the send stream.
/// req_stream.finish().await?;
/// // Receive the response
/// let response: Response<()> = req_stream.recv_response().await?;
/// // Process the response...
/// # Ok(())
/// # }
/// # pub fn main() {}
/// ```
///
/// ## Sending a request with a body and trailers
///
/// ```rust
/// # use h3::{quic, client::*};
/// # use http::{Request, Response, HeaderMap};
/// # use bytes::{Buf, Bytes};
/// # async fn doc<T,B>(mut send_request: SendRequest<T, Bytes>) -> Result<(), Box<dyn std::error::Error>>
/// # where
/// #     T: quic::OpenStreams<Bytes>,
/// # {
/// // Prepare the HTTP request to send to the server
/// let request = Request::get("https://www.example.com/").body(())?;
///
/// // Send the request to the server
/// let mut req_stream = send_request.send_request(request).await?;
/// // Send some data
/// req_stream.send_data("body".into()).await?;
/// // Prepare the trailers
/// let mut trailers = HeaderMap::new();
/// trailers.insert("trailer", "value".parse()?);
/// // Send them and finish the send stream
/// req_stream.send_trailers(trailers).await?;
/// // We don't need to finish the send stream, as `send_trailers()` did it for us
///
/// // Receive the response.
/// let response = req_stream.recv_response().await?;
/// // Process the response...
/// # Ok(())
/// # }
/// # pub fn main() {}
/// ```
///
/// [`send_request()`]: struct.SendRequest.html#method.send_request
/// [`RequestStream`]: struct.RequestStream.html
/// [`RequestStream::finish()`]: struct.RequestStream.html#method.finish
pub struct SendRequest<T, B>
where
    T: quic::OpenStreams<B>,
    B: Buf,
{
    pub(super) open: T,
    pub(super) conn_state: Arc<SharedState>,
    pub(super) max_field_section_size: u64, // maximum size for a header we receive
    // counts instances of SendRequest to close the connection when the last is dropped.
    pub(super) sender_count: Arc<AtomicUsize>,
    pub(super) _buf: PhantomData<fn(B)>,
    pub(super) send_grease_frame: bool,
    /// See [`SendRequest::send_after_goaway`]
    pub(super) after_goaway: bool,
}

impl<T, B> ConnectionState for SendRequest<T, B>
where
    T: quic::OpenStreams<B>,
    B: Buf,
{
    fn shared_state(&self) -> &SharedState {
        &self.conn_state
    }
}

impl<T, B> CloseStream for SendRequest<T, B>
where
    T: quic::OpenStreams<B>,
    B: Buf,
{
}

impl<T, B> SendRequest<T, B>
where
    T: quic::OpenStreams<B>,
    B: Buf,
{
    /// Send an HTTP/3 request to the server
    #[cfg_attr(feature = "tracing", instrument(skip_all, level = "trace"))]
    pub async fn send_request(
        &mut self,
        req: http::Request<()>,
    ) -> Result<RequestStream<T::BidiStream, B>, StreamError> {
        if !self.after_goaway {
            if let Some(error) = self.check_peer_connection_closing() {
                return Err(error);
            };
        }

        let (parts, _) = req.into_parts();
        let request::Parts {
            method,
            uri,
            headers,
            extensions,
            ..
        } = parts;
        let order = extensions.get::<crate::ext::HeaderOrder>().cloned();
        let pseudo_order = extensions.get::<crate::ext::PseudoOrder>().cloned();
        let mut headers = Header::request(method, uri, headers, extensions).map_err(|_e| {
            self.handle_connection_error_on_stream(InternalConnectionError {
                code: Code::H3_INTERNAL_ERROR,
                message: "Failed to build request headers".to_string(),
            })
        })?;
        if let Some(order) = order {
            headers.set_order(order);
        }
        if let Some(pseudo_order) = pseudo_order {
            headers.set_pseudo_order(pseudo_order);
        }

        //= https://www.rfc-editor.org/rfc/rfc9114#section-4.1
        //= type=implication
        //# A
        //# client MUST send only a single request on a given stream.
        let mut stream = future::poll_fn(|cx| self.open.poll_open_bidi(cx))
            .await
            .map_err(|e| self.handle_quic_stream_error(e))?;

        //= https://www.rfc-editor.org/rfc/rfc9114#section-4.2
        //= type=TODO
        //# Characters in field names MUST be
        //# converted to lowercase prior to their encoding.

        //= https://www.rfc-editor.org/rfc/rfc9114#section-4.2.1
        //= type=TODO
        //# To allow for better compression efficiency, the Cookie header field
        //# ([COOKIES]) MAY be split into separate field lines, each with one or
        //# more cookie-pairs, before compression.

        let mut block = BytesMut::new();
        let peer_max_field_section_size = self.settings().max_field_section_size;
        let mem_size = self
            .conn_state
            .encode(
                stream.send_id().into_inner(),
                headers,
                &mut block,
                peer_max_field_section_size,
            )
            .map_err(|_e| {
                self.handle_connection_error_on_stream(InternalConnectionError {
                    code: Code::H3_INTERNAL_ERROR,
                    message: "Failed to encode headers".to_string(),
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
        if mem_size > peer_max_field_section_size {
            return Err(StreamError::HeaderTooBig {
                actual_size: mem_size,
                max_size: peer_max_field_section_size,
            });
        }

        stream::write(&mut stream, Frame::Headers(block.freeze()))
            .await
            .map_err(|e| self.handle_quic_stream_error(e))?;

        let qpack_end = QpackStreamEnd::track(&self.conn_state, stream.send_id());
        let push_end = PushEnd::track(&self.conn_state, stream.send_id());
        let mut request_stream = RequestStream {
            inner: connection::RequestStream::new(
                FrameStream::new(BufRecvStream::new(stream)),
                self.max_field_section_size,
                self.conn_state.clone(),
                self.send_grease_frame,
            ),
        };
        request_stream.inner.qpack_end = qpack_end;
        request_stream.inner.push_end = push_end;
        // send the grease frame only once
        self.send_grease_frame = false;
        Ok(request_stream)
    }
}

impl<T, B> SendRequest<T, B>
where
    T: quic::OpenStreams<B>,
    B: Buf,
{
    /// Send a PRIORITY_UPDATE (RFC 9218) for the request stream `stream_id` on the control
    /// stream, with the Priority Field Value `priority` (e.g. `u=0, i`), for instance mirroring
    /// one a client sent for the request forwarded on `stream_id`. The connection driver writes
    /// it. The stream may be one this client has not opened yet. Fails once the connection
    /// failed, or while the control stream holds back as many frames as it may queue (see
    /// [`Self::send_control_frame`]).
    pub fn send_priority_update(
        &self,
        stream_id: StreamId,
        priority: impl Into<Bytes>,
    ) -> Result<(), StreamError> {
        if let Some(error) = self.get_conn_error() {
            return Err(StreamError::ConnectionError(convert_to_connection_error(
                error,
            )));
        }
        //= https://www.rfc-editor.org/rfc/rfc9218#section-7.1
        //# The request-stream variant of PRIORITY_UPDATE (type=0xF0700) MUST
        //# reference a request stream.
        if !stream_id.is_request() {
            return Err(StreamError::StreamError {
                code: Code::H3_ID_ERROR,
                reason: format!("{} is not a request stream", stream_id),
            });
        }
        self.conn_state
            .send_raw_control_frame(&crate::ext::ControlFrame::PriorityUpdate {
                push: false,
                id: stream_id.into_inner(),
                priority: priority.into(),
            })
    }

    /// Sends MAX_PUSH_ID `max_push_id` on the control stream, raising the one sent so far
    /// ([`super::Builder::control_frames`]) or sending a first: the server may push up to it
    /// from now on. Fails once the connection failed, or if `max_push_id` is below the one
    /// sent before. The connection driver writes it.
    pub fn send_max_push_id(&self, max_push_id: u64) -> Result<(), StreamError> {
        if let Some(error) = self.get_conn_error() {
            return Err(StreamError::ConnectionError(convert_to_connection_error(
                error,
            )));
        }
        self.conn_state
            .send_max_push_id(max_push_id)
            .map_err(|current| StreamError::StreamError {
                code: Code::H3_ID_ERROR,
                reason: format!("MAX_PUSH_ID {max_push_id} below the {current} sent"),
            })
    }

    /// Sends CANCEL_PUSH for `push_id`, a push the server promised, unless this client sent
    /// one already: a push stream arriving after is stopped (H3_REQUEST_CANCELLED), while one
    /// already taken ([`super::PushedResponse`]) is left to the caller. Fails once the
    /// connection failed. The connection driver writes it.
    pub fn cancel_push(&self, push_id: u64) -> Result<(), StreamError> {
        if let Some(error) = self.get_conn_error() {
            return Err(StreamError::ConnectionError(convert_to_connection_error(
                error,
            )));
        }
        self.conn_state.cancel_push(push_id);
        Ok(())
    }

    /// Sends `frame` on the control stream as it is, changing none of this client's state: a
    /// GOAWAY (with the push ID given, which must not exceed one sent before) or a reserved
    /// (GREASE) or unknown frame, for instance relaying one another peer sent. MAX_PUSH_ID,
    /// CANCEL_PUSH and PRIORITY_UPDATE have their own methods. Fails once the connection
    /// failed, if a value doesn't fit a variable-length integer, or while the frames queued
    /// before and not written yet, as the server's flow control holds the control stream back,
    /// hold 64 KiB or more (H3_EXCESSIVE_LOAD). The connection driver writes it after the
    /// SETTINGS.
    pub fn send_control_frame(&self, frame: crate::ext::ControlFrame) -> Result<(), StreamError> {
        self.conn_state.send_raw_control_frame(&frame)
    }

    /// Lets this sender send requests after the server's GOAWAY, which the server processes
    /// on streams below the GOAWAY's ID (RFC 9114 §5.2): those a client sent before it saw the
    /// GOAWAY, relayed. The caller keeps them below it.
    pub fn send_after_goaway(&mut self) {
        self.after_goaway = true;
    }

    /// Resolves once the control-stream frames queued so far (a
    /// [`send_priority_update`](Self::send_priority_update)) reached the transport, so a
    /// request sent after it goes out after them.
    pub async fn control_written(&self) {
        future::poll_fn(|cx| self.conn_state.poll_control_written(cx)).await
    }

    /// Resolves once the control-stream frames queued so far reached the transport or wait
    /// behind frames the server's flow control holds back: a request sent after it goes out
    /// after them unless they wait for credit, as a request a client opens while its control
    /// stream is blocked does.
    pub async fn control_flushed(&self) {
        future::poll_fn(|cx| self.conn_state.poll_control_flushed(cx)).await
    }

    /// Whether the server's SETTINGS enabled HTTP datagrams (RFC 9297 §2.1.1): false until
    /// they arrived.
    pub fn peer_enables_datagram(&self) -> bool {
        self.conn_state.settings().enable_datagram()
    }
}

impl<T, B> Clone for SendRequest<T, B>
where
    T: quic::OpenStreams<B> + Clone,
    B: Buf,
{
    fn clone(&self) -> Self {
        self.sender_count
            .fetch_add(1, std::sync::atomic::Ordering::Release);

        Self {
            conn_state: self.conn_state.clone(),
            open: self.open.clone(),
            max_field_section_size: self.max_field_section_size,
            sender_count: self.sender_count.clone(),
            _buf: PhantomData,
            send_grease_frame: self.send_grease_frame,
            after_goaway: self.after_goaway,
        }
    }
}

impl<T, B> Drop for SendRequest<T, B>
where
    T: quic::OpenStreams<B>,
    B: Buf,
{
    fn drop(&mut self) {
        if self
            .sender_count
            .fetch_sub(1, std::sync::atomic::Ordering::AcqRel)
            == 1
        {
            self.handle_connection_error_on_stream(InternalConnectionError::new(
                Code::H3_NO_ERROR,
                "Connection closed by client".to_string(),
            ));
        }
    }
}

/// Client connection driver
///
/// Maintains the internal state of an HTTP/3 connection, including control and QPACK.
/// It needs to be polled continuously via [`poll_close()`]. On connection closure, this
/// will resolve to `Ok(())` if the peer sent `HTTP_NO_ERROR`, or `Err()` if a connection-level
/// error occurred.
///
/// [`shutdown()`] initiates a graceful shutdown of this connection. After calling it, no request
/// initiation will be further allowed. Then [`poll_close()`] will resolve when all ongoing requests
/// and push streams complete. Finally, a connection closure with `HTTP_NO_ERROR` code will be
/// sent to the server.
///
/// # Examples
///
/// ## Drive a connection concurrently
///
/// ```rust
/// # use bytes::Buf;
/// # use futures_util::future;
/// # use h3::{client::*, quic};
/// # use tokio::task::JoinHandle;
/// # async fn doc<C, B>(mut connection: Connection<C, B>)
/// #    -> JoinHandle<Result<(), Box<dyn std::error::Error + Send + Sync>>>
/// # where
/// #    C: quic::Connection<B> + Send + 'static,
/// #    C::SendStream: Send + 'static,
/// #    C::RecvStream: Send + 'static,
/// #    C::BidiStream: Send + 'static,
/// #    B: Buf + Send + 'static,
/// # {
/// // Run the driver on a different task
/// tokio::spawn(async move {
///     future::poll_fn(|cx| connection.poll_close(cx)).await;
///     Ok::<(), Box<dyn std::error::Error + Send + Sync>>(())
/// })
/// # }
/// ```
///
/// ## Shutdown a connection gracefully
///
/// ```rust
/// # use bytes::Buf;
/// # use futures_util::future;
/// # use h3::quic;
/// # use h3::client::Connection;
/// # use h3::client::SendRequest;
/// # use tokio::{self, sync::oneshot, task::JoinHandle};
/// # async fn doc<C, B>(mut connection: Connection<C, B>)
/// #    -> Result<(), Box<dyn std::error::Error + Send + Sync>>
/// # where
/// #    C: quic::Connection<B> + Send + 'static,
/// #    C::SendStream: Send + 'static,
/// #    C::RecvStream: Send + 'static,
/// #    C::BidiStream: Send + 'static,
/// #    B: Buf + Send + 'static,
/// # {
/// // Prepare a channel to stop the driver thread
/// let (shutdown_tx, shutdown_rx) = oneshot::channel();
///
/// // Run the driver on a different task
/// let driver = tokio::spawn(async move {
///     tokio::select! {
///         // Drive the connection
///         closed = future::poll_fn(|cx| connection.poll_close(cx)) => closed,
///         // Listen for shutdown condition
///         max_streams = shutdown_rx => {
///             // Initiate shutdown
///             connection.shutdown(max_streams?);
///             // Wait for ongoing work to complete
///             future::poll_fn(|cx| connection.poll_close(cx)).await
///         }
///     };
///
///     Ok::<(), Box<dyn std::error::Error + Send + Sync>>(())
/// });
///
/// // Do client things, wait for close condition...
///
/// // Initiate shutdown
/// shutdown_tx.send(2);
/// // Wait for the connection to be closed
/// driver.await?
/// # }
/// ```
/// [`poll_close()`]: struct.Connection.html#method.poll_close
/// [`shutdown()`]: struct.Connection.html#method.shutdown
pub struct Connection<C, B>
where
    C: quic::Connection<B>,
    B: Buf,
{
    /// TODO: breaking encapsulation for RFC9298.
    pub inner: ConnectionInner<C, B>,
    // Has a GOAWAY frame been sent? If so, this PushId is the last we are willing to accept.
    pub(super) sent_closing: Option<PushId>,
    // Has a GOAWAY frame been received? If so, this is StreamId the last the remote will accept.
    pub(super) recv_closing: Option<StreamId>,
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
    /// Initiate a graceful shutdown, accepting `max_push` potentially in-flight server pushes
    #[cfg_attr(feature = "tracing", instrument(skip_all, level = "trace"))]
    pub async fn shutdown(&mut self, _max_push: usize) -> Result<(), ConnectionError> {
        // TODO: Calculate remaining pushes once server push is implemented.
        self.inner.shutdown(&mut self.sent_closing, PushId(0)).await
    }

    /// The first 16 pushes the server made after this client sent MAX_PUSH_ID
    /// ([`super::Builder::control_frames`]): promises (answered with CANCEL_PUSH unless
    /// delivered), push streams (stopped with H3_REQUEST_CANCELLED unless delivered) and the
    /// server's CANCEL_PUSH frames.
    pub fn pushes(&self) -> Vec<crate::ext::PushEvent> {
        self.inner.shared.pushes()
    }

    /// Receives the server's pushes as they are promised, each with its response, when this
    /// client delivers them ([`super::Builder::deliver_pushes`]), and when each request
    /// stream promises no more; replacing any previous receiver. The connection must be
    /// driven (polled) for them to arrive. A push received by no one is cancelled.
    pub fn subscribe_pushes(
        &mut self,
    ) -> tokio::sync::mpsc::UnboundedReceiver<PushDelivery<C::RecvStream, B>> {
        self.inner.subscribe_pushes()
    }

    /// Receives every frame after SETTINGS on the server's control stream as the driver reads
    /// it, from now on, with its whole payload (GOAWAY and reserved (GREASE) or unknown frames
    /// among them), replacing any previous receiver. The stream is read only while the
    /// receiver takes them (see [`crate::ext::ControlFrames`]).
    pub fn subscribe_control_frames(&mut self) -> crate::ext::ControlFrames {
        self.inner.subscribe_control_frames()
    }

    /// Receives the unidirectional streams of types HTTP/3 doesn't know (reserved (GREASE)
    /// ones among them) the server opens from now on, rather than stopping them, replacing
    /// any previous receiver. The connection must be driven (polled) for them to arrive.
    pub fn subscribe_unknown_streams(
        &mut self,
    ) -> tokio::sync::mpsc::UnboundedReceiver<crate::ext::UnknownStream<C::RecvStream>> {
        self.inner.subscribe_unknown_streams()
    }

    /// Receives the WebTransport streams the server opens from now on, bidirectional and
    /// unidirectional, whether or not WebTransport was negotiated, replacing any previous
    /// receiver. The connection must be driven (polled) for them to arrive.
    pub fn subscribe_webtransport(
        &mut self,
    ) -> tokio::sync::mpsc::UnboundedReceiver<
        crate::ext::WebTransportStream<C::BidiStream, C::RecvStream>,
    > {
        self.inner.subscribe_webtransport()
    }

    /// How the server used its QPACK encoder stream so far. `None` unless this client
    /// advertises a dynamic table, as the encoder stream is only read then.
    pub fn peer_qpack_encoder(&self) -> Option<crate::ext::QpackEncoderUse> {
        self.inner.peer_qpack_encoder()
    }

    /// Sends what a connection built with [`Builder::defer_settings`] held back, as `builder`
    /// configures it in place of the builder it was built with: the SETTINGS and control
    /// frames, the QPACK streams' types and dynamic table use, and the reserved stream. Does
    /// nothing on a connection that sent them already.
    ///
    /// [`Builder::defer_settings`]: super::Builder::defer_settings
    pub async fn start(&mut self, builder: &super::Builder) -> Result<(), ConnectionError> {
        self.inner.start(builder.config()).await
    }

    /// Wait until the connection is closed
    #[cfg_attr(feature = "tracing", instrument(skip_all, level = "trace"))]
    pub async fn wait_idle(&mut self) -> ConnectionError {
        future::poll_fn(|cx| self.poll_close(cx)).await
    }

    /// Maintain the connection state until it is closed
    #[cfg_attr(feature = "tracing", instrument(skip_all, level = "trace"))]
    pub fn poll_close(&mut self, cx: &mut Context<'_>) -> Poll<ConnectionError> {
        while let Poll::Ready(result) = self.inner.poll_control(cx) {
            match result {
                //= https://www.rfc-editor.org/rfc/rfc9114#section-7.2.4.2
                //= type=TODO
                //# When a 0-RTT QUIC connection is being used, the initial value of each
                //# server setting is the value used in the previous session.  Clients
                //# SHOULD store the settings the server provided in the HTTP/3
                //# connection where resumption information was provided, but they MAY
                //# opt not to store settings in certain cases (e.g., if the session
                //# ticket is received before the SETTINGS frame).

                //= https://www.rfc-editor.org/rfc/rfc9114#section-7.2.4.2
                //= type=TODO
                //# A client MUST comply
                //# with stored settings -- or default values if no values are stored --
                //# when attempting 0-RTT.

                //= https://www.rfc-editor.org/rfc/rfc9114#section-7.2.4.2
                //= type=TODO
                //# Once a server has provided new settings,
                //# clients MUST comply with those values.
                Ok(Frame::Settings(_)) => {
                    #[cfg(feature = "tracing")]
                    trace!("Got settings");
                    ()
                }

                //= https://www.rfc-editor.org/rfc/rfc9114#section-7.2.3
                //# The CANCEL_PUSH frame (type=0x03) is used to request cancellation of
                //# a server push prior to the push stream being received.
                Ok(Frame::CancelPush(push_id)) if self.inner.shared.accepts_pushes() => {
                    self.inner
                        .shared
                        .record_push(crate::ext::PushEvent::Cancelled { push_id: push_id.0 });
                    self.inner.push_cancelled(push_id.0);
                }

                Ok(Frame::Goaway(id)) => {
                    //= https://www.rfc-editor.org/rfc/rfc9114#section-7.2.6
                    //# The GOAWAY frame is always sent on the control stream.  In the
                    //# server-to-client direction, it carries a QUIC stream ID for a client-
                    //# initiated bidirectional stream encoded as a variable-length integer.
                    //# A client MUST treat receipt of a GOAWAY frame containing a stream ID
                    //# of any other type as a connection error of type H3_ID_ERROR.
                    if !StreamId::from(id).is_request() {
                        return Poll::Ready(self.inner.handle_connection_error(
                            InternalConnectionError::new(
                                Code::H3_ID_ERROR,
                                format!("non-request StreamId in a GoAway frame: {}", id),
                            ),
                        ));
                    }
                    if let Err(err) = self.inner.process_goaway(&mut self.recv_closing, id) {
                        return Poll::Ready(err);
                    }

                    #[cfg(feature = "tracing")]
                    info!("Server initiated graceful shutdown, last: StreamId({})", id);
                }

                //= https://www.rfc-editor.org/rfc/rfc9114#section-7.2.5
                //# If a PUSH_PROMISE frame is received on the control stream, the client
                //# MUST respond with a connection error of type H3_FRAME_UNEXPECTED.

                //= https://www.rfc-editor.org/rfc/rfc9114#section-7.2.7
                //# A client MUST treat the
                //# receipt of a MAX_PUSH_ID frame as a connection error of type
                //# H3_FRAME_UNEXPECTED.
                Ok(frame) => {
                    return Poll::Ready(self.inner.handle_connection_error(
                        InternalConnectionError::new(
                            Code::H3_FRAME_UNEXPECTED,
                            format!("on client control stream: {:?}", frame),
                        ),
                    ));
                }
                Err(connection_error) => {
                    return Poll::Ready(connection_error);
                }
            }
        }

        //= https://www.rfc-editor.org/rfc/rfc9114#section-6.1
        //# Clients MUST treat
        //# receipt of a server-initiated bidirectional stream as a connection
        //# error of type H3_STREAM_CREATION_ERROR unless such an extension has
        //# been negotiated.
        if self.inner.delivers_webtransport() {
            if let Err(error) = self.inner.poll_webtransport_bidi(cx) {
                return Poll::Ready(error);
            }
        } else if self.inner.poll_accept_bi(cx).is_ready() {
            return Poll::Ready(
                self.inner
                    .handle_connection_error(InternalConnectionError::new(
                        Code::H3_STREAM_CREATION_ERROR,
                        "client received a server-initiated bidirectional stream".to_string(),
                    )),
            );
        }

        Poll::Pending
    }
}
