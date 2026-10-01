//! The pushes a server makes, delivered to a client that opted in
//! ([`Builder::deliver_pushes`](super::Builder::deliver_pushes))

use std::{
    future::Future,
    pin::Pin,
    sync::Arc,
    task::{ready, Context, Poll},
};

use tokio::sync::oneshot;

use crate::{
    connection,
    error::{connection_error_creators::convert_to_connection_error, Code, StreamError},
    ext::ControlFrame,
    frame::FrameStream,
    quic::{self, StreamId},
    shared_state::{ConnectionState, QpackStreamEnd, SharedState},
};

use super::RequestStream;

/// What [`Connection::subscribe_pushes`](super::Connection::subscribe_pushes) delivers
#[allow(clippy::large_enum_variant)]
pub enum PushDelivery<R, B>
where
    R: quic::RecvStream,
{
    /// A PUSH_PROMISE
    Promised(PushedRequest<R, B>),
    /// The request stream `StreamId` promises no more pushes: it was read to its end or
    /// dropped
    Ended(StreamId),
}

/// A push the server promised on a request stream: the request it answers, and the
/// response it pushes
pub struct PushedRequest<R, B>
where
    R: quic::RecvStream,
{
    /// The push ID
    pub push_id: u64,
    /// The request stream the promise came on
    pub stream: StreamId,
    /// The promised request, with its [`HeaderOrder`](crate::ext::HeaderOrder) and
    /// [`PseudoOrder`](crate::ext::PseudoOrder)
    pub request: http::Request<()>,
    /// The pushed response
    pub response: PushedResponse<R, B>,
}

/// The response a server pushes, resolving to the stream carrying it (its HEADERS, DATA and
/// trailers read as a request's response) once its push stream arrived. Dropped before
/// then, it cancels the push: CANCEL_PUSH, or STOP_SENDING a push stream that arrived.
pub struct PushedResponse<R, B>
where
    R: quic::RecvStream,
{
    push_id: u64,
    stream: PushStream<R, B>,
    shared: Arc<SharedState>,
    max_field_section_size: u64,
}

enum PushStream<R, B> {
    Arrived(Option<FrameStream<R, B>>),
    Awaited(oneshot::Receiver<FrameStream<R, B>>),
    Taken,
}

impl<R, B> PushedResponse<R, B>
where
    R: quic::RecvStream,
{
    pub(crate) fn arrived(
        push_id: u64,
        stream: FrameStream<R, B>,
        shared: Arc<SharedState>,
        max_field_section_size: u64,
    ) -> Self {
        Self {
            push_id,
            stream: PushStream::Arrived(Some(stream)),
            shared,
            max_field_section_size,
        }
    }

    pub(crate) fn awaited(
        push_id: u64,
        stream: oneshot::Receiver<FrameStream<R, B>>,
        shared: Arc<SharedState>,
        max_field_section_size: u64,
    ) -> Self {
        Self {
            push_id,
            stream: PushStream::Awaited(stream),
            shared,
            max_field_section_size,
        }
    }

    /// The push ID
    pub fn push_id(&self) -> u64 {
        self.push_id
    }

    /// The error for a push stream that will not come: the server cancelled the push, or
    /// the connection failed.
    fn cancelled(&self) -> StreamError {
        match self.shared.get_conn_error() {
            Some(error) => StreamError::ConnectionError(convert_to_connection_error(error)),
            None => StreamError::StreamError {
                code: Code::H3_REQUEST_CANCELLED,
                reason: format!("push {} cancelled by the server", self.push_id),
            },
        }
    }
}

impl<R, B> Future for PushedResponse<R, B>
where
    R: quic::RecvStream,
{
    type Output = Result<RequestStream<R, B>, StreamError>;

    fn poll(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Self::Output> {
        let this = self.get_mut();
        let stream = match &mut this.stream {
            PushStream::Arrived(stream) => stream.take(),
            PushStream::Awaited(stream) => match ready!(Pin::new(stream).poll(cx)) {
                Ok(stream) => Some(stream),
                Err(_) => {
                    this.stream = PushStream::Taken;
                    return Poll::Ready(Err(this.cancelled()));
                }
            },
            PushStream::Taken => None,
        };
        let stream = stream.expect("PushedResponse polled after completion");
        this.stream = PushStream::Taken;
        let id = stream.id();
        let mut inner = connection::RequestStream::new(
            stream,
            this.max_field_section_size,
            this.shared.clone(),
            false,
        );
        inner.qpack_end = QpackStreamEnd::track(&this.shared, id);
        Poll::Ready(Ok(RequestStream { inner }))
    }
}

impl<R, B> Drop for PushedResponse<R, B>
where
    R: quic::RecvStream,
{
    fn drop(&mut self) {
        match &mut self.stream {
            //= https://www.rfc-editor.org/rfc/rfc9114#section-7.2.3
            //# The
            //# client SHOULD abort reading the stream with an error code of
            //# H3_REQUEST_CANCELLED.
            PushStream::Arrived(Some(stream)) => {
                stream.stop_sending(Code::H3_REQUEST_CANCELLED);
                self.shared.qpack().cancel_stream(stream.id().into_inner());
                self.shared.waker().wake();
            }
            PushStream::Awaited(_) => {
                self.shared
                    .send_control_frame(&ControlFrame::CancelPush(self.push_id));
            }
            PushStream::Arrived(None) | PushStream::Taken => (),
        }
    }
}
