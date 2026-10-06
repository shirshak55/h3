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

/// A PUSH_PROMISE where it stood among a request stream's frames (see
/// [`RequestStream::poll_recv_event`]): the push ID and the promised request, whose
/// response [`PushDelivery::Promised`] carries under the same push ID
#[derive(Debug)]
pub struct PromisedPush {
    /// The push ID
    pub push_id: u64,
    /// The promised request, with its [`HeaderOrder`](crate::ext::HeaderOrder) and
    /// [`PseudoOrder`](crate::ext::PseudoOrder)
    pub request: http::Request<()>,
}

/// What [`RequestStream::poll_recv_event`] yields: body data, or a PUSH_PROMISE in its wire
/// position among the DATA frames
#[allow(clippy::large_enum_variant)]
pub enum RecvEvent<D> {
    /// Some of the body
    Data(D),
    /// A PUSH_PROMISE delivered to this client
    PushPromise(PromisedPush),
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
    /// Its promised request's size, awaited until it drops (see [`SharedState::push_taken`])
    size: usize,
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
        size: usize,
        shared: Arc<SharedState>,
        max_field_section_size: u64,
    ) -> Self {
        Self {
            push_id,
            stream: PushStream::Arrived(Some(stream)),
            size,
            shared,
            max_field_section_size,
        }
    }

    pub(crate) fn awaited(
        push_id: u64,
        stream: oneshot::Receiver<FrameStream<R, B>>,
        size: usize,
        shared: Arc<SharedState>,
        max_field_section_size: u64,
    ) -> Self {
        Self {
            push_id,
            stream: PushStream::Awaited(stream),
            size,
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
        self.shared.push_taken(self.size);
        let stream = match &mut self.stream {
            PushStream::Arrived(stream) => stream.take(),
            // Its push stream may have arrived since it was last polled.
            PushStream::Awaited(stream) => match stream.try_recv() {
                Ok(stream) => Some(stream),
                Err(_) => {
                    self.shared.cancel_push(self.push_id);
                    None
                }
            },
            PushStream::Taken => None,
        };
        //= https://www.rfc-editor.org/rfc/rfc9114#section-7.2.3
        //# The
        //# client SHOULD abort reading the stream with an error code of
        //# H3_REQUEST_CANCELLED.
        if let Some(mut stream) = stream {
            stream.stop_sending(Code::H3_REQUEST_CANCELLED);
            self.shared.qpack().cancel_stream(stream.id().into_inner());
            self.shared.waker().wake();
        }
    }
}
