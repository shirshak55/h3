//! Server push: push IDs, push streams and CANCEL_PUSH

use std::{marker::PhantomData, sync::Arc};

use bytes::Buf;
use futures_util::future;
use tokio::sync::mpsc;

use crate::{
    connection,
    error::{
        connection_error_creators::{convert_to_connection_error, CloseStream},
        StreamError,
    },
    ext::ControlFrame,
    frame::FrameStream,
    quic::{self, SendStream as _, StreamId},
    shared_state::{ConnectionState, SharedState},
    stream::{self, BufRecvStream, UniStreamHeader, WriteBuf},
};

use super::{connection::RequestEnd, stream::RequestStream};

/// Pushes on a server connection (see [`Connection::push_opener`]): a push ID is allocated
/// ([`Self::allocate_push_id`]), promised on a request stream
/// ([`RequestStream::push_promise`]), then its response goes on the push stream
/// [`Self::open_push_stream`] opens, or the push is cancelled ([`Self::cancel_push`]).
///
/// [`Connection::push_opener`]: super::Connection::push_opener
pub struct PushOpener<O, B>
where
    O: quic::OpenStreams<B>,
    B: Buf,
{
    open: O,
    shared: Arc<SharedState>,
    request_end: mpsc::UnboundedSender<StreamId>,
    _buf: PhantomData<fn(B)>,
}

impl<O, B> ConnectionState for PushOpener<O, B>
where
    O: quic::OpenStreams<B>,
    B: Buf,
{
    fn shared_state(&self) -> &SharedState {
        &self.shared
    }
}

impl<O, B> CloseStream for PushOpener<O, B>
where
    O: quic::OpenStreams<B>,
    B: Buf,
{
}

impl<O, B> PushOpener<O, B>
where
    O: quic::OpenStreams<B>,
    B: Buf,
{
    pub(super) fn new(
        open: O,
        shared: Arc<SharedState>,
        request_end: mpsc::UnboundedSender<StreamId>,
    ) -> Self {
        Self {
            open,
            shared,
            request_end,
            _buf: PhantomData,
        }
    }

    /// Allocates the next push ID, once the client's MAX_PUSH_ID allows it; fails once the
    /// connection failed.
    pub async fn allocate_push_id(&self) -> Result<u64, StreamError> {
        future::poll_fn(|cx| {
            if let Some(error) = self.get_conn_error() {
                return std::task::Poll::Ready(Err(StreamError::ConnectionError(
                    convert_to_connection_error(error),
                )));
            }
            self.shared.poll_allocate_push_id(cx).map(Ok)
        })
        .await
    }

    /// The next push ID, if the client's MAX_PUSH_ID allows one now.
    pub fn try_allocate_push_id(&self) -> Option<u64> {
        self.shared.try_allocate_push_id()
    }

    /// Opens the push stream of `push_id`, promised already: the stream its response goes on,
    /// sent as a request's response ([`RequestStream::send_response`], `send_data`,
    /// `send_trailers`, `finish`).
    pub async fn open_push_stream(
        &mut self,
        push_id: u64,
    ) -> Result<RequestStream<O::SendStream, B>, StreamError> {
        if let Some(error) = self.check_peer_connection_closing() {
            return Err(error);
        }
        let mut send = future::poll_fn(|cx| self.open.poll_open_send(cx))
            .await
            .map_err(|e| self.handle_quic_stream_error(e))?;
        stream::write(&mut send, WriteBuf::from(UniStreamHeader::Push(push_id)))
            .await
            .map_err(|e| self.handle_quic_stream_error(e))?;
        let stream_id = send.send_id();
        Ok(RequestStream {
            inner: connection::RequestStream::new(
                FrameStream::new(BufRecvStream::new(send)),
                0,
                self.shared.clone(),
                false,
            ),
            request_end: Arc::new(RequestEnd {
                request_end: self.request_end.clone(),
                stream_id,
            }),
        })
    }

    /// Sends CANCEL_PUSH for `push_id`, a push promised whose push stream was not opened. The
    /// connection must be driven for it to go out.
    pub fn cancel_push(&self, push_id: u64) {
        self.shared
            .send_control_frame(&ControlFrame::CancelPush(push_id));
    }
}

impl<O, B> Clone for PushOpener<O, B>
where
    O: quic::OpenStreams<B> + Clone,
    B: Buf,
{
    fn clone(&self) -> Self {
        Self {
            open: self.open.clone(),
            shared: self.shared.clone(),
            request_end: self.request_end.clone(),
            _buf: PhantomData,
        }
    }
}
