//! This module represents the shared state of the h3 connection

use std::{
    borrow::Cow,
    collections::HashMap,
    hash::{DefaultHasher, Hash, Hasher},
    sync::{
        atomic::{AtomicBool, AtomicU64, Ordering},
        Arc, Mutex, MutexGuard, OnceLock,
    },
    task::{Context, Poll, Waker},
};

use bytes::{Bytes, BytesMut};
use futures_util::task::AtomicWaker;
use http::HeaderName;

use crate::{
    config::Settings,
    error::{
        connection_error_creators::convert_to_connection_error,
        internal_error::{ErrorOrigin, InternalConnectionError},
        Code, StreamError,
    },
    ext::{ControlFrame, HeaderOrder, PushEvent},
    proto::headers::{Header, HeaderError},
    qpack::{Decoded, DecoderError, EncoderError, HeaderField, QpackState},
    quic::StreamId,
};

/// `SharedState::max_push_id` before the client sent MAX_PUSH_ID (no push ID is that large)
const NO_MAX_PUSH_ID: u64 = u64::MAX;

#[derive(Debug)]
/// This struct represents the shared state of the h3 connection and the stream structs
pub struct SharedState {
    /// The settings, sent by the peer
    settings: OnceLock<Settings>,
    /// The connection error
    connection_error: OnceLock<ErrorOrigin>,
    /// The connection is closing
    closing: AtomicBool,
    /// Waker for the connection
    waker: AtomicWaker,
    /// The QPACK dynamic table state
    qpack: Mutex<QpackState>,
    /// Control-stream frames waiting for the connection driver to write them
    control_out: Mutex<BytesMut>,
    /// Whether the driver holds control-stream frames the transport has not taken yet
    control_in_flight: AtomicBool,
    /// Tasks waiting for the control-stream frames queued so far to reach the transport
    control_written: Mutex<Vec<Waker>>,
    /// The MAX_PUSH_ID this client sent (`NO_MAX_PUSH_ID` until it sent one): it tolerates
    /// pushes, cancelling them unless they are delivered
    max_push_id: AtomicU64,
    /// Whether this client delivers the pushes ([`crate::client::Builder::deliver_pushes`])
    deliver_pushes: AtomicBool,
    /// The pushes this client saw
    pushes: Mutex<Pushes>,
    /// The push IDs this server allocates below the client's MAX_PUSH_ID
    push_ids: Mutex<PushIds>,
}

/// A client's record of the server's pushes
#[derive(Debug, Default)]
struct Pushes {
    /// The first events seen
    events: Vec<PushEvent>,
    /// Each push ID promised or pushed
    ids: HashMap<u64, PushSeen>,
    /// What the request streams hand the connection driver
    pending: Vec<PushPending>,
}

/// How a push ID was seen
#[derive(Debug, Default)]
struct PushSeen {
    /// The hash of the promised request's field lines
    promise: Option<u64>,
    /// Its push stream arrived
    streamed: bool,
    /// This client sent CANCEL_PUSH for it
    cancelled: bool,
}

/// What a request stream hands the connection driver about pushes
#[derive(Debug)]
#[allow(clippy::large_enum_variant)]
pub(crate) enum PushPending {
    /// A PUSH_PROMISE decoded on the request stream `stream`
    Promised {
        push_id: u64,
        stream: StreamId,
        request: http::Request<()>,
    },
    /// A promise that can't be delivered (its request is malformed): its push stream, if it
    /// arrived, is stopped
    Cancel(u64),
    /// The request stream was read to its end or dropped: it promises no more
    Ended(StreamId),
}

/// A server's push IDs, allocated in order below the client's MAX_PUSH_ID
#[derive(Debug, Default)]
struct PushIds {
    /// The client's MAX_PUSH_ID
    max: Option<u64>,
    /// The next push ID to allocate: those below were promised
    next: u64,
    /// Tasks waiting for a push ID the client's MAX_PUSH_ID doesn't allow yet
    wakers: Vec<Waker>,
}

impl Default for SharedState {
    fn default() -> Self {
        Self {
            settings: OnceLock::new(),
            connection_error: OnceLock::new(),
            closing: AtomicBool::new(false),
            waker: AtomicWaker::new(),
            qpack: Mutex::new(QpackState::default()),
            control_out: Mutex::new(BytesMut::new()),
            control_in_flight: AtomicBool::new(false),
            control_written: Mutex::new(Vec::new()),
            max_push_id: AtomicU64::new(NO_MAX_PUSH_ID),
            deliver_pushes: AtomicBool::new(false),
            pushes: Mutex::new(Pushes::default()),
            push_ids: Mutex::new(PushIds::default()),
        }
    }
}

impl SharedState {
    pub(crate) fn control_out(&self) -> MutexGuard<'_, BytesMut> {
        self.control_out
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
    }

    /// Queues `frame` for the connection driver to write on the control stream.
    pub(crate) fn send_control_frame(&self, frame: &crate::ext::ControlFrame) {
        frame.encode(&mut *self.control_out());
        self.waker.wake();
    }

    /// Queues `frame` as it is, changing none of the connection's state (see
    /// [`crate::client::SendRequest::send_control_frame`]): fails once the connection failed,
    /// or if a value doesn't fit a variable-length integer.
    pub(crate) fn send_raw_control_frame(&self, frame: &ControlFrame) -> Result<(), StreamError> {
        if let Some(error) = self.get_conn_error() {
            return Err(StreamError::ConnectionError(convert_to_connection_error(
                error,
            )));
        }
        if !frame.is_valid() {
            return Err(StreamError::StreamError {
                code: Code::H3_INTERNAL_ERROR,
                reason: "a control frame value is not a valid variable-length integer".to_string(),
            });
        }
        self.send_control_frame(frame);
        Ok(())
    }

    /// Records whether the driver holds control-stream frames the transport has not taken
    /// yet, waking the tasks waiting for them once it holds none.
    pub(crate) fn set_control_in_flight(&self, in_flight: bool) {
        self.control_in_flight.store(in_flight, Ordering::Release);
        if !in_flight {
            let wakers = std::mem::take(&mut *self.control_written_lock());
            for waker in wakers {
                waker.wake();
            }
        }
    }

    /// Resolves once the control-stream frames queued so far reached the transport, so a
    /// frame written to another stream after it goes out after them.
    pub(crate) fn poll_control_written(&self, cx: &mut Context<'_>) -> Poll<()> {
        let mut wakers = self.control_written_lock();
        if self.control_out().is_empty() && !self.control_in_flight.load(Ordering::Acquire) {
            return Poll::Ready(());
        }
        if !wakers.iter().any(|waker| waker.will_wake(cx.waker())) {
            wakers.push(cx.waker().clone());
        }
        Poll::Pending
    }

    fn control_written_lock(&self) -> MutexGuard<'_, Vec<Waker>> {
        self.control_written
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
    }

    /// Records the MAX_PUSH_ID this client sent, which only grows.
    pub(crate) fn set_max_push_id(&self, max_push_id: u64) {
        if !self
            .max_push_id()
            .is_some_and(|current| max_push_id <= current)
        {
            self.max_push_id.store(max_push_id, Ordering::Release);
        }
    }

    /// Queues MAX_PUSH_ID `max_push_id` on the control stream and records it; `max_push_id`
    /// must not be below the one sent before.
    pub(crate) fn send_max_push_id(&self, max_push_id: u64) -> Result<(), u64> {
        if self
            .max_push_id()
            .is_some_and(|current| max_push_id < current)
        {
            return Err(self.max_push_id.load(Ordering::Acquire));
        }
        self.set_max_push_id(max_push_id);
        self.send_control_frame(&ControlFrame::MaxPushId(max_push_id));
        Ok(())
    }

    /// Whether this client sent MAX_PUSH_ID, so it tolerates pushes
    pub(crate) fn accepts_pushes(&self) -> bool {
        self.max_push_id().is_some()
    }

    /// The MAX_PUSH_ID this client sent
    pub(crate) fn max_push_id(&self) -> Option<u64> {
        match self.max_push_id.load(Ordering::Acquire) {
            NO_MAX_PUSH_ID => None,
            max => Some(max),
        }
    }

    pub(crate) fn set_deliver_pushes(&self, enabled: bool) {
        self.deliver_pushes.store(enabled, Ordering::Release);
    }

    /// Whether this client delivers the pushes it tolerates, rather than cancel them
    pub(crate) fn delivers_pushes(&self) -> bool {
        self.accepts_pushes() && self.deliver_pushes.load(Ordering::Acquire)
    }

    fn pushes_lock(&self) -> MutexGuard<'_, Pushes> {
        self.pushes
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
    }

    /// Records a server's CANCEL_PUSH the client saw (the first 16 events).
    pub(crate) fn record_push(&self, event: PushEvent) {
        let mut pushes = self.pushes_lock();
        if pushes.events.len() < 16 {
            pushes.events.push(event);
        }
    }

    /// Records the push stream `stream` for `push_id`: whether it is the first for that ID.
    pub(crate) fn push_stream(&self, push_id: u64, stream: StreamId) -> bool {
        let mut pushes = self.pushes_lock();
        let first = !std::mem::replace(&mut pushes.ids.entry(push_id).or_default().streamed, true);
        if pushes.events.len() < 16 {
            pushes.events.push(PushEvent::Stream { push_id, stream });
        }
        first
    }

    /// Queues CANCEL_PUSH for `push_id` unless this client sent one already.
    pub(crate) fn cancel_push(&self, push_id: u64) {
        let first = !std::mem::replace(
            &mut self.pushes_lock().ids.entry(push_id).or_default().cancelled,
            true,
        );
        if first {
            self.send_control_frame(&ControlFrame::CancelPush(push_id));
        }
    }

    /// Whether this client sent CANCEL_PUSH for `push_id`.
    pub(crate) fn push_cancelled(&self, push_id: u64) -> bool {
        self.pushes_lock()
            .ids
            .get(&push_id)
            .is_some_and(|seen| seen.cancelled)
    }

    /// A PUSH_PROMISE decoded on the request stream `stream`, checked against MAX_PUSH_ID and
    /// the push ID's earlier promise and recorded; then cancelled (CANCEL_PUSH, unless its
    /// push stream arrived) or, when pushes are delivered, handed to the connection driver as
    /// a request.
    pub(crate) fn promise(
        &self,
        push_id: u64,
        stream: StreamId,
        fields: Vec<HeaderField>,
    ) -> Result<Option<http::Request<()>>, InternalConnectionError> {
        //= https://www.rfc-editor.org/rfc/rfc9114#section-7.2.5
        //# A client MUST treat
        //# receipt of a PUSH_PROMISE frame that contains a larger push ID than
        //# the client has advertised as a connection error of H3_ID_ERROR.
        if self.max_push_id().map_or(true, |max| push_id > max) {
            return Err(InternalConnectionError::new(
                Code::H3_ID_ERROR,
                format!("PUSH_PROMISE with push ID {push_id} above MAX_PUSH_ID"),
            ));
        }
        let mut hasher = DefaultHasher::new();
        for field in &fields {
            field.name.as_ref().hash(&mut hasher);
            field.value.as_ref().hash(&mut hasher);
        }
        let hash = hasher.finish();
        let mut pushes = self.pushes_lock();
        //= https://www.rfc-editor.org/rfc/rfc9114#section-7.2.5
        //# If a client
        //# receives a push ID that has already been promised and detects a
        //# mismatch, it MUST respond with a connection error of type
        //# H3_GENERAL_PROTOCOL_ERROR.
        let seen = pushes.ids.entry(push_id).or_default();
        let previous = seen.promise.replace(hash);
        let streamed = seen.streamed;
        if previous.is_some_and(|earlier| earlier != hash) {
            return Err(InternalConnectionError::new(
                Code::H3_GENERAL_PROTOCOL_ERROR,
                format!("PUSH_PROMISE with push ID {push_id} differs from its earlier promise"),
            ));
        }
        if pushes.events.len() < 16 {
            pushes.events.push(PushEvent::Promise {
                push_id,
                stream,
                fields: fields
                    .iter()
                    .map(|field| {
                        (
                            Bytes::copy_from_slice(&field.name),
                            Bytes::copy_from_slice(&field.value),
                        )
                    })
                    .collect(),
            });
        }
        // The same promise again: handled already.
        if previous.is_some() {
            return Ok(None);
        }
        if !self.delivers_pushes() {
            //= https://www.rfc-editor.org/rfc/rfc9114#section-7.2.3
            //# A client SHOULD NOT send a CANCEL_PUSH frame
            //# when it has already received a corresponding push stream.
            if !streamed {
                self.send_control_frame(&ControlFrame::CancelPush(push_id));
            }
            return Ok(None);
        }
        let (pending, in_band) = match promised_request(fields.clone())
            .and_then(|request| promised_request(fields).map(|in_band| (request, in_band)))
        {
            Ok((request, in_band)) => (
                PushPending::Promised {
                    push_id,
                    stream,
                    request,
                },
                Some(in_band),
            ),
            Err(_) => {
                if !streamed {
                    self.send_control_frame(&ControlFrame::CancelPush(push_id));
                }
                (PushPending::Cancel(push_id), None)
            }
        };
        pushes.pending.push(pending);
        self.waker.wake();
        Ok(in_band)
    }

    /// Tells the connection driver the request stream `stream` promises no more pushes.
    fn push_ended(&self, stream: StreamId) {
        self.pushes_lock().pending.push(PushPending::Ended(stream));
        self.waker.wake();
    }

    /// What the request streams handed the connection driver since it last took them.
    pub(crate) fn take_pending_pushes(&self) -> Vec<PushPending> {
        std::mem::take(&mut self.pushes_lock().pending)
    }

    pub(crate) fn pushes(&self) -> Vec<PushEvent> {
        self.pushes_lock().events.clone()
    }

    fn push_ids_lock(&self) -> MutexGuard<'_, PushIds> {
        self.push_ids
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
    }

    /// Records the client's MAX_PUSH_ID, which may only grow.
    pub(crate) fn set_peer_max_push_id(&self, max: u64) -> Result<(), InternalConnectionError> {
        let mut ids = self.push_ids_lock();
        //= https://www.rfc-editor.org/rfc/rfc9114#section-7.2.7
        //# A MAX_PUSH_ID frame cannot reduce the maximum push
        //# ID; receipt of a MAX_PUSH_ID frame that contains a smaller value than
        //# previously received MUST be treated as a connection error of type
        //# H3_ID_ERROR.
        if ids.max.is_some_and(|current| max < current) {
            return Err(InternalConnectionError::new(
                Code::H3_ID_ERROR,
                format!("MAX_PUSH_ID {max} below the earlier one"),
            ));
        }
        ids.max = Some(max);
        for waker in ids.wakers.drain(..) {
            waker.wake();
        }
        Ok(())
    }

    /// Allocates the next push ID, once the client's MAX_PUSH_ID allows it; a connection
    /// error wakes the waiters, who check it.
    pub(crate) fn poll_allocate_push_id(&self, cx: &mut Context<'_>) -> Poll<u64> {
        let mut ids = self.push_ids_lock();
        if ids.max.is_some_and(|max| ids.next <= max) {
            let id = ids.next;
            ids.next += 1;
            return Poll::Ready(id);
        }
        if !ids.wakers.iter().any(|waker| waker.will_wake(cx.waker())) {
            ids.wakers.push(cx.waker().clone());
        }
        Poll::Pending
    }

    /// The next push ID, if the client's MAX_PUSH_ID allows one now.
    pub(crate) fn try_allocate_push_id(&self) -> Option<u64> {
        let mut ids = self.push_ids_lock();
        ids.max.is_some_and(|max| ids.next <= max).then(|| {
            ids.next += 1;
            ids.next - 1
        })
    }

    /// Whether the server promised (allocated) `push_id`.
    pub(crate) fn push_id_promised(&self, push_id: u64) -> bool {
        push_id < self.push_ids_lock().next
    }

    fn wake_push_id_waiters(&self) {
        for waker in self.push_ids_lock().wakers.drain(..) {
            waker.wake();
        }
    }

    pub(crate) fn qpack(&self) -> MutexGuard<'_, QpackState> {
        self.qpack
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
    }

    /// Decodes a field section received on `stream_id`, waking the connection driver to send
    /// the QPACK decoder instructions this queues.
    pub(crate) fn poll_decode(
        &self,
        cx: &mut Context<'_>,
        stream_id: u64,
        block: &Bytes,
        max_size: u64,
    ) -> Poll<Result<Decoded, DecoderError>> {
        let mut qpack = self.qpack();
        let decoded = qpack.poll_decode(cx, stream_id, block, max_size);
        if !qpack.decoder_out.is_empty() {
            self.waker.wake();
        }
        decoded
    }
}

impl SharedState {
    /// Encodes a field section sent on `stream_id` (see [`QpackState::encode`]), waking the
    /// connection driver to send the encoder instructions this queues.
    pub(crate) fn encode(
        &self,
        stream_id: u64,
        fields: Header,
        block: &mut BytesMut,
        max_size: u64,
    ) -> Result<u64, EncoderError> {
        let mut qpack = self.qpack();
        let size = qpack.encode(stream_id, fields, block, max_size);
        if !qpack.encoder_out.is_empty() {
            self.waker.wake();
        }
        size
    }
}

/// Tells the peer's QPACK encoder about a request stream abandoned before its end
pub(crate) struct QpackStreamEnd {
    pub(crate) shared: std::sync::Arc<SharedState>,
    pub(crate) stream_id: u64,
    pub(crate) ended: bool,
}

impl Drop for QpackStreamEnd {
    fn drop(&mut self) {
        if self.ended {
            return;
        }
        let mut qpack = self.shared.qpack();
        qpack.cancel_stream(self.stream_id);
        if !qpack.decoder_out.is_empty() {
            self.shared.waker.wake();
        }
    }
}

/// The request a PUSH_PROMISE's field lines carry
fn promised_request(fields: Vec<HeaderField>) -> Result<http::Request<()>, HeaderError> {
    // Pseudo-header names aren't header names, so this lists the regular fields.
    let order = fields
        .iter()
        .filter_map(|field| HeaderName::from_bytes(&field.name).ok())
        .collect();
    let header = Header::try_from(fields)?;
    let pseudo_order = header.pseudo_order().clone();
    let (method, uri, protocol, headers) = header.into_request_parts()?;
    let mut request = http::Request::new(());
    *request.method_mut() = method;
    *request.uri_mut() = uri;
    *request.headers_mut() = headers;
    *request.version_mut() = http::Version::HTTP_3;
    if let Some(protocol) = protocol {
        request.extensions_mut().insert(protocol);
    }
    request.extensions_mut().insert(HeaderOrder(order));
    request.extensions_mut().insert(pseudo_order);
    Ok(request)
}

/// Tells the connection driver a request stream promises no more pushes, once dropped
pub(crate) struct PushEnd {
    shared: Arc<SharedState>,
    stream_id: StreamId,
}

impl PushEnd {
    /// Tracks `stream_id` when the connection delivers pushes.
    pub(crate) fn track(shared: &Arc<SharedState>, stream_id: StreamId) -> Option<Self> {
        shared.delivers_pushes().then(|| Self {
            shared: shared.clone(),
            stream_id,
        })
    }
}

impl Drop for PushEnd {
    fn drop(&mut self) {
        self.shared.push_ended(self.stream_id);
    }
}

impl ConnectionState for SharedState {
    fn shared_state(&self) -> &SharedState {
        self
    }
}

/// This trait can be implemented for all types which have a shared state
pub trait ConnectionState {
    /// Get the shared state
    fn shared_state(&self) -> &SharedState;
    /// Get the connection error if the connection is in error state because of another task
    ///
    /// Return the error as an Err variant if it is set in order to allow using ? in the calling function
    fn get_conn_error(&self) -> Option<ErrorOrigin> {
        self.shared_state().connection_error.get().cloned()
    }

    /// tries to set the connection error
    fn set_conn_error(&self, error: ErrorOrigin) -> ErrorOrigin {
        let err = self
            .shared_state()
            .connection_error
            .get_or_init(move || error);
        self.shared_state().wake_push_id_waiters();
        err.clone()
    }

    /// set the connection error and wake the connection
    fn set_conn_error_and_wake<T: Into<ErrorOrigin>>(&self, error: T) -> ErrorOrigin {
        let err = self.set_conn_error(error.into());
        self.waker().wake();
        err
    }

    /// Get the settings
    fn settings(&self) -> Cow<Settings> {
        //= https://www.rfc-editor.org/rfc/rfc9114#section-7.2.4.2
        //# Each endpoint SHOULD use
        //# these initial values to send messages before the peer's SETTINGS
        //# frame has arrived, as packets carrying the settings can be lost or
        //# delayed.
        self.shared_state()
            .settings
            .get()
            .map(|s| Cow::Borrowed(s))
            .unwrap_or_default()
    }
    /// Set the connection to closing
    fn set_closing(&self) {
        self.shared_state()
            .closing
            .store(true, std::sync::atomic::Ordering::Relaxed);
    }
    /// Check if the connection is closing
    fn is_closing(&self) -> bool {
        self.shared_state()
            .closing
            .load(std::sync::atomic::Ordering::Relaxed)
    }
    /// Set the settings
    fn set_settings(&self, settings: Settings) {
        let _ = self.shared_state().settings.set(settings);
    }

    /// Returns the waker for the connection
    fn waker(&self) -> &AtomicWaker {
        &self.shared_state().waker
    }
}
