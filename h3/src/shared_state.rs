//! This module represents the shared state of the h3 connection

use std::{
    borrow::Cow,
    collections::HashSet,
    sync::{atomic::AtomicBool, Mutex, MutexGuard, OnceLock},
    task::{Context, Poll},
};

use bytes::{Bytes, BytesMut};
use futures_util::task::AtomicWaker;

use crate::{
    config::Settings,
    error::internal_error::ErrorOrigin,
    proto::headers::Header,
    qpack::{Decoded, DecoderError, EncoderError, QpackState},
};

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
    /// The MAX_PUSH_ID this client sent: it tolerates pushes, cancelling them
    max_push_id: OnceLock<u64>,
    /// The first pushes seen, and the push IDs promised or pushed
    pushes: Mutex<(Vec<crate::ext::PushEvent>, HashSet<u64>)>,
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
            max_push_id: OnceLock::new(),
            pushes: Mutex::new((Vec::new(), HashSet::new())),
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

    pub(crate) fn set_max_push_id(&self, max_push_id: u64) {
        let _ = self.max_push_id.set(max_push_id);
    }

    /// Whether this client sent MAX_PUSH_ID, so it tolerates pushes
    pub(crate) fn accepts_pushes(&self) -> bool {
        self.max_push_id.get().is_some()
    }

    fn pushes_lock(&self) -> MutexGuard<'_, (Vec<crate::ext::PushEvent>, HashSet<u64>)> {
        self.pushes
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
    }

    /// Records a push the client saw (the first 16), sending CANCEL_PUSH for a promise whose
    /// push stream has not arrived.
    pub(crate) fn record_push(&self, event: crate::ext::PushEvent) {
        let mut pushes = self.pushes_lock();
        match event {
            //= https://www.rfc-editor.org/rfc/rfc9114#section-7.2.3
            //# A client SHOULD NOT send a CANCEL_PUSH frame
            //# when it has already received a corresponding push stream.
            crate::ext::PushEvent::Promise { push_id, .. } if pushes.1.insert(push_id) => {
                self.send_control_frame(&crate::ext::ControlFrame::CancelPush(push_id));
            }
            crate::ext::PushEvent::Stream { push_id, .. } => {
                pushes.1.insert(push_id);
            }
            _ => (),
        }
        if pushes.0.len() < 16 {
            pushes.0.push(event);
        }
    }

    pub(crate) fn pushes(&self) -> Vec<crate::ext::PushEvent> {
        self.pushes_lock().0.clone()
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
