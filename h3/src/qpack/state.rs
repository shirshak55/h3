//! A connection's QPACK dynamic table state, shared by the connection driver, which reads and
//! writes the QPACK streams, and its request streams, which decode field sections.

use std::{
    collections::HashMap,
    task::{Context, Poll, Waker},
};

use bytes::{Buf, BufMut, Bytes, BytesMut};

use crate::ext::QpackEncoderUse;

use super::{
    decoder::{decode_stateless, Decoded, Decoder, DecoderError},
    encode_stateless,
    encoder::{DynamicEncoder, EncoderError},
    stream::{HeaderAck, InsertCountIncrement, StreamCancel},
    HeaderField,
};

/// Decoding with the dynamic table the peer's encoder stream builds
struct DynamicDecoding {
    decoder: Decoder,
    /// The SETTINGS_QPACK_BLOCKED_STREAMS this endpoint advertised
    max_blocked: usize,
    /// Streams whose field section waits for encoder-stream instructions: its Required Insert
    /// Count and the stream's waker
    blocked: HashMap<u64, (usize, Waker)>,
    /// The Known Received Count the peer's encoder learned from our decoder stream
    known_received: usize,
    /// Encoder-stream bytes not yet forming a whole instruction
    pending: BytesMut,
    usage: QpackEncoderUse,
}

#[derive(Default)]
pub(crate) struct QpackState {
    decoding: Option<DynamicDecoding>,
    encoding: Option<DynamicEncoder>,
    /// Decoder-stream instructions waiting for the connection driver to write them
    pub(crate) decoder_out: BytesMut,
    /// Encoder-stream instructions waiting for the connection driver to write them
    pub(crate) encoder_out: BytesMut,
}

impl std::fmt::Debug for QpackState {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("QpackState")
            .field("decoding", &self.decoding.is_some())
            .field("encoding", &self.encoding.is_some())
            .finish_non_exhaustive()
    }
}

impl QpackState {
    /// Decodes field sections with a dynamic table of up to `max_capacity` bytes, as advertised
    /// in SETTINGS_QPACK_MAX_TABLE_CAPACITY, letting up to `max_blocked` streams wait for it.
    pub(crate) fn enable_decoding(&mut self, max_capacity: usize, max_blocked: usize) {
        self.decoding = Some(DynamicDecoding {
            decoder: Decoder::new(max_capacity),
            max_blocked,
            blocked: HashMap::new(),
            known_received: 0,
            pending: BytesMut::new(),
            usage: QpackEncoderUse::default(),
        });
    }

    pub(crate) fn decoding(&self) -> bool {
        self.decoding.is_some()
    }

    pub(crate) fn encoder_use(&self) -> Option<QpackEncoderUse> {
        self.decoding
            .as_ref()
            .map(|decoding| decoding.usage.clone())
    }

    /// Decodes the field section `block` received on `stream_id`. With a dynamic table, a
    /// section whose Required Insert Count is not reached yet waits for the encoder-stream
    /// instructions it depends on (a blocked stream); a decoded one that references the table
    /// is acknowledged, with the inserts no acknowledgment covered yet.
    pub(crate) fn poll_decode(
        &mut self,
        cx: &mut Context<'_>,
        stream_id: u64,
        block: &Bytes,
        max_size: u64,
    ) -> Poll<Result<Decoded, DecoderError>> {
        let Some(decoding) = &mut self.decoding else {
            return Poll::Ready(decode_stateless(&mut block.clone(), max_size));
        };

        let decoded = match decoding.decoder.decode_header(&mut block.clone(), max_size) {
            Err(DecoderError::MissingRefs(required)) => {
                if let Some((_, waker)) = decoding.blocked.get_mut(&stream_id) {
                    waker.clone_from(cx.waker());
                    return Poll::Pending;
                }
                //= https://www.rfc-editor.org/rfc/rfc9204#section-2.1.2
                //# If a decoder encounters more blocked streams than it promised to
                //# support, it MUST treat this as a connection error of type
                //# QPACK_DECOMPRESSION_FAILED.
                if decoding.blocked.len() >= decoding.max_blocked {
                    return Poll::Ready(Err(DecoderError::MissingRefs(required)));
                }
                decoding.usage.blocked_sections += 1;
                decoding
                    .blocked
                    .insert(stream_id, (required, cx.waker().clone()));
                return Poll::Pending;
            }
            Err(e) => return Poll::Ready(Err(e)),
            Ok(decoded) => decoded,
        };
        decoding.blocked.remove(&stream_id);

        //= https://www.rfc-editor.org/rfc/rfc9204#section-4.4.1
        //# After processing an encoded field section whose declared Required
        //# Insert Count is not zero, the decoder emits a Section Acknowledgment
        //# instruction.
        if decoded.required_insert_count > 0 {
            decoding.usage.dynamic_sections += 1;
            HeaderAck(stream_id).encode(&mut self.decoder_out);
            decoding.known_received = decoding.known_received.max(decoded.required_insert_count);
        }
        let inserted = decoding.decoder.total_inserted();
        if inserted > decoding.known_received {
            InsertCountIncrement((inserted - decoding.known_received) as u64)
                .encode(&mut self.decoder_out);
            decoding.known_received = inserted;
        }

        if decoded.mem_size > max_size {
            return Poll::Ready(Err(DecoderError::HeaderTooLong(decoded.mem_size)));
        }
        Poll::Ready(Ok(decoded))
    }

    /// Applies instructions read from the peer's encoder stream and wakes the streams they
    /// unblock.
    pub(crate) fn on_encoder_stream(&mut self, data: &mut impl Buf) -> Result<(), DecoderError> {
        let Some(decoding) = &mut self.decoding else {
            return Ok(());
        };
        while data.has_remaining() {
            let chunk = data.chunk();
            decoding.pending.put_slice(chunk);
            let len = chunk.len();
            data.advance(len);
        }
        decoding
            .decoder
            .on_encoder_stream(&mut decoding.pending, &mut decoding.usage)?;

        let inserted = decoding.decoder.total_inserted();
        decoding.blocked.retain(|_, (required, waker)| {
            let unblocked = *required <= inserted;
            if unblocked {
                waker.wake_by_ref();
            }
            !unblocked
        });
        Ok(())
    }

    /// Encodes field sections with the peer's dynamic table, of up to `max_capacity` bytes, once
    /// its SETTINGS allow one.
    pub(crate) fn enable_encoding(&mut self, max_capacity: usize) {
        self.encoding = Some(DynamicEncoder::new(max_capacity));
    }

    /// Takes the peer's QPACK SETTINGS: the encoder sets the dynamic table capacity they allow.
    pub(crate) fn on_peer_settings(&mut self, max_capacity: u64, max_blocked: u64) {
        if let Some(encoding) = &mut self.encoding {
            encoding.on_peer_settings(max_capacity, max_blocked, &mut self.encoder_out);
        }
    }

    /// Encodes a field section sent on `stream_id` into `block`, with the peer's dynamic table
    /// when it is in use, statelessly otherwise. Returns the section's size; with the dynamic
    /// table, a section larger than `max_size` is not encoded.
    pub(crate) fn encode(
        &mut self,
        stream_id: u64,
        fields: impl IntoIterator<Item = HeaderField>,
        block: &mut BytesMut,
        max_size: u64,
    ) -> Result<u64, EncoderError> {
        let Some(encoding) = self.encoding.as_mut().filter(|e| e.active()) else {
            return encode_stateless(block, fields);
        };
        let fields: Vec<HeaderField> = fields.into_iter().collect();
        let size = fields.iter().map(|f| f.mem_size() as u64).sum();
        if size > max_size {
            return Ok(size);
        }
        encoding.encode(stream_id, block, &mut self.encoder_out, fields)
    }

    /// Whether field sections are encoded with the peer's dynamic table
    pub(crate) fn encoding_active(&self) -> bool {
        self.encoding.as_ref().is_some_and(|e| e.active())
    }

    /// Applies instructions read from the peer's decoder stream.
    pub(crate) fn on_decoder_stream(&mut self, data: &mut impl Buf) -> Result<(), EncoderError> {
        match &mut self.encoding {
            Some(encoding) => encoding.on_decoder_stream(data),
            None => Ok(()),
        }
    }

    /// Forgets a stream abandoned before its end and, as its unprocessed field sections may
    /// reference the dynamic table, tells the peer's encoder (Stream Cancellation).
    pub(crate) fn cancel_stream(&mut self, stream_id: u64) {
        let Some(decoding) = &mut self.decoding else {
            return;
        };
        decoding.blocked.remove(&stream_id);
        //= https://www.rfc-editor.org/rfc/rfc9204#section-4.4.2
        //# When a stream is reset or reading is abandoned, the decoder emits a
        //# Stream Cancellation instruction.
        StreamCancel(stream_id).encode(&mut self.decoder_out);
    }
}
