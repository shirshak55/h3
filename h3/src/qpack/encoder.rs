use std::{
    cmp,
    collections::{HashMap, VecDeque},
    io::Cursor,
};

use bytes::{Buf, BufMut, BytesMut};

use super::{
    block::{
        HeaderPrefix, Indexed, IndexedWithPostBase, Literal, LiteralWithNameRef,
        LiteralWithPostBaseNameRef,
    },
    dynamic::{
        DynamicInsertionResult, DynamicLookupResult, DynamicTable, DynamicTableEncoder,
        Error as DynamicTableError,
    },
    parse_error::ParseError,
    prefix_int::Error as IntError,
    prefix_string::Error as StringError,
    static_::StaticTable,
    stream::{
        DecoderInstruction, Duplicate, DynamicTableSizeUpdate, HeaderAck, InsertCountIncrement,
        InsertWithNameRef, InsertWithoutNameRef, StreamCancel,
    },
    HeaderField,
};

#[derive(Debug, PartialEq)]
pub enum EncoderError {
    Insertion(DynamicTableError),
    InvalidString(StringError),
    InvalidInteger(IntError),
    UnknownDecoderInstruction(u8),
    /// A Section Acknowledgment for a stream with no unacknowledged field section
    UnexpectedAck(u64),
    /// An Insert Count Increment of 0 or beyond the inserts sent
    InvalidIncrement(u64),
}

impl std::error::Error for EncoderError {}

impl std::fmt::Display for EncoderError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            EncoderError::Insertion(e) => write!(f, "dynamic table insertion: {:?}", e),
            EncoderError::InvalidString(e) => write!(f, "could not parse string: {}", e),
            EncoderError::InvalidInteger(e) => write!(f, "could not parse integer: {}", e),
            EncoderError::UnknownDecoderInstruction(e) => {
                write!(f, "got unkown decoder instruction: {}", e)
            }
            EncoderError::UnexpectedAck(id) => {
                write!(
                    f,
                    "section acknowledgment for stream {} without one due",
                    id
                )
            }
            EncoderError::InvalidIncrement(n) => write!(f, "invalid insert count increment {}", n),
        }
    }
}

pub struct Encoder {
    table: DynamicTable,
}

impl Encoder {
    pub fn encode<W, T, H>(
        &mut self,
        stream_id: u64,
        block: &mut W,
        encoder_buf: &mut W,
        fields: T,
    ) -> Result<usize, EncoderError>
    where
        W: BufMut,
        T: IntoIterator<Item = H>,
        H: AsRef<HeaderField>,
    {
        let mut required_ref = 0;
        let mut block_buf = Vec::new();
        let mut encoder = self.table.encoder(stream_id);

        for field in fields {
            if let Some(reference) =
                Self::encode_field(&mut encoder, &mut block_buf, encoder_buf, field.as_ref())?
            {
                required_ref = cmp::max(required_ref, reference);
            }
        }

        HeaderPrefix::new(
            required_ref,
            encoder.base(),
            encoder.total_inserted(),
            encoder.max_size(),
        )
        .encode(block);
        block.put(block_buf.as_slice());

        encoder.commit(required_ref);

        Ok(required_ref)
    }

    pub fn on_decoder_recv<R: Buf>(&mut self, read: &mut R) -> Result<(), EncoderError> {
        while let Some(instruction) = Action::parse(read)? {
            match instruction {
                Action::Untrack(stream_id) => self.table.untrack_block(stream_id)?,
                Action::StreamCancel(stream_id) => {
                    // Untrack block twice, as this stream might have a trailer in addition to
                    // the header. Failures are ignored as blocks might have been acked before
                    // cancellation.
                    if self.table.untrack_block(stream_id).is_ok() {
                        let _ = self.table.untrack_block(stream_id);
                    }
                }
                Action::ReceivedRefIncrement(increment) => {
                    self.table.update_largest_received(increment)
                }
            }
        }
        Ok(())
    }

    fn encode_field<W: BufMut>(
        table: &mut DynamicTableEncoder,
        block: &mut Vec<u8>,
        encoder: &mut W,
        field: &HeaderField,
    ) -> Result<Option<usize>, EncoderError> {
        if let Some(index) = StaticTable::find(field) {
            Indexed::Static(index).encode(block);
            return Ok(None);
        }

        if let DynamicLookupResult::Relative { index, absolute } = table.find(field) {
            Indexed::Dynamic(index).encode(block);
            return Ok(Some(absolute));
        }

        let reference = match table.insert(field)? {
            DynamicInsertionResult::Duplicated {
                relative,
                postbase,
                absolute,
            } => {
                Duplicate(relative).encode(encoder);
                IndexedWithPostBase(postbase).encode(block);
                Some(absolute)
            }
            DynamicInsertionResult::Inserted { postbase, absolute } => {
                InsertWithoutNameRef::new(field.name.clone(), field.value.clone())
                    .encode(encoder)?;
                IndexedWithPostBase(postbase).encode(block);
                Some(absolute)
            }
            DynamicInsertionResult::InsertedWithStaticNameRef {
                postbase,
                index,
                absolute,
            } => {
                InsertWithNameRef::new_static(index, field.value.clone()).encode(encoder)?;
                IndexedWithPostBase(postbase).encode(block);
                Some(absolute)
            }
            DynamicInsertionResult::InsertedWithNameRef {
                postbase,
                relative,
                absolute,
            } => {
                InsertWithNameRef::new_dynamic(relative, field.value.clone()).encode(encoder)?;
                IndexedWithPostBase(postbase).encode(block);
                Some(absolute)
            }
            DynamicInsertionResult::NotInserted(lookup_result) => match lookup_result {
                DynamicLookupResult::Static(index) => {
                    LiteralWithNameRef::new_static(index, field.value.clone()).encode(block)?;
                    None
                }
                DynamicLookupResult::Relative { index, absolute } => {
                    LiteralWithNameRef::new_dynamic(index, field.value.clone()).encode(block)?;
                    Some(absolute)
                }
                DynamicLookupResult::PostBase { index, absolute } => {
                    LiteralWithPostBaseNameRef::new(index, field.value.clone()).encode(block)?;
                    Some(absolute)
                }
                DynamicLookupResult::NotFound => {
                    Literal::new(field.name.clone(), field.value.clone()).encode(block)?;
                    None
                }
            },
        };
        Ok(reference)
    }
}

impl Default for Encoder {
    fn default() -> Self {
        Self {
            table: DynamicTable::new(),
        }
    }
}

/// Field names whose values rarely repeat, or are secrets, which are not inserted
const NOT_INSERTED: &[&[u8]] = &[
    b":path",
    b"content-length",
    b"date",
    b"etag",
    b"last-modified",
    b"if-modified-since",
    b"if-none-match",
    b"authorization",
    b"proxy-authorization",
];

/// A field section sent with a Required Insert Count above 0, not acknowledged yet
struct Section {
    required: usize,
    /// The smallest absolute index it references
    min_ref: usize,
}

/// How a field line is encoded
enum Line {
    Static(usize),
    StaticName(usize, Vec<u8>),
    Dynamic(usize),
    DynamicName(usize, Vec<u8>),
    Literal(HeaderField),
}

/// Encodes field sections with the peer's dynamic table.
///
/// Once the peer's SETTINGS allow a capacity, it sets the smaller of that and its own
/// maximum. Each field without an exact static-table match is referenced if an identical
/// entry exists, else inserted (unless its name is in `NOT_INSERTED` or it would take more
/// than half the capacity) and referenced; otherwise it is a literal with a static or dynamic
/// name reference when one exists. An entry not yet acknowledged by the peer is only
/// referenced while the stream may block (the peer's SETTINGS_QPACK_BLOCKED_STREAMS), and an
/// entry is evicted only once acknowledged and no unacknowledged section references it. As in
/// Chrome's encoder, the oldest entries, up to a quarter of the capacity, are draining: they
/// are not referenced, but duplicated, so they can be evicted.
/// Strings are Huffman-encoded; the Base is the Required Insert Count, so references are
/// relative, never post-base.
pub(crate) struct DynamicEncoder {
    /// The largest capacity this encoder sets
    max_capacity: usize,
    /// The peer's SETTINGS_QPACK_MAX_TABLE_CAPACITY, which the Required Insert Count encoding uses
    peer_max_capacity: usize,
    /// The peer's SETTINGS_QPACK_BLOCKED_STREAMS
    peer_max_blocked: usize,
    capacity: usize,
    entries: VecDeque<HeaderField>,
    /// The absolute index of `entries[0]`: how many entries were evicted
    dropped: usize,
    size: usize,
    known_received: usize,
    sections: HashMap<u64, VecDeque<Section>>,
    /// Decoder-stream bytes not yet forming a whole instruction
    pending: BytesMut,
}

impl DynamicEncoder {
    pub fn new(max_capacity: usize) -> Self {
        Self {
            max_capacity,
            peer_max_capacity: 0,
            peer_max_blocked: 0,
            capacity: 0,
            entries: VecDeque::new(),
            dropped: 0,
            size: 0,
            known_received: 0,
            sections: HashMap::new(),
            pending: BytesMut::new(),
        }
    }

    /// Takes the peer's QPACK SETTINGS, setting the table capacity if they allow one.
    pub fn on_peer_settings(
        &mut self,
        max_capacity: u64,
        max_blocked: u64,
        encoder: &mut BytesMut,
    ) {
        self.peer_max_capacity = usize::try_from(max_capacity).unwrap_or(usize::MAX);
        self.peer_max_blocked = usize::try_from(max_blocked).unwrap_or(usize::MAX);
        self.capacity = self.max_capacity.min(self.peer_max_capacity);
        if self.capacity > 0 {
            DynamicTableSizeUpdate(self.capacity).encode(encoder);
        }
    }

    /// Whether field sections use the dynamic table: the peer allowed a capacity
    pub fn active(&self) -> bool {
        self.capacity > 0
    }

    fn inserted(&self) -> usize {
        self.dropped + self.entries.len()
    }

    fn blocking(&self, stream_id: u64) -> bool {
        self.sections
            .get(&stream_id)
            .is_some_and(|sections| sections.iter().any(|s| s.required > self.known_received))
    }

    /// The newest entry equal to `field`, or only its name
    fn find(&self, field: &HeaderField, name_only: bool) -> Option<usize> {
        self.entries
            .iter()
            .rposition(|entry| {
                entry.name == field.name && (name_only || entry.value == field.value)
            })
            .map(|pos| self.dropped + pos)
    }

    /// The absolute index below which entries are draining: the oldest entries until a quarter
    /// of the capacity would be free
    fn draining_index(&self) -> usize {
        let required = self.capacity / 4;
        let mut free = self.capacity - self.size;
        let mut index = self.dropped;
        for entry in &self.entries {
            if free >= required {
                break;
            }
            free += entry.mem_size();
            index += 1;
        }
        index
    }

    /// Inserts `field`, evicting acknowledged entries no section references, below `min_ref`
    fn insert(
        &mut self,
        field: &HeaderField,
        min_ref: usize,
        encoder: &mut BytesMut,
    ) -> Result<Option<usize>, EncoderError> {
        let size = field.mem_size();
        if NOT_INSERTED.contains(&field.name.as_ref()) || size * 2 > self.capacity {
            return Ok(None);
        }
        let pinned = self
            .sections
            .values()
            .flatten()
            .map(|s| s.min_ref)
            .fold(min_ref, cmp::min)
            .min(self.known_received);
        let mut evict = 0;
        let mut free = self.capacity - self.size;
        while free < size {
            if self.dropped + evict >= pinned {
                return Ok(None);
            }
            free += self.entries[evict].mem_size();
            evict += 1;
        }

        let inserted = self.inserted();
        let kept = self.dropped + evict;
        if let Some(absolute) = self.find(field, false).filter(|&a| a >= kept) {
            Duplicate(inserted - 1 - absolute).encode(encoder);
        } else if let Some(index) = StaticTable::find_name(&field.name) {
            InsertWithNameRef::new_static(index, field.value.clone()).encode(encoder)?;
        } else if let Some(absolute) = self.find(field, true).filter(|&a| a >= kept) {
            InsertWithNameRef::new_dynamic(inserted - 1 - absolute, field.value.clone())
                .encode(encoder)?;
        } else {
            InsertWithoutNameRef::new(field.name.clone(), field.value.clone()).encode(encoder)?;
        }
        for evicted in self.entries.drain(..evict) {
            self.size -= evicted.mem_size();
        }
        self.dropped += evict;
        self.size += size;
        self.entries.push_back(field.clone());
        Ok(Some(inserted))
    }

    /// Encodes a field section sent on `stream_id` into `block`, and the inserts it makes into
    /// `encoder`. Returns the section's size.
    pub fn encode<T, H>(
        &mut self,
        stream_id: u64,
        block: &mut BytesMut,
        encoder: &mut BytesMut,
        fields: T,
    ) -> Result<u64, EncoderError>
    where
        T: IntoIterator<Item = H>,
        H: AsRef<HeaderField>,
    {
        //= https://www.rfc-editor.org/rfc/rfc9204#section-2.1.2
        //# An encoder MUST limit the number of streams that could become blocked
        //# to the value of SETTINGS_QPACK_BLOCKED_STREAMS at all times.
        let blocking = self
            .sections
            .keys()
            .filter(|&&id| self.blocking(id))
            .count();
        let may_block = self.blocking(stream_id) || blocking < self.peer_max_blocked;

        let mut size = 0;
        let mut min_ref = usize::MAX;
        let mut required = 0;
        let mut lines = Vec::new();
        for field in fields {
            let field = field.as_ref();
            size += field.mem_size() as u64;
            let known_received = self.known_received;
            let draining = self.draining_index();
            let usable =
                |absolute: usize| absolute >= draining && (absolute < known_received || may_block);
            let exact = self.find(field, false);
            // An identical entry that is not draining is only not referenceable yet
            let insert = !exact.is_some_and(|absolute| absolute >= draining);
            let line = if let Some(index) = StaticTable::find(field) {
                Line::Static(index)
            } else if let Some(absolute) = exact.filter(|&a| usable(a)) {
                Line::Dynamic(absolute)
            } else if let Some(absolute) = match insert {
                true => self.insert(field, min_ref, encoder)?.filter(|_| may_block),
                false => None,
            } {
                Line::Dynamic(absolute)
            } else if let Some(index) = StaticTable::find_name(&field.name) {
                Line::StaticName(index, field.value.to_vec())
            } else if let Some(absolute) = self.find(field, true).filter(|&a| usable(a)) {
                Line::DynamicName(absolute, field.value.to_vec())
            } else {
                Line::Literal(field.clone())
            };
            if let Line::Dynamic(absolute) | Line::DynamicName(absolute, _) = line {
                min_ref = min_ref.min(absolute);
                required = required.max(absolute + 1);
            }
            lines.push(line);
        }

        HeaderPrefix::new(required, required, self.inserted(), self.peer_max_capacity)
            .encode(block);
        for line in lines {
            match line {
                Line::Static(index) => Indexed::Static(index).encode(block),
                Line::StaticName(index, value) => {
                    LiteralWithNameRef::new_static(index, value).encode(block)?
                }
                Line::Dynamic(absolute) => Indexed::Dynamic(required - 1 - absolute).encode(block),
                Line::DynamicName(absolute, value) => {
                    LiteralWithNameRef::new_dynamic(required - 1 - absolute, value).encode(block)?
                }
                Line::Literal(field) => Literal::new(field.name, field.value).encode(block)?,
            }
        }
        if required > 0 {
            self.sections
                .entry(stream_id)
                .or_default()
                .push_back(Section { required, min_ref });
        }
        Ok(size)
    }

    /// Applies instructions read from the peer's decoder stream.
    pub fn on_decoder_stream(&mut self, data: &mut impl Buf) -> Result<(), EncoderError> {
        while data.has_remaining() {
            let chunk = data.chunk();
            self.pending.put_slice(chunk);
            let len = chunk.len();
            data.advance(len);
        }
        while let Some(instruction) = Action::parse(&mut self.pending)? {
            match instruction {
                //= https://www.rfc-editor.org/rfc/rfc9204#section-4.4.1
                //# If an encoder receives a Section Acknowledgment instruction referring
                //# to a stream on which every encoded field section with a non-zero
                //# Required Insert Count has already been acknowledged, this MUST be
                //# treated as a connection error of type QPACK_DECODER_STREAM_ERROR.
                Action::Untrack(stream_id) => {
                    let sections = self
                        .sections
                        .get_mut(&stream_id)
                        .ok_or(EncoderError::UnexpectedAck(stream_id))?;
                    let section = sections
                        .pop_front()
                        .ok_or(EncoderError::UnexpectedAck(stream_id))?;
                    if sections.is_empty() {
                        self.sections.remove(&stream_id);
                    }
                    self.known_received = self.known_received.max(section.required);
                }
                Action::StreamCancel(stream_id) => {
                    self.sections.remove(&stream_id);
                }
                //= https://www.rfc-editor.org/rfc/rfc9204#section-4.4.3
                //# An encoder that receives an Increment field equal to zero, or one
                //# that increases the Known Received Count beyond what the encoder has
                //# sent, MUST treat this as a connection error of type
                //# QPACK_DECODER_STREAM_ERROR.
                Action::ReceivedRefIncrement(increment) => {
                    if increment == 0 || self.known_received + increment > self.inserted() {
                        return Err(EncoderError::InvalidIncrement(increment as u64));
                    }
                    self.known_received += increment;
                }
            }
        }
        Ok(())
    }
}

pub fn encode_stateless<W, T, H>(block: &mut W, fields: T) -> Result<u64, EncoderError>
where
    W: BufMut,
    T: IntoIterator<Item = H>,
    H: AsRef<HeaderField>,
{
    let mut size = 0;

    HeaderPrefix::new(0, 0, 0, 0).encode(block);
    for field in fields {
        let field = field.as_ref();

        if let Some(index) = StaticTable::find(field) {
            Indexed::Static(index).encode(block);
        } else if let Some(index) = StaticTable::find_name(&field.name) {
            LiteralWithNameRef::new_static(index, field.value.clone()).encode(block)?;
        } else {
            Literal::new(field.name.clone(), field.value.clone()).encode(block)?;
        }

        size += field.mem_size() as u64;
    }
    Ok(size)
}

#[cfg(test)]
impl From<DynamicTable> for Encoder {
    fn from(table: DynamicTable) -> Encoder {
        Encoder { table }
    }
}

// Action to apply to the encoder table, given an instruction received from the decoder.
#[derive(Debug, PartialEq)]
enum Action {
    ReceivedRefIncrement(usize),
    Untrack(u64),
    StreamCancel(u64),
}

impl Action {
    fn parse<R: Buf>(read: &mut R) -> Result<Option<Action>, EncoderError> {
        if read.remaining() < 1 {
            return Ok(None);
        }

        let mut buf = Cursor::new(read.chunk());
        let first = buf.chunk()[0];
        let instruction = match DecoderInstruction::decode(first) {
            DecoderInstruction::Unknown => {
                return Err(EncoderError::UnknownDecoderInstruction(first))
            }
            DecoderInstruction::InsertCountIncrement => InsertCountIncrement::decode(&mut buf)?
                .map(|x| Action::ReceivedRefIncrement(x.0 as usize)),
            DecoderInstruction::HeaderAck => {
                HeaderAck::decode(&mut buf)?.map(|x| Action::Untrack(x.0))
            }
            DecoderInstruction::StreamCancel => {
                StreamCancel::decode(&mut buf)?.map(|x| Action::StreamCancel(x.0))
            }
        };

        if instruction.is_some() {
            let pos = buf.position();
            read.advance(pos as usize);
        }

        Ok(instruction)
    }
}

pub fn set_dynamic_table_size<W: BufMut>(
    table: &mut DynamicTable,
    encoder: &mut W,
    size: usize,
) -> Result<(), EncoderError> {
    table.set_max_size(size)?;
    DynamicTableSizeUpdate(size).encode(encoder);
    Ok(())
}

impl From<DynamicTableError> for EncoderError {
    fn from(e: DynamicTableError) -> Self {
        EncoderError::Insertion(e)
    }
}

impl From<StringError> for EncoderError {
    fn from(e: StringError) -> Self {
        EncoderError::InvalidString(e)
    }
}

impl From<ParseError> for EncoderError {
    fn from(e: ParseError) -> Self {
        match e {
            ParseError::Integer(x) => EncoderError::InvalidInteger(x),
            ParseError::String(x) => EncoderError::InvalidString(x),
            ParseError::InvalidPrefix(x) => EncoderError::UnknownDecoderInstruction(x),
            _ => unreachable!(),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    use crate::qpack::tests::helpers::{build_table, TABLE_SIZE};

    #[allow(clippy::type_complexity)]
    fn check_encode_field(
        init_fields: &[HeaderField],
        field: &[HeaderField],
        check: &dyn Fn(&mut Cursor<&mut Vec<u8>>, &mut Cursor<&mut Vec<u8>>),
    ) {
        let mut table = build_table();
        table.set_max_size(TABLE_SIZE).unwrap();
        check_encode_field_table(&mut table, init_fields, field, 1, check);
    }

    #[allow(clippy::type_complexity)]
    fn check_encode_field_table(
        table: &mut DynamicTable,
        init_fields: &[HeaderField],
        field: &[HeaderField],
        stream_id: u64,
        check: &dyn Fn(&mut Cursor<&mut Vec<u8>>, &mut Cursor<&mut Vec<u8>>),
    ) {
        for field in init_fields {
            table.put(field.clone()).unwrap();
        }

        let mut encoder = Vec::new();
        let mut block = Vec::new();
        let mut enc_table = table.encoder(stream_id);

        for field in field {
            Encoder::encode_field(&mut enc_table, &mut block, &mut encoder, field).unwrap();
        }

        enc_table.commit(field.len());

        let mut read_block = Cursor::new(&mut block);
        let mut read_encoder = Cursor::new(&mut encoder);
        check(&mut read_block, &mut read_encoder);
    }

    #[test]
    fn encode_static() {
        let field = HeaderField::new(":method", "GET");
        check_encode_field(&[], &[field], &|mut b, e| {
            assert_eq!(Indexed::decode(&mut b), Ok(Indexed::Static(17)));
            assert_eq!(e.get_ref().len(), 0);
        });
    }

    #[test]
    fn encode_static_nameref() {
        let field = HeaderField::new("location", "/bar");
        check_encode_field(&[], &[field], &|mut b, mut e| {
            assert_eq!(
                IndexedWithPostBase::decode(&mut b),
                Ok(IndexedWithPostBase(0))
            );
            assert_eq!(
                InsertWithNameRef::decode(&mut e),
                Ok(Some(InsertWithNameRef::new_static(12, "/bar")))
            );
        });
    }

    #[test]
    fn encode_static_nameref_indexed_in_dynamic() {
        let field = HeaderField::new("location", "/bar");
        check_encode_field(&[field.clone()], &[field], &|mut b, e| {
            assert_eq!(Indexed::decode(&mut b), Ok(Indexed::Dynamic(0)));
            assert_eq!(e.get_ref().len(), 0);
        });
    }

    #[test]
    fn encode_dynamic_insert() {
        let field = HeaderField::new("foo", "bar");
        check_encode_field(&[], &[field], &|mut b, mut e| {
            assert_eq!(
                IndexedWithPostBase::decode(&mut b),
                Ok(IndexedWithPostBase(0))
            );
            assert_eq!(
                InsertWithoutNameRef::decode(&mut e),
                Ok(Some(InsertWithoutNameRef::new("foo", "bar")))
            );
        });
    }

    #[test]
    fn encode_dynamic_insert_nameref() {
        let field = HeaderField::new("foo", "bar");
        check_encode_field(
            &[field.clone(), HeaderField::new("baz", "bar")],
            &[field.with_value("quxx")],
            &|mut b, mut e| {
                assert_eq!(
                    IndexedWithPostBase::decode(&mut b),
                    Ok(IndexedWithPostBase(0))
                );
                assert_eq!(
                    InsertWithNameRef::decode(&mut e),
                    Ok(Some(InsertWithNameRef::new_dynamic(1, "quxx")))
                );
            },
        );
    }

    #[test]
    fn encode_literal() {
        let mut table = build_table();
        table.set_max_size(0).unwrap();
        let field = HeaderField::new("foo", "bar");
        check_encode_field_table(&mut table, &[], &[field], 1, &|mut b, e| {
            assert_eq!(Literal::decode(&mut b), Ok(Literal::new("foo", "bar")));
            assert_eq!(e.get_ref().len(), 0);
        });
    }

    #[test]
    fn encode_literal_nameref() {
        let mut table = build_table();
        table.set_max_size(63).unwrap();
        let field = HeaderField::new("foo", "bar");

        check_encode_field_table(&mut table, &[], &[field.clone()], 1, &|mut b, _| {
            assert_eq!(
                IndexedWithPostBase::decode(&mut b),
                Ok(IndexedWithPostBase(0))
            );
        });
        check_encode_field_table(
            &mut table,
            &[field.clone()],
            &[field.with_value("quxx")],
            2,
            &|mut b, e| {
                assert_eq!(
                    LiteralWithNameRef::decode(&mut b),
                    Ok(LiteralWithNameRef::new_dynamic(0, "quxx"))
                );
                assert_eq!(e.get_ref().len(), 0);
            },
        );
    }

    #[test]
    fn encode_literal_postbase_nameref() {
        let mut table = build_table();
        table.set_max_size(63).unwrap();
        let field = HeaderField::new("foo", "bar");
        check_encode_field_table(
            &mut table,
            &[],
            &[field.clone(), field.with_value("quxx")],
            1,
            &|mut b, mut e| {
                assert_eq!(
                    IndexedWithPostBase::decode(&mut b),
                    Ok(IndexedWithPostBase(0))
                );
                assert_eq!(
                    LiteralWithPostBaseNameRef::decode(&mut b),
                    Ok(LiteralWithPostBaseNameRef::new(0, "quxx"))
                );
                assert_eq!(
                    InsertWithoutNameRef::decode(&mut e),
                    Ok(Some(InsertWithoutNameRef::new("foo", "bar")))
                );
            },
        );
    }

    #[test]
    fn encode_with_header_block() {
        let mut table = build_table();

        for idx in 1..5 {
            table
                .put(HeaderField::new(
                    format!("foo{}", idx),
                    format!("bar{}", idx),
                ))
                .unwrap();
        }

        let mut encoder_buf = Vec::new();
        let mut block = Vec::new();
        let mut encoder = Encoder::from(table);

        let fields = vec![
            HeaderField::new(":method", "GET"),
            HeaderField::new("foo1", "bar1"),
            HeaderField::new("foo3", "new bar3"),
            HeaderField::new(":method", "staticnameref"),
            HeaderField::new("newfoo", "newbar"),
        ]
        .into_iter();

        assert_eq!(
            encoder.encode(1, &mut block, &mut encoder_buf, fields),
            Ok(7)
        );

        let mut read_block = Cursor::new(&mut block);
        let mut read_encoder = Cursor::new(&mut encoder_buf);

        assert_eq!(
            InsertWithNameRef::decode(&mut read_encoder),
            Ok(Some(InsertWithNameRef::new_dynamic(1, "new bar3")))
        );
        assert_eq!(
            InsertWithNameRef::decode(&mut read_encoder),
            Ok(Some(InsertWithNameRef::new_static(
                StaticTable::find_name(&b":method"[..]).unwrap(),
                "staticnameref"
            )))
        );
        assert_eq!(
            InsertWithoutNameRef::decode(&mut read_encoder),
            Ok(Some(InsertWithoutNameRef::new("newfoo", "newbar")))
        );

        assert_eq!(
            HeaderPrefix::decode(&mut read_block)
                .unwrap()
                .get(7, TABLE_SIZE),
            Ok((7, 4))
        );
        assert_eq!(Indexed::decode(&mut read_block), Ok(Indexed::Static(17)));
        assert_eq!(Indexed::decode(&mut read_block), Ok(Indexed::Dynamic(3)));
        assert_eq!(
            IndexedWithPostBase::decode(&mut read_block),
            Ok(IndexedWithPostBase(0))
        );
        assert_eq!(
            IndexedWithPostBase::decode(&mut read_block),
            Ok(IndexedWithPostBase(1))
        );
        assert_eq!(
            IndexedWithPostBase::decode(&mut read_block),
            Ok(IndexedWithPostBase(2))
        );
        assert_eq!(read_block.get_ref().len() as u64, read_block.position());
    }

    #[test]
    fn decoder_block_ack() {
        let mut table = build_table();

        let field = HeaderField::new("foo", "bar");
        check_encode_field_table(
            &mut table,
            &[],
            &[field.clone(), field.with_value("quxx")],
            2,
            &|_, _| {},
        );

        let mut buf = vec![];
        let mut encoder = Encoder::from(table);

        HeaderAck(2).encode(&mut buf);
        let mut cur = Cursor::new(&buf);
        assert_eq!(Action::parse(&mut cur), Ok(Some(Action::Untrack(2))));

        let mut cur = Cursor::new(&buf);
        assert_eq!(encoder.on_decoder_recv(&mut cur), Ok(()),);

        let mut cur = Cursor::new(&buf);
        assert_eq!(
            encoder.on_decoder_recv(&mut cur),
            Err(EncoderError::Insertion(DynamicTableError::UnknownStreamId(
                2
            )))
        );
    }

    #[test]
    fn decoder_stream_cacnceled() {
        let mut table = build_table();

        let field = HeaderField::new("foo", "bar");
        check_encode_field_table(
            &mut table,
            &[],
            &[field.clone(), field.with_value("quxx")],
            2,
            &|_, _| {},
        );

        let mut buf = vec![];

        StreamCancel(2).encode(&mut buf);
        let mut cur = Cursor::new(&buf);
        assert_eq!(Action::parse(&mut cur), Ok(Some(Action::StreamCancel(2))));
    }

    #[test]
    fn decoder_accept_truncated() {
        let mut buf = vec![];
        StreamCancel(2321).encode(&mut buf);

        let mut cur = Cursor::new(&buf[..2]); // trucated prefix_int
        assert_eq!(Action::parse(&mut cur), Ok(None));

        let mut cur = Cursor::new(&buf);
        assert_eq!(
            Action::parse(&mut cur),
            Ok(Some(Action::StreamCancel(2321)))
        );
    }

    #[test]
    fn decoder_unknown_stream() {
        let mut table = build_table();

        check_encode_field_table(
            &mut table,
            &[],
            &[HeaderField::new("foo", "bar")],
            2,
            &|_, _| {},
        );
        let mut encoder = Encoder::from(table);

        let mut buf = vec![];
        HeaderAck(4).encode(&mut buf);

        let mut cur = Cursor::new(&buf);
        assert_eq!(
            encoder.on_decoder_recv(&mut cur),
            Err(EncoderError::Insertion(DynamicTableError::UnknownStreamId(
                4
            )))
        );
    }

    #[test]
    fn insert_count() {
        let mut buf = vec![];
        InsertCountIncrement(4).encode(&mut buf);

        let mut cur = Cursor::new(&buf);
        assert_eq!(
            Action::parse(&mut cur),
            Ok(Some(Action::ReceivedRefIncrement(4)))
        );

        let mut encoder = Encoder {
            table: build_table(),
        };

        let mut cur = Cursor::new(&buf);
        assert_eq!(encoder.on_decoder_recv(&mut cur), Ok(()));
    }
}
