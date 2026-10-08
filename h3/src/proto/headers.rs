use std::{
    collections::HashMap,
    convert::TryFrom,
    fmt,
    iter::{IntoIterator, Iterator},
    str::FromStr,
};

use http::{
    header::{self, HeaderName, HeaderValue},
    uri::{self, Authority, Parts, PathAndQuery, Scheme, Uri},
    Extensions, HeaderMap, Method, StatusCode,
};

use crate::{
    ext::{HeaderOrder, Protocol, PseudoOrder},
    qpack::HeaderField,
};

#[derive(Debug)]
#[cfg_attr(test, derive(PartialEq, Clone))]
pub struct Header {
    pseudo: Pseudo,
    fields: HeaderMap,
    /// The fields' names in the order to encode them in
    order: HeaderOrder,
    /// The pseudo-header fields' names in the order received or to encode them in
    pseudo_order: PseudoOrder,
}

#[allow(clippy::len_without_is_empty)]
impl Header {
    /// Creates a new `Header` frame data suitable for sending a request
    pub fn request(
        method: Method,
        uri: Uri,
        fields: HeaderMap,
        ext: Extensions,
    ) -> Result<Self, HeaderError> {
        match (uri.authority(), fields.get("host")) {
            (None, None) => Err(HeaderError::MissingAuthority),
            (Some(a), Some(h)) if a.as_str() != h => Err(HeaderError::ContradictedAuthority),
            _ => Ok(Self {
                pseudo: Pseudo::request(method, uri, ext),
                fields,
                order: HeaderOrder::default(),
                pseudo_order: PseudoOrder::default(),
            }),
        }
    }

    pub fn response(status: StatusCode, fields: HeaderMap) -> Self {
        Self {
            pseudo: Pseudo::response(status),
            fields,
            order: HeaderOrder::default(),
            pseudo_order: PseudoOrder::default(),
        }
    }

    pub fn trailer(fields: HeaderMap) -> Self {
        Self {
            //= https://www.rfc-editor.org/rfc/rfc9114#section-4.3
            //# Pseudo-header fields MUST NOT appear in trailer
            //# sections.
            pseudo: Pseudo::default(),
            fields,
            order: HeaderOrder::default(),
            pseudo_order: PseudoOrder::default(),
        }
    }

    /// Encodes the fields in `order`.
    pub fn set_order(&mut self, order: HeaderOrder) {
        self.order = order;
    }

    /// Encodes the pseudo-header fields in `order`.
    pub fn set_pseudo_order(&mut self, order: PseudoOrder) {
        self.pseudo_order = order;
    }

    /// The order the pseudo-header fields were decoded in.
    pub fn pseudo_order(&self) -> &PseudoOrder {
        &self.pseudo_order
    }

    pub fn into_request_parts(
        self,
    ) -> Result<(Method, Uri, Option<Protocol>, HeaderMap), HeaderError> {
        let mut uri = Uri::builder();

        if let Some(path) = self.pseudo.path {
            uri = uri.path_and_query(path.as_str().as_bytes());
        }

        if let Some(scheme) = self.pseudo.scheme {
            uri = uri.scheme(scheme.as_str().as_bytes());
        }

        //= https://www.rfc-editor.org/rfc/rfc9114#section-4.3.1
        //# If the :scheme pseudo-header field identifies a scheme that has a
        //# mandatory authority component (including "http" and "https"), the
        //# request MUST contain either an :authority pseudo-header field or a
        //# Host header field.

        //= https://www.rfc-editor.org/rfc/rfc9114#section-4.3.1
        //= type=TODO
        //# If the scheme does not have a mandatory authority component and none
        //# is provided in the request target, the request MUST NOT contain the
        //# :authority pseudo-header or Host header fields.
        match (self.pseudo.authority, self.fields.get("host")) {
            (None, None) => return Err(HeaderError::MissingAuthority),
            (Some(a), None) => uri = uri.authority(a.as_str().as_bytes()),
            (None, Some(h)) => uri = uri.authority(h.as_bytes()),
            //= https://www.rfc-editor.org/rfc/rfc9114#section-4.3.1
            //# If both fields are present, they MUST contain the same value.
            (Some(a), Some(h)) if a.as_str() != h => {
                return Err(HeaderError::ContradictedAuthority)
            }
            (Some(_), Some(h)) => uri = uri.authority(h.as_bytes()),
        }

        let method = self.pseudo.method.ok_or(HeaderError::MissingMethod)?;
        // `:protocol` belongs to an extended CONNECT (RFC 8441 §4, RFC 9220 §3): on any other
        // request it is malformed (RFC 9114 §4.3.1).
        if self.pseudo.protocol.is_some() && method != Method::CONNECT {
            return Err(HeaderError::ProtocolWithoutConnect);
        }

        Ok((
            method,
            // When empty host field is built into an uri it fails
            //= https://www.rfc-editor.org/rfc/rfc9114#section-4.3.1
            //# If these fields are present, they MUST NOT be
            //# empty.
            uri.build().map_err(HeaderError::InvalidRequest)?,
            self.pseudo.protocol,
            self.fields,
        ))
    }

    pub fn into_response_parts(self) -> Result<(StatusCode, HeaderMap), HeaderError> {
        //= https://www.rfc-editor.org/rfc/rfc9114#section-4.3.2
        //= type=implication
        //# For responses, a single ":status" pseudo-header field is defined that
        //# carries the HTTP status code; see Section 15 of [HTTP].  This pseudo-
        //# header field MUST be included in all responses; otherwise, the
        //# response is malformed (see Section 4.1.2).
        Ok((
            self.pseudo.status.ok_or(HeaderError::MissingStatus)?,
            self.fields,
        ))
    }

    pub fn into_fields(self) -> HeaderMap {
        self.fields
    }

    pub fn len(&self) -> usize {
        self.pseudo.len() + self.fields.len()
    }

    pub fn size(&self) -> usize {
        self.pseudo.len() + self.fields.len()
    }

    #[cfg(test)]
    pub(crate) fn authory_mut(&mut self) -> &mut Option<Authority> {
        &mut self.pseudo.authority
    }
}

impl IntoIterator for Header {
    type Item = HeaderField;
    type IntoIter = HeaderIter;
    fn into_iter(self) -> Self::IntoIter {
        // A `HeaderMap` can't hold repeats interleaved with other names, so fields in a
        // recorded order are encoded from a list.
        let (fields, ordered) = if self.order.0.is_empty() {
            (self.fields, Vec::new())
        } else {
            let ordered = ordered_fields(&self.fields, &self.order.0);
            (HeaderMap::new(), ordered)
        };
        HeaderIter {
            pseudo_order: self.pseudo_order.0.into_iter(),
            pseudo: Some(self.pseudo),
            last_header_name: None,
            fields: fields.into_iter(),
            ordered: ordered.into_iter(),
        }
    }
}

/// `fields` in `order`, each listed name taking the next value of that name, then the
/// values `order` doesn't list, in map order.
fn ordered_fields(fields: &HeaderMap, order: &[HeaderName]) -> Vec<(HeaderName, HeaderValue)> {
    let mut values = HashMap::new();
    let mut out = Vec::with_capacity(fields.len());
    for name in order {
        let listed = values
            .entry(name)
            .or_insert_with_key(|name| fields.get_all(*name).iter());
        if let Some(value) = listed.next() {
            out.push((name.clone(), value.clone()));
        }
    }
    for name in fields.keys() {
        let rest = values
            .remove(name)
            .unwrap_or_else(|| fields.get_all(name).iter());
        out.extend(rest.map(|value| (name.clone(), value.clone())));
    }
    out
}

pub struct HeaderIter {
    pseudo_order: std::vec::IntoIter<&'static str>,
    pseudo: Option<Pseudo>,
    last_header_name: Option<HeaderName>,
    fields: header::IntoIter<HeaderValue>,
    ordered: std::vec::IntoIter<(HeaderName, HeaderValue)>,
}

impl Iterator for HeaderIter {
    type Item = HeaderField;

    fn next(&mut self) -> Option<Self::Item> {
        //= https://www.rfc-editor.org/rfc/rfc9114#section-4.3
        //# All pseudo-header fields MUST appear in the header section before
        //# regular header fields.
        if let Some(ref mut pseudo) = self.pseudo {
            for name in self.pseudo_order.by_ref() {
                let field = match name {
                    ":method" => pseudo.method.take().map(|m| (name, m.as_str()).into()),
                    ":scheme" => pseudo
                        .scheme
                        .take()
                        .map(|s| (name, s.as_str().as_bytes()).into()),
                    ":authority" => pseudo
                        .authority
                        .take()
                        .map(|a| (name, a.as_str().as_bytes()).into()),
                    ":path" => pseudo
                        .path
                        .take()
                        .map(|p| (name, p.as_str().as_bytes()).into()),
                    ":protocol" => pseudo
                        .protocol
                        .take()
                        .map(|p| (name, p.as_str().as_bytes()).into()),
                    _ => None,
                };
                if field.is_some() {
                    return field;
                }
            }

            if let Some(method) = pseudo.method.take() {
                return Some((":method", method.as_str()).into());
            }

            if let Some(scheme) = pseudo.scheme.take() {
                return Some((":scheme", scheme.as_str().as_bytes()).into());
            }

            if let Some(authority) = pseudo.authority.take() {
                return Some((":authority", authority.as_str().as_bytes()).into());
            }

            if let Some(path) = pseudo.path.take() {
                return Some((":path", path.as_str().as_bytes()).into());
            }

            if let Some(status) = pseudo.status.take() {
                return Some((":status", status.as_str()).into());
            }

            if let Some(protocol) = pseudo.protocol.take() {
                return Some((":protocol", protocol.as_str().as_bytes()).into());
            }
        }

        self.pseudo = None;

        for (new_header_name, header_value) in self.fields.by_ref() {
            if let Some(new) = new_header_name {
                self.last_header_name = Some(new);
            }
            if let (Some(ref n), v) = (&self.last_header_name, header_value) {
                return Some((n.as_str(), v.as_bytes()).into());
            }
        }

        self.ordered
            .next()
            .map(|(name, value)| (name.as_str(), value.as_bytes()).into())
    }
}

impl TryFrom<Vec<HeaderField>> for Header {
    type Error = HeaderError;
    fn try_from(headers: Vec<HeaderField>) -> Result<Self, Self::Error> {
        let mut fields = HeaderMap::try_with_capacity(headers.len())
            .map_err(|_| HeaderError::TooManyFields(headers.len()))?;
        let mut pseudo = Pseudo::default();
        let mut pseudo_order = Vec::new();

        for field in headers.into_iter() {
            let (name, value) = field.into_inner();
            match Field::parse(name, value)? {
                Field::Method(m) => {
                    pseudo_order.push(":method");
                    pseudo.method = Some(m);
                    pseudo.len += 1;
                }
                Field::Scheme(s) => {
                    pseudo_order.push(":scheme");
                    pseudo.scheme = Some(s);
                    pseudo.len += 1;
                }
                Field::Authority(a) => {
                    pseudo_order.push(":authority");
                    pseudo.authority = Some(a);
                    pseudo.len += 1;
                }
                Field::Path(p) => {
                    pseudo_order.push(":path");
                    pseudo.path = Some(p);
                    pseudo.len += 1;
                }
                Field::Status(s) => {
                    pseudo.status = Some(s);
                    pseudo.len += 1;
                }
                Field::Header((n, v)) => {
                    fields.append(n, v);
                }
                Field::Protocol(p) => {
                    pseudo_order.push(":protocol");
                    pseudo.protocol = Some(p);
                    pseudo.len += 1;
                }
            }
        }

        Ok(Header {
            pseudo,
            fields,
            order: HeaderOrder::default(),
            pseudo_order: PseudoOrder(pseudo_order),
        })
    }
}

enum Field {
    Method(Method),
    Scheme(Scheme),
    Authority(Authority),
    Path(PathAndQuery),
    Status(StatusCode),
    Protocol(Protocol),
    Header((HeaderName, HeaderValue)),
}

impl Field {
    fn parse<N, V>(name: N, value: V) -> Result<Self, HeaderError>
    where
        N: AsRef<[u8]>,
        V: AsRef<[u8]>,
    {
        let name = name.as_ref();
        if name.is_empty() {
            return Err(HeaderError::InvalidHeaderName("name is empty".into()));
        }

        //= https://www.rfc-editor.org/rfc/rfc9114#section-10.3
        //# Requests or responses containing invalid field names MUST be treated
        //# as malformed.

        //= https://www.rfc-editor.org/rfc/rfc9114#section-10.3
        //# Any request or response that contains a
        //# character not permitted in a field value MUST be treated as
        //# malformed.

        //= https://www.rfc-editor.org/rfc/rfc9114#section-4.2
        //= type=implication
        //# A request or
        //# response containing uppercase characters in field names MUST be
        //# treated as malformed.

        if name[0] != b':' {
            return Ok(Field::Header((
                HeaderName::from_lowercase(name).map_err(|_| HeaderError::invalid_name(name))?,
                HeaderValue::from_bytes(value.as_ref())
                    .map_err(|_| HeaderError::invalid_value(name, value))?,
            )));
        }

        Ok(match name {
            b":scheme" => Field::Scheme(try_value(name, value)?),
            //= https://www.rfc-editor.org/rfc/rfc9114#section-4.3.1
            //# If these fields are present, they MUST NOT be
            //# empty.
            b":authority" => Field::Authority(try_value(name, value)?),
            b":path" => Field::Path(try_value(name, value)?),
            b":method" => Field::Method(
                Method::from_bytes(value.as_ref())
                    .map_err(|_| HeaderError::invalid_value(name, value))?,
            ),
            b":status" => Field::Status(
                StatusCode::from_bytes(value.as_ref())
                    .map_err(|_| HeaderError::invalid_value(name, value))?,
            ),
            b":protocol" => Field::Protocol(try_value(name, value)?),
            _ => return Err(HeaderError::invalid_name(name)),
        })
    }
}

fn try_value<N, V, R>(name: N, value: V) -> Result<R, HeaderError>
where
    N: AsRef<[u8]>,
    V: AsRef<[u8]>,
    R: FromStr,
{
    let (name, value) = (name.as_ref(), value.as_ref());
    let s = std::str::from_utf8(value).map_err(|_| HeaderError::invalid_value(name, value))?;
    R::from_str(s).map_err(|_| HeaderError::invalid_value(name, value))
}

/// Pseudo-header fields have the same purpose as data from the first line of HTTP/1.X,
/// but are conveyed along with other headers. For example ':method' and ':path' in a
/// request, and ':status' in a response. They must be placed before all other fields,
/// start with ':', and be lowercase.
/// See RFC7540 section 8.1.2.1. for more details.
#[derive(Debug, Default)]
#[cfg_attr(test, derive(PartialEq, Clone))]
struct Pseudo {
    //= https://www.rfc-editor.org/rfc/rfc9114#section-4.3
    //= type=implication
    //# Endpoints MUST NOT
    //# generate pseudo-header fields other than those defined in this
    //# document.

    // Request
    method: Option<Method>,
    scheme: Option<Scheme>,
    authority: Option<Authority>,
    path: Option<PathAndQuery>,

    // Response
    status: Option<StatusCode>,

    protocol: Option<Protocol>,

    len: usize,
}

#[allow(clippy::len_without_is_empty)]
impl Pseudo {
    fn request(method: Method, uri: Uri, ext: Extensions) -> Self {
        let Parts {
            scheme,
            authority,
            path_and_query,
            ..
        } = uri::Parts::from(uri);

        //= https://www.rfc-editor.org/rfc/rfc9114#section-4.3.1
        //= type=implication
        //# This pseudo-header field MUST NOT be empty for "http" or "https"
        //# URIs; "http" or "https" URIs that do not contain a path component
        //# MUST include a value of / (ASCII 0x2f).
        let path = path_and_query.map_or_else(
            || PathAndQuery::from_static("/"),
            |path| {
                if path.path().is_empty() && method != Method::OPTIONS {
                    PathAndQuery::from_static("/")
                } else {
                    path
                }
            },
        );

        // If the method is connect, the `:protocol` pseudo-header MAY be defined
        //
        // See: [https://www.rfc-editor.org/rfc/rfc8441#section-4]
        let protocol = if method == Method::CONNECT {
            ext.get::<Protocol>().cloned()
        } else {
            None
        };

        let len = 3 + authority.is_some() as usize + protocol.is_some() as usize;

        //= https://www.rfc-editor.org/rfc/rfc9114#section-4.3
        //= type=implication
        //# Pseudo-header fields defined for requests MUST NOT appear
        //# in responses; pseudo-header fields defined for responses MUST NOT
        //# appear in requests.

        //= https://www.rfc-editor.org/rfc/rfc9114#section-4.3.1
        //= type=implication
        //# All HTTP/3 requests MUST include exactly one value for the :method,
        //# :scheme, and :path pseudo-header fields, unless the request is a
        //# CONNECT request; see Section 4.4.
        Self {
            method: Some(method),
            scheme: scheme.or(Some(Scheme::HTTPS)),
            authority,
            path: Some(path),
            status: None,
            protocol,
            len,
        }
    }

    fn response(status: StatusCode) -> Self {
        //= https://www.rfc-editor.org/rfc/rfc9114#section-4.3
        //= type=implication
        //# Pseudo-header fields defined for requests MUST NOT appear
        //# in responses; pseudo-header fields defined for responses MUST NOT
        //# appear in requests.
        Pseudo {
            method: None,
            scheme: None,
            authority: None,
            path: None,
            status: Some(status),
            len: 1,
            protocol: None,
        }
    }

    fn len(&self) -> usize {
        self.len
    }
}

#[derive(Debug)]
pub enum HeaderError {
    InvalidHeaderName(String),
    InvalidHeaderValue(String),
    InvalidRequest(http::Error),
    MissingMethod,
    MissingStatus,
    MissingAuthority,
    ContradictedAuthority,
    ProtocolWithoutConnect,
    /// More field lines than a [`HeaderMap`] holds
    TooManyFields(usize),
}

impl HeaderError {
    fn invalid_name<N>(name: N) -> Self
    where
        N: AsRef<[u8]>,
    {
        HeaderError::InvalidHeaderName(format!("{:?}", name.as_ref()))
    }

    fn invalid_value<N, V>(name: N, value: V) -> Self
    where
        N: AsRef<[u8]>,
        V: AsRef<[u8]>,
    {
        HeaderError::InvalidHeaderValue(format!(
            "{:?} {:?}",
            String::from_utf8_lossy(name.as_ref()),
            value.as_ref()
        ))
    }
}

impl std::error::Error for HeaderError {}

impl fmt::Display for HeaderError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            HeaderError::InvalidHeaderName(h) => write!(f, "invalid header name: {}", h),
            HeaderError::InvalidHeaderValue(v) => write!(f, "invalid header value: {}", v),
            HeaderError::InvalidRequest(r) => write!(f, "invalid request: {}", r),
            HeaderError::MissingMethod => write!(f, "missing method in request headers"),
            HeaderError::MissingStatus => write!(f, "missing status in response headers"),
            HeaderError::MissingAuthority => write!(f, "missing authority"),
            HeaderError::ContradictedAuthority => {
                write!(f, "uri and authority field are in contradiction")
            }
            HeaderError::ProtocolWithoutConnect => {
                write!(
                    f,
                    ":protocol pseudo-header on a request whose method is not CONNECT"
                )
            }
            HeaderError::TooManyFields(count) => {
                write!(f, "{count} field lines, more than a header map holds")
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use assert_matches::assert_matches;

    #[test]
    fn request_has_no_authority_nor_host() {
        //= https://www.rfc-editor.org/rfc/rfc9114#section-4.3.1
        //= type=test
        //# If the :scheme pseudo-header field identifies a scheme that has a
        //# mandatory authority component (including "http" and "https"), the
        //# request MUST contain either an :authority pseudo-header field or a
        //# Host header field.
        let headers = Header::try_from(vec![(b":method", Method::GET.as_str()).into()]).unwrap();
        assert!(headers.pseudo.authority.is_none());
        assert_matches!(
            headers.into_request_parts(),
            Err(HeaderError::MissingAuthority)
        );
    }

    #[test]
    fn request_has_empty_authority() {
        //= https://www.rfc-editor.org/rfc/rfc9114#section-4.3.1
        //= type=test
        //# If these fields are present, they MUST NOT be
        //# empty.
        assert_matches!(
            Header::try_from(vec![
                (b":method", Method::GET.as_str()).into(),
                (b":authority", b"").into(),
            ]),
            Err(HeaderError::InvalidHeaderValue(_))
        );
    }

    #[test]
    fn request_has_empty_host() {
        //= https://www.rfc-editor.org/rfc/rfc9114#section-4.3.1
        //= type=test
        //# If these fields are present, they MUST NOT be
        //# empty.
        let headers = Header::try_from(vec![
            (b":method", Method::GET.as_str()).into(),
            (b"host", b"").into(),
        ])
        .unwrap();
        assert_matches!(
            headers.into_request_parts(),
            Err(HeaderError::InvalidRequest(_))
        );
    }

    #[test]
    fn request_has_authority() {
        //= https://www.rfc-editor.org/rfc/rfc9114#section-4.3.1
        //= type=test
        //# If the :scheme pseudo-header field identifies a scheme that has a
        //# mandatory authority component (including "http" and "https"), the
        //# request MUST contain either an :authority pseudo-header field or a
        //# Host header field.
        let headers = Header::try_from(vec![
            (b":method", Method::GET.as_str()).into(),
            (b":authority", b"test.com").into(),
        ])
        .unwrap();
        assert_matches!(headers.into_request_parts(), Ok(_));
    }

    #[test]
    fn request_has_host() {
        //= https://www.rfc-editor.org/rfc/rfc9114#section-4.3.1
        //= type=test
        //# If the :scheme pseudo-header field identifies a scheme that has a
        //# mandatory authority component (including "http" and "https"), the
        //# request MUST contain either an :authority pseudo-header field or a
        //# Host header field.
        let headers = Header::try_from(vec![
            (b":method", Method::GET.as_str()).into(),
            (b"host", b"test.com").into(),
        ])
        .unwrap();
        assert!(headers.pseudo.authority.is_none());
        assert_matches!(headers.into_request_parts(), Ok(_));
    }

    #[test]
    fn request_has_same_host_and_authority() {
        //= https://www.rfc-editor.org/rfc/rfc9114#section-4.3.1
        //= type=test
        //# If both fields are present, they MUST contain the same value.
        let headers = Header::try_from(vec![
            (b":method", Method::GET.as_str()).into(),
            (b":authority", b"test.com").into(),
            (b"host", b"test.com").into(),
        ])
        .unwrap();
        assert_matches!(headers.into_request_parts(), Ok(_));
    }
    #[test]
    fn request_has_different_host_and_authority() {
        //= https://www.rfc-editor.org/rfc/rfc9114#section-4.3.1
        //= type=test
        //# If both fields are present, they MUST contain the same value.
        let headers = Header::try_from(vec![
            (b":method", Method::GET.as_str()).into(),
            (b":authority", b"authority.com").into(),
            (b"host", b"host.com").into(),
        ])
        .unwrap();
        assert_matches!(
            headers.into_request_parts(),
            Err(HeaderError::ContradictedAuthority)
        );
    }

    #[test]
    fn preserves_duplicate_headers() {
        let headers = Header::try_from(vec![
            (b":method", Method::GET.as_str()).into(),
            (b":authority", b"test.com").into(),
            (b"set-cookie", b"foo=foo").into(),
            (b"set-cookie", b"bar=bar").into(),
            (b"other-header", b"other-header-value").into(),
        ])
        .unwrap();

        assert_eq!(
            headers
                .clone()
                .into_iter()
                .filter(|h| h.name.as_ref() == b"set-cookie")
                .collect::<Vec<_>>(),
            vec![
                HeaderField {
                    name: std::borrow::Cow::Borrowed(b"set-cookie"),
                    value: std::borrow::Cow::Borrowed(b"foo=foo")
                },
                HeaderField {
                    name: std::borrow::Cow::Borrowed(b"set-cookie"),
                    value: std::borrow::Cow::Borrowed(b"bar=bar")
                }
            ]
        );
        assert_eq!(
            headers
                .into_iter()
                .filter(|h| h.name.as_ref() == b"other-header")
                .collect::<Vec<_>>(),
            vec![HeaderField {
                name: std::borrow::Cow::Borrowed(b"other-header"),
                value: std::borrow::Cow::Borrowed(b"other-header-value")
            },]
        );
    }

    #[test]
    fn ordered_fields_take_listed_values_then_the_rest() {
        let mut fields = HeaderMap::new();
        for (name, value) in [
            ("x", "1"),
            ("y", "a"),
            ("x", "2"),
            ("x", "3"),
            ("z", "q"),
            ("y", "b"),
        ] {
            fields.append(name, HeaderValue::from_static(value));
        }
        let order = ["y", "x", "w", "x", "y", "y"].map(HeaderName::from_static);
        let fields: Vec<_> = ordered_fields(&fields, &order)
            .into_iter()
            .map(|(name, value)| (name.to_string(), value.to_str().unwrap().to_owned()))
            .collect();
        assert_eq!(
            fields,
            [
                ("y", "a"),
                ("x", "1"),
                ("x", "2"),
                ("y", "b"),
                ("x", "3"),
                ("z", "q")
            ]
            .map(|(name, value)| (name.to_owned(), value.to_owned()))
        );
    }
}
