//! BER input — parses TLVs from a byte slice, zero-copy.
//!
//! Mirrors `BerReader` (`runtime/include/asn1cpp/codec/BerReader.hpp`):
//! same `read_tlv`/`peek_tag` entry points, same definite- and
//! indefinite-length support (X.690 §8.1.3.2 — see `Reader::read_tlv`'s
//! own doc for how the two forms end up producing identical `.value` bytes).

use crate::ber::tag::{read_tag, Tag};
use crate::nesting::Depth;
use std::fmt;

/// Decode failure with a human-readable reason and the byte offset it
/// occurred at. Mirrors `asn1::DecodeError` (`runtime/include/asn1cpp/Error.hpp`).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DecodeError {
    pub message: String,
    pub pos: usize,
}

impl DecodeError {
    // pub, not pub(crate): both fields are already public (a caller could
    // always construct one via struct-literal syntax), and generated code
    // (e.g. RustBackend's ENUMERATED decode closures, "invalid <Type> value:
    // <n>") legitimately needs to raise a DecodeError of its own from
    // outside this crate — restricting just the constructor bought no real
    // encapsulation.
    pub fn new(message: impl Into<String>, pos: usize) -> DecodeError {
        DecodeError { message: message.into(), pos }
    }
}

impl fmt::Display for DecodeError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{} (at byte {})", self.message, self.pos)
    }
}

impl std::error::Error for DecodeError {}

/// One decoded TLV: tag plus a zero-copy view of the value bytes.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Tlv<'a> {
    pub tag: Tag,
    pub value: &'a [u8],
}

/// Decoded length octets — definite (`len` bytes) or indefinite (X.690
/// §8.1.3.2, a lone `0x80` length octet; `len` meaningless when
/// `indefinite` is true, actual content extent found by scanning for the
/// matching end-of-contents octets instead, see `Reader::read_tlv`).
struct LengthResult {
    len: usize,
    indefinite: bool,
}

/// Cursor over a read-only byte slice.
pub struct Reader<'a> {
    data: &'a [u8],
    pos: usize,
    pub(crate) depth: Depth,
    pub(crate) contained: Option<&'a crate::containing::ContainedOptions>,
}

impl<'a> Reader<'a> {
    /// @brief Set the contained-value settings of this decode; nested
    ///        readers inherit them.
    pub fn set_contained(&mut self, opts: &'a crate::containing::ContainedOptions) {
        self.contained = Some(opts);
    }

    pub fn new(data: &'a [u8]) -> Reader<'a> {
        Reader { data, pos: 0, depth: Depth::default(), contained: None }
    }

    /// @brief Opens a reader over a nested value's bytes (a TLV's
    ///        contents) at this reader's decode nesting depth.
    /// @see `crate::nesting`.
    pub(crate) fn sub<'b>(&self, data: &'b [u8]) -> Reader<'b>
    where
        'a: 'b,
    {
        Reader { data, pos: 0, depth: self.depth, contained: self.contained }
    }

    pub fn at_end(&self) -> bool {
        self.pos >= self.data.len()
    }

    pub fn pos(&self) -> usize {
        self.pos
    }

    /// All bytes from the current position to the end, unconsumed —
    /// used for ANY's raw capture: an X.208 legacy type, not defined at
    /// all in the current standard (X.680/X.690 don't mention it), with
    /// X.691's own note that a legacy ANY should be treated as an open
    /// type. No fixed tag to validate against, so decoding it is "take
    /// whatever bytes are here", not a typed TLV read — mirrors
    /// `AnyBerHandler::decode` (`runtime/src/BerCodec.cpp`), which reads
    /// `r.remaining()` from whatever (already outer-tag-bounded) reader
    /// it's handed.
    pub fn remaining(&self) -> &'a [u8] {
        &self.data[self.pos..]
    }

    /// Peek at the next TLV's tag without consuming it — used for CHOICE
    /// dispatch (inspect the tag, then decide which variant's decoder to call).
    pub fn peek_tag(&self) -> Option<Tag> {
        let mut p = self.pos;
        read_tag(self.data, &mut p)
    }

    /// Read and consume the length octets of a TLV.
    /// @see X.690 §8.1.3 — Length octets.
    fn read_length(&mut self) -> Result<LengthResult, DecodeError> {
        let first = *self
            .data
            .get(self.pos)
            .ok_or_else(|| DecodeError::new("unexpected end of data reading length", self.pos))?;
        self.pos += 1;
        if first == 0x80 {
            return Ok(LengthResult { len: 0, indefinite: true });
        }
        if first & 0x80 == 0 {
            return Ok(LengthResult { len: first as usize, indefinite: false });
        }
        let n = (first & 0x7F) as usize;
        if n > 8 {
            return Err(DecodeError::new(
                format!("unsupported length encoding ({} bytes)", n),
                self.pos - 1,
            ));
        }
        if self.data.len() - self.pos < n {
            return Err(DecodeError::new("truncated length field", self.pos));
        }
        let mut len = 0usize;
        for _ in 0..n {
            len = (len << 8) | self.data[self.pos] as usize;
            self.pos += 1;
        }
        Ok(LengthResult { len, indefinite: false })
    }

    /// Read and consume one complete TLV — definite or indefinite length
    /// (X.690 §8.1.3.2). Mirrors `BerReader::read_tlv`'s slow path
    /// (`runtime/include/asn1cpp/codec/BerReader.hpp`): an indefinite-length
    /// TLV's content runs until the matching end-of-contents octets (`00
    /// 00`) at the *same* nesting depth — found by walking nested TLVs
    /// (each definite one skipped by its own length, each nested
    /// indefinite one incrementing depth), not by a byte count. `value`
    /// ends up holding exactly the same bytes either way (definite or
    /// indefinite), EOC octets excluded — so everything downstream of
    /// `read_tlv` (which only ever inspects `.value` as "N content bytes to
    /// walk") needs no indefinite-specific handling at all; unlike the C++
    /// `TLV` struct, no `indefinite` flag is carried on `Tlv` here, nothing
    /// downstream needs to know which form produced these bytes.
    pub fn read_tlv(&mut self) -> Result<Tlv<'a>, DecodeError> {
        let tag = read_tag(self.data, &mut self.pos)
            .ok_or_else(|| DecodeError::new("truncated or oversized tag", self.pos))?;
        let len_r = self.read_length()?;
        if len_r.indefinite {
            // X.690 §8.1.3.2: indefinite-length is only valid for
            // constructed encodings — a primitive value has no TLVs nested
            // inside it to scan for an EOC marker within.
            if !tag.constructed {
                return Err(DecodeError::new(
                    "indefinite-length encoding on primitive type",
                    self.pos - 1,
                ));
            }
            let start = self.pos;
            let mut depth = 1usize;
            while depth > 0 {
                if self.data.len() - self.pos < 2 {
                    return Err(DecodeError::new("unterminated indefinite-length encoding", self.pos));
                }
                if self.data[self.pos] == 0x00 && self.data[self.pos + 1] == 0x00 {
                    self.pos += 2;
                    depth -= 1;
                } else {
                    let inner_tag = read_tag(self.data, &mut self.pos)
                        .ok_or_else(|| DecodeError::new("truncated or oversized tag", self.pos))?;
                    let inner_len = self.read_length()?;
                    if inner_len.indefinite {
                        if !inner_tag.constructed {
                            return Err(DecodeError::new(
                                "indefinite-length encoding on primitive type",
                                self.pos - 1,
                            ));
                        }
                        depth += 1;
                    } else {
                        if self.data.len() - self.pos < inner_len.len {
                            return Err(DecodeError::new("truncated nested value", self.pos));
                        }
                        self.pos += inner_len.len;
                    }
                }
            }
            let end = self.pos - 2;
            return Ok(Tlv { tag, value: &self.data[start..end] });
        }
        let len = len_r.len;
        if self.data.len() - self.pos < len {
            return Err(DecodeError::new(
                format!("need {} bytes but only {} remain", len, self.data.len() - self.pos),
                self.pos,
            ));
        }
        let value = &self.data[self.pos..self.pos + len];
        self.pos += len;
        Ok(Tlv { tag, value })
    }

    /// @brief Checks that the next TLV of an ANY value is a complete BER
    ///        encoding: a constructed one's contents are themselves
    ///        complete encodings (X.690 §3.2), and an indefinite length is
    ///        closed by its end-of-contents octets (§8.1.3.6, §8.1.5). Tag
    ///        0 is otherwise refused, except an exact `00 00` in a
    ///        definite-length frame, which asn1c keeps as legacy ANY bytes
    ///        (`octet_string_ber_read_child`). Mirrors C++
    ///        `check_any_tlv` (`BerCodec.cpp`).
    /// @param depth    Nesting level inside the ANY, limited to
    ///                 [`crate::nesting::MAX_DECODE_DEPTH`].
    /// @param definite True when the enclosing frame has a definite length.
    /// @return `Err` describing the first malformed TLV.
    fn check_any_tlv(&mut self, depth: u32, definite: bool) -> Result<(), DecodeError> {
        if depth > crate::nesting::MAX_DECODE_DEPTH {
            return Err(DecodeError::new(
                format!("ANY contents nest deeper than {} levels", crate::nesting::MAX_DECODE_DEPTH),
                self.pos,
            ));
        }
        if definite && self.data[self.pos..].starts_with(&[0, 0]) {
            self.pos += 2;
            return Ok(());
        }
        let tag = read_tag(self.data, &mut self.pos)
            .ok_or_else(|| DecodeError::new("truncated or oversized tag", self.pos))?;
        if tag.class == crate::ber::tag::TagClass::Universal && tag.number == 0 {
            return Err(DecodeError::new("end-of-contents octets outside an indefinite-length encoding", self.pos));
        }
        let len = self.read_length()?;
        if !len.indefinite {
            if self.data.len() - self.pos < len.len {
                return Err(DecodeError::new(
                    format!("need {} bytes but only {} remain", len.len, self.data.len() - self.pos),
                    self.pos,
                ));
            }
            let value = &self.data[self.pos..self.pos + len.len];
            self.pos += len.len;
            return if tag.constructed { Reader::new(value).check_any_tlvs(depth + 1) } else { Ok(()) };
        }
        if !tag.constructed {
            return Err(DecodeError::new("indefinite-length encoding on primitive type", self.pos));
        }
        loop {
            let rest = &self.data[self.pos..];
            if rest.len() < 2 {
                return Err(DecodeError::new("unterminated indefinite-length encoding", self.pos));
            }
            if rest[0] == 0 && rest[1] == 0 {
                self.pos += 2;
                return Ok(());
            }
            self.check_any_tlv(depth + 1, false)?;
        }
    }

    /// @brief Checks that this reader, a definite-length frame, holds zero
    ///        or more complete BER encodings; see `check_any_tlv`.
    fn check_any_tlvs(mut self, depth: u32) -> Result<(), DecodeError> {
        while !self.at_end() {
            self.check_any_tlv(depth, true)?;
        }
        Ok(())
    }
}

/// @brief Checks that `data`, the octets of an ANY value, are zero or more
///        complete BER encodings (X.690 §8.1); their types are not known,
///        so their values are not decoded.
/// @return `Err` naming the first malformed TLV, as
///         `malformed ANY contents: <reason>`.
pub(crate) fn check_any_contents(data: &[u8]) -> Result<(), DecodeError> {
    Reader::new(data)
        .check_any_tlvs(0)
        .map_err(|e| DecodeError::new(format!("malformed ANY contents: {}", e.message), e.pos))
}

/// @brief Joins the segments of a constructed BIT STRING, OCTET STRING or
///        character string: `data` (the constructed contents, for an
///        indefinite length without the end-of-contents octets) holds
///        primitive or nested constructed encodings with the universal tag
///        `universal`, which are concatenated in order. Mirrors C++
///        `join_segments` / `string_contents` (`BerCodec.cpp`), with the
///        same errors.
/// @param universal  3 for BIT STRING segments, 4 for OCTET STRING segments
///                   (which character strings use too, X.690 §8.23.3).
/// @return The joined contents; for BIT STRING with the last segment's
///         unused-bits octet in front, so it decodes as a primitive one.
/// @see X.690 §8.6.4 (BIT STRING), §8.7.3 (OCTET STRING), §8.23.6.
pub(crate) fn join_segments(data: &[u8], universal: u32) -> Result<Vec<u8>, DecodeError> {
    let mut out = Vec::with_capacity(data.len());
    let bits = universal == crate::ber::tag::universal::BIT_STRING;
    if bits {
        out.push(0);
    }
    let mut unused = 0u8;
    join_into(data, universal, 1, &mut out, &mut unused)?;
    if bits {
        out[0] = unused;
    }
    if crate::debug::debug_flags() & crate::debug::DBG_BER_SEGMENTS != 0 {
        eprintln!("[BER-SEGMENTS] universal {universal}: {} contents octets joined into {}", data.len(), out.len());
    }
    Ok(out)
}

/// @brief Appends the segments in `data` to `out`; part of [`join_segments`].
/// @param depth   Nesting level, limited to [`crate::nesting::MAX_DECODE_DEPTH`].
/// @param unused  BIT STRING only: unused bits of the last segment so far.
fn join_into(data: &[u8], universal: u32, depth: u32, out: &mut Vec<u8>, unused: &mut u8) -> Result<(), DecodeError> {
    let mut r = Reader::new(data);
    if depth > crate::nesting::MAX_DECODE_DEPTH {
        return Err(DecodeError::new(
            format!("constructed string segments nest deeper than {} levels", crate::nesting::MAX_DECODE_DEPTH),
            0,
        ));
    }
    let bits = universal == crate::ber::tag::universal::BIT_STRING;
    while !r.at_end() {
        let at = r.pos();
        let seg = r.read_tlv()?;
        if seg.tag.class != crate::ber::tag::TagClass::Universal || seg.tag.number != universal {
            let msg = if bits {
                "segment of a constructed BIT STRING is not a BIT STRING"
            } else {
                "segment of a constructed string is not an OCTET STRING"
            };
            return Err(DecodeError::new(msg, at));
        }
        if seg.tag.constructed {
            join_into(seg.value, universal, depth + 1, out, unused)?;
            continue;
        }
        let mut value = seg.value;
        if bits {
            if *unused != 0 {
                return Err(DecodeError::new("BIT STRING segment other than the last has unused bits", at));
            }
            let Some((&u, rest)) = value.split_first() else {
                return Err(DecodeError::new("BIT STRING segment is empty (need at least unused-bits byte)", at));
            };
            if u > 7 || (u != 0 && rest.is_empty()) {
                return Err(DecodeError::new(
                    format!("BIT STRING segment has {u} unused bits in {} octets", rest.len()),
                    at,
                ));
            }
            *unused = u;
            value = rest;
        }
        out.extend_from_slice(value);
    }
    Ok(())
}

/// EXPLICIT tagging (X.690 §8.14.3) decode — read the
/// constructed outer TLV, check its tag, then decode the inner value from a
/// sub-`Reader` over the outer TLV's content (the complete inner natural-tag
/// encoding, unchanged). See `writer::write_explicit`'s doc comment for the
/// encode side and the IMPLICIT-vs-EXPLICIT distinction.
pub fn read_explicit<T>(
    r: &mut Reader,
    tag: Tag,
    inner_decode: impl FnOnce(&mut Reader) -> Result<T, DecodeError>,
) -> Result<T, DecodeError> {
    let tlv = r.read_tlv()?;
    if tlv.tag != tag {
        return Err(DecodeError::new(format!("expected EXPLICIT tag, got {:?}", tlv.tag), r.pos()));
    }
    let mut inner = Reader::new(tlv.value);
    inner_decode(&mut inner)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::ber::tag::universal;

    fn hex(s: &str) -> Vec<u8> {
        (0..s.len() / 2).map(|i| u8::from_str_radix(&s[2 * i..2 * i + 2], 16).unwrap()).collect()
    }

    #[test]
    fn any_contents_must_be_complete_encodings() {
        // asn1c's data-62 ANY contents: -B vectors 13/15/17/21/23 must fail.
        for bad in ["E1800000E280", "E180E2800000E3800000", "E1801305746573743200", "E180BF7B00B700", "E180BF7B05B70205000000"] {
            let e = check_any_contents(&hex(bad)).unwrap_err();
            assert!(e.message.starts_with("malformed ANY contents: "), "{bad}: {}", e.message);
        }
        assert_eq!(check_any_contents(&hex("E1800000E280")).unwrap_err().message,
                   "malformed ANY contents: unterminated indefinite-length encoding");
        // -L vector 24: an exact 00 00 in a definite frame is kept, as asn1c does.
        check_any_contents(&hex("E180BF7B05B70313017A00000000")).unwrap();
        check_any_contents(&[]).unwrap();
        check_any_contents(&hex("020105")).unwrap();
        // 00 01 is no end-of-contents octets.
        assert!(check_any_contents(&hex("0001FF")).is_err());
    }

    #[test]
    fn segments_join_in_order() {
        use crate::ber::tag::universal::{BIT_STRING, OCTET_STRING};
        // X.690 §8.23.6 example contents, then nested definite and indefinite segments.
        assert_eq!(join_segments(&hex("04034A6F6E04026573"), OCTET_STRING).unwrap(), b"Jones");
        assert_eq!(join_segments(&hex("240504034A6F6E04026573"), OCTET_STRING).unwrap(), b"Jones");
        assert_eq!(join_segments(&hex("248004034A6F6E000004026573"), OCTET_STRING).unwrap(), b"Jones");
        assert_eq!(join_segments(&[], OCTET_STRING).unwrap(), b"");
        // X.690 §8.6.4.2: the unused-bits octet of the last segment goes in front.
        assert_eq!(join_segments(&hex("0303000A3B0305045F291CD0"), BIT_STRING).unwrap(), hex("040A3B5F291CD0"));
        assert_eq!(join_segments(&[], BIT_STRING).unwrap(), hex("00"));
    }

    #[test]
    fn malformed_segments_are_refused() {
        use crate::ber::tag::universal::{BIT_STRING, OCTET_STRING};
        let err = |s: &str, u| join_segments(&hex(s), u).unwrap_err().message;
        assert_eq!(err("1A034A6F6E", OCTET_STRING), "segment of a constructed string is not an OCTET STRING");
        assert_eq!(err("04000000", OCTET_STRING), "segment of a constructed string is not an OCTET STRING");
        assert_eq!(err("040200FF", BIT_STRING), "segment of a constructed BIT STRING is not a BIT STRING");
        assert_eq!(err("03020180030200FF", BIT_STRING),
                   "BIT STRING segment other than the last has unused bits");
        assert_eq!(err("0300", BIT_STRING), "BIT STRING segment is empty (need at least unused-bits byte)");
        assert_eq!(err("030103", BIT_STRING), "BIT STRING segment has 3 unused bits in 0 octets");
    }

    #[test]
    fn segment_nesting_is_limited() {
        let deep = |n: usize| [[0x24u8, 0x80].repeat(n), vec![0x00; 2 * n]].concat();
        join_segments(&deep(200), crate::ber::tag::universal::OCTET_STRING).unwrap();
        let e = join_segments(&deep(300), crate::ber::tag::universal::OCTET_STRING).unwrap_err();
        assert_eq!(e.message, "constructed string segments nest deeper than 256 levels");
    }

    #[test]
    fn any_contents_nesting_is_limited() {
        let deep = |n: usize| [[0x30u8, 0x80].repeat(n), vec![0x00; 2 * n]].concat();
        check_any_contents(&deep(200)).unwrap();
        let e = check_any_contents(&deep(300)).unwrap_err();
        assert!(e.message.contains("nest deeper than 256 levels"), "{}", e.message);
    }

    #[test]
    fn reads_primitive_tlv() {
        let data = [0x04, 0x02, 0x68, 0x69];
        let mut r = Reader::new(&data);
        let tlv = r.read_tlv().unwrap();
        assert_eq!(tlv.tag, Tag::universal(universal::OCTET_STRING, false));
        assert_eq!(tlv.value, &[0x68, 0x69]);
        assert!(r.at_end());
    }

    #[test]
    fn reads_long_form_length() {
        let mut data = vec![0x04, 0x82, 0x01, 0x2C];
        data.extend(std::iter::repeat_n(0xAA, 300));
        let mut r = Reader::new(&data);
        let tlv = r.read_tlv().unwrap();
        assert_eq!(tlv.value.len(), 300);
    }

    #[test]
    fn peek_tag_does_not_advance() {
        let data = [0x02, 0x01, 0x05];
        let r = Reader::new(&data);
        assert_eq!(r.peek_tag(), Some(Tag::universal(universal::INTEGER, false)));
        assert_eq!(r.pos(), 0);
    }

    #[test]
    fn truncated_value_is_error() {
        let data = [0x04, 0x05, 0x68, 0x69]; // claims 5 bytes, only 2 present
        let mut r = Reader::new(&data);
        assert!(r.read_tlv().is_err());
    }

    #[test]
    fn indefinite_length_empty_sequence_decodes() {
        // SEQUENCE (0x30), indefinite length (0x80), immediately EOC (0x00 0x00).
        let data = [0x30, 0x80, 0x00, 0x00];
        let mut r = Reader::new(&data);
        let tlv = r.read_tlv().unwrap();
        assert_eq!(tlv.tag, Tag::universal(universal::SEQUENCE, true));
        assert!(tlv.value.is_empty());
        assert!(r.at_end());
    }

    #[test]
    fn indefinite_length_sequence_with_nested_definite_tlv_decodes() {
        // SEQUENCE (indefinite) containing one INTEGER 42 (definite), then EOC.
        let data = [0x30, 0x80, 0x02, 0x01, 0x2A, 0x00, 0x00];
        let mut r = Reader::new(&data);
        let tlv = r.read_tlv().unwrap();
        assert_eq!(tlv.value, &[0x02, 0x01, 0x2A]);
        assert!(r.at_end());

        // The captured content re-parses as an ordinary definite-length TLV.
        let mut inner = Reader::new(tlv.value);
        let inner_tlv = inner.read_tlv().unwrap();
        assert_eq!(inner_tlv.tag, crate::integer::INTEGER_TAG);
        assert_eq!(inner_tlv.value, &[0x2A]);
    }

    #[test]
    fn indefinite_length_nested_indefinite_tlv_decodes() {
        // Outer SEQUENCE (indefinite) containing an inner SEQUENCE
        // (indefinite, empty), then outer EOC — exercises depth tracking.
        let data = [0x30, 0x80, 0x30, 0x80, 0x00, 0x00, 0x00, 0x00];
        let mut r = Reader::new(&data);
        let tlv = r.read_tlv().unwrap();
        assert_eq!(tlv.value, &[0x30, 0x80, 0x00, 0x00]);
        assert!(r.at_end());
    }

    #[test]
    fn indefinite_length_on_primitive_type_is_rejected() {
        // OCTET STRING (0x04, primitive) can't be indefinite-length —
        // X.690 §8.1.3.2 restricts that form to constructed encodings.
        let data = [0x04, 0x80, 0x00, 0x00];
        let mut r = Reader::new(&data);
        assert!(r.read_tlv().is_err());
    }

    #[test]
    fn indefinite_length_unterminated_is_rejected() {
        let data = [0x30, 0x80, 0x02, 0x01, 0x2A]; // no EOC
        let mut r = Reader::new(&data);
        assert!(r.read_tlv().is_err());
    }

    #[test]
    fn explicit_unwraps_the_outer_tlv_and_decodes_the_inner_natural_tag() {
        // [5] EXPLICIT wrapping INTEGER 42 — same bytes writer.rs's
        // explicit_wraps_the_inner_encoding_in_an_outer_constructed_tlv test produces.
        let data = [0xA5, 0x03, 0x02, 0x01, 0x2A];
        let mut r = Reader::new(&data);
        let v = read_explicit(&mut r, Tag::context(5, true), |inner| {
            let tlv = inner.read_tlv()?;
            Ok(tlv.value[0] as i64)
        })
        .unwrap();
        assert_eq!(v, 42);
    }

    #[test]
    fn explicit_rejects_the_wrong_outer_tag() {
        let data = [0xA5, 0x03, 0x02, 0x01, 0x2A];
        let mut r = Reader::new(&data);
        let result = read_explicit(&mut r, Tag::context(6, true), |inner| {
            let tlv = inner.read_tlv()?;
            Ok(tlv.value[0] as i64)
        });
        assert!(result.is_err());
    }
}
