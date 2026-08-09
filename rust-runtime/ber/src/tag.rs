//! BER identifier (tag) octets — X.690 §8.1.2.

/// Tag class (X.690 §8.1.2.2), encoded in the top two bits of the first identifier octet.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TagClass {
    Universal,
    Application,
    Context,
    Private,
}

impl TagClass {
    fn from_bits(bits: u8) -> TagClass {
        match bits & 0x03 {
            0 => TagClass::Universal,
            1 => TagClass::Application,
            2 => TagClass::Context,
            _ => TagClass::Private,
        }
    }

    fn to_bits(self) -> u8 {
        match self {
            TagClass::Universal => 0,
            TagClass::Application => 1,
            TagClass::Context => 2,
            TagClass::Private => 3,
        }
    }
}

/// A parsed/to-be-encoded BER tag: class, number, and constructed bit.
///
/// Mirrors `asn1::Tag` (`runtime/include/asn1cpp/Tag.hpp`) — same three
/// fields, same X.690 §8.1.2 semantics.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Tag {
    pub class: TagClass,
    pub number: u32,
    pub constructed: bool,
}

impl Tag {
    pub const fn universal(number: u32, constructed: bool) -> Tag {
        Tag { class: TagClass::Universal, number, constructed }
    }

    pub const fn context(number: u32, constructed: bool) -> Tag {
        Tag { class: TagClass::Context, number, constructed }
    }
}

/// Universal class tag numbers used by the constructs this crate implements
/// (X.680 §8, table 1).
pub mod universal {
    pub const BOOLEAN: u32 = 1;
    pub const INTEGER: u32 = 2;
    pub const BIT_STRING: u32 = 3;
    pub const OCTET_STRING: u32 = 4;
    pub const NULL: u32 = 5;
    pub const OBJECT_DESCRIPTOR: u32 = 7;
    pub const UTF8_STRING: u32 = 12;
    pub const SEQUENCE: u32 = 16;
    pub const SET: u32 = 17;
    pub const NUMERIC_STRING: u32 = 18;
    pub const PRINTABLE_STRING: u32 = 19;
    pub const T61_STRING: u32 = 20;
    pub const VIDEOTEX_STRING: u32 = 21;
    pub const IA5_STRING: u32 = 22;
    pub const GRAPHIC_STRING: u32 = 25;
    pub const VISIBLE_STRING: u32 = 26;
    pub const GENERAL_STRING: u32 = 27;
    pub const UNIVERSAL_STRING: u32 = 28;
    pub const BMP_STRING: u32 = 30;
}

/// Encode and append the identifier octets for `t` — short-form
/// (`t.number < 31`) or long-form (base-128, MSB-continuation).
/// Mirrors `BerWriter::write_tag` (`runtime/include/asn1cpp/codec/BerWriter.hpp`).
pub fn write_tag(out: &mut Vec<u8>, t: Tag) {
    let first = (t.class.to_bits() << 6) | if t.constructed { 0x20 } else { 0x00 };
    if t.number < 31 {
        out.push(first | (t.number as u8));
    } else {
        out.push(first | 0x1F);
        let mut tmp = [0u8; 5];
        let mut i = 0;
        let mut n = t.number;
        loop {
            tmp[i] = (n & 0x7F) as u8;
            i += 1;
            n >>= 7;
            if n == 0 {
                break;
            }
        }
        for j in (0..i).rev() {
            out.push(tmp[j] | if j != 0 { 0x80 } else { 0x00 });
        }
    }
}

/// Decode one tag starting at `data[*pos]`, advancing `*pos`.
/// Mirrors `BerReader::parse_tag_at`. Returns `None` on truncation or a
/// long-form tag number needing more than 5 continuation bytes (matches the
/// C++ reader's `~0u` sentinel behaviour, just as `Option` instead).
pub fn read_tag(data: &[u8], pos: &mut usize) -> Option<Tag> {
    let first = *data.get(*pos)?;
    *pos += 1;
    let class = TagClass::from_bits(first >> 6);
    let constructed = (first & 0x20) != 0;
    let mut number = (first & 0x1F) as u32;
    if number != 0x1F {
        return Some(Tag { class, number, constructed });
    }
    number = 0;
    for _ in 0..5 {
        let b = *data.get(*pos)?;
        *pos += 1;
        number = (number << 7) | (b & 0x7F) as u32;
        if b & 0x80 == 0 {
            return Some(Tag { class, number, constructed });
        }
    }
    None
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn short_form_tag_round_trips() {
        let t = Tag::universal(universal::INTEGER, false);
        let mut buf = Vec::new();
        write_tag(&mut buf, t);
        assert_eq!(buf, vec![0x02]);
        let mut pos = 0;
        assert_eq!(read_tag(&buf, &mut pos), Some(t));
        assert_eq!(pos, 1);
    }

    #[test]
    fn constructed_universal_sequence_tag() {
        let t = Tag::universal(universal::SEQUENCE, true);
        let mut buf = Vec::new();
        write_tag(&mut buf, t);
        assert_eq!(buf, vec![0x30]);
    }

    #[test]
    fn context_constructed_tag() {
        let t = Tag::context(0, true);
        let mut buf = Vec::new();
        write_tag(&mut buf, t);
        assert_eq!(buf, vec![0xA0]);
        let mut pos = 0;
        assert_eq!(read_tag(&buf, &mut pos), Some(t));
    }

    #[test]
    fn long_form_tag_round_trips() {
        // Tag number 300 (> 30, needs long form): 300 = 0b100_1011100
        // base-128: [0x02, 0x2C] with continuation bit on all but last.
        let t = Tag::context(300, false);
        let mut buf = Vec::new();
        write_tag(&mut buf, t);
        assert_eq!(buf, vec![0x9F, 0x82, 0x2C]);
        let mut pos = 0;
        assert_eq!(read_tag(&buf, &mut pos), Some(t));
        assert_eq!(pos, 3);
    }

    #[test]
    fn truncated_tag_is_none() {
        let mut pos = 0;
        assert_eq!(read_tag(&[], &mut pos), None);
        let mut pos = 0;
        assert_eq!(read_tag(&[0x9F], &mut pos), None); // long-form marker, no continuation byte
    }
}
