//! XER encode-side primitives — escape, indentation, element-tag writing.
//!
//! Ports `xer_detail::xer_escape` (`runtime/include/asn1cpp/codec/XerCodec.hpp`)
//! — only `<`/`>`/`&` on encode (X.693 §8.2); decode accepts a wider set
//! of entities (`crate::xer::reader::unescape`).

/// Append `s` to `out` with XER's three encode-time escapes (X.693 §8.2).
/// Mirrors `xer_detail::xer_escape`.
pub fn escape(s: &str, out: &mut String) {
    for c in s.chars() {
        match c {
            '<' => out.push_str("&lt;"),
            '>' => out.push_str("&gt;"),
            '&' => out.push_str("&amp;"),
            _ => out.push(c),
        }
    }
}

/// `depth * 4` spaces — the C++ runtime's own indent unit
/// (`XerEncodeStream::indent`, `runtime/include/asn1cpp/codec/XerCodec.hpp`:
/// `4 * (depth_ + offset)`). `depth` means "the level this value's own
/// wrapper tag sits at" throughout the XER encode call graph (`Asn1Value::
/// xer_encode`'s own `depth` parameter, `sequence::encode_sequence_xer_content`,
/// `choice::encode_choice_xer_into`, `seq_of::encode_seq_of_xer_named`) — a
/// composite's content is always written one level deeper than its own
/// `depth`, recursively, matching the C++ runtime's `s.depth() + 1`
/// convention exactly (`XerCodec.cpp`'s `SequenceXerHandler`/
/// `ChoiceXerHandler`/`SeqOfXerHandler`, all three).
pub fn indent(depth: usize) -> String {
    " ".repeat(4 * depth)
}

/// Append `<name>` to `out`. Field-name-derived — callers (the
/// table-driven walker, `sequence::encode_sequence_xer` etc.) supply
/// `name` from `MemberDescriptor::name`, not from the value's own type.
pub fn write_open_tag(out: &mut String, name: &str) {
    out.push('<');
    out.push_str(name);
    out.push('>');
}

/// Append `</name>` to `out`.
pub fn write_close_tag(out: &mut String, name: &str) {
    out.push_str("</");
    out.push_str(name);
    out.push('>');
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn escape_covers_lt_gt_amp_only() {
        let mut out = String::new();
        escape("a<b>c&d\"e'f", &mut out);
        assert_eq!(out, "a&lt;b&gt;c&amp;d\"e'f");
    }
}
