/// @file BerCorruptor.hpp
/// @brief Post-encode BER byte-level wire fuzzer.
///
/// Walks a well-formed BER buffer and occasionally mutates TLV header bytes to produce
/// malformed-but-plausible records.  Applied \b after normal encoding — orthogonal to
/// the schema-constraint fuzz path in \c RandomFiller (\c FillConfig::invalid_percent).
///
/// The header mutations are in-place: buffer size stays unchanged so sibling TLV offsets
/// remain valid for the recursive walker. \c CORRUPT_SEGMENT is the exception: it keeps
/// the value and rewrites strings into BER's constructed form, so the buffer grows.
///
/// Typical usage:
/// @code
/// std::vector<uint8_t> buf = encode(obj);
/// asn1::corrupt_ber(buf, 5.0, rng);            // 5 % corruption, all modes
/// asn1::corrupt_ber(buf, 2.0, rng, asn1::CORRUPT_LEN_INDEF); // one mode only
/// @endcode
///
/// @see RandomFiller — schema-level constraint fuzzing (value range, SIZE, alphabet).
#pragma once

#include <cctype>
#include <cstdint>
#include <cstdlib>
#include <random>
#include <span>
#include <string>
#include <string_view>
#include <vector>

namespace asn1 {

/// @brief Bitmask type for \c corrupt_ber mode selection.
/// Combine multiple \c CorruptModeBit values with bitwise OR.
using CorruptMask = uint32_t;

/// @brief Individual corruption mode bits for \c corrupt_ber.
///
/// Pass one or more OR'd bits as the \c mask argument to \c corrupt_ber.
/// On each TLV visit the corruptor picks one set bit uniformly at random.
///
/// @see X.690 §8.1.2 — identifier (tag) octets; §8.1.3 — length octets.
enum CorruptModeBit : CorruptMask {
    CORRUPT_FLIP_PC        = 1u << 0,  ///< XOR bit 6 of tag byte (primitive ↔ constructed). Violates X.690 §8.1.2.5.
    CORRUPT_ROTATE_CLASS   = 1u << 1,  ///< Rotate top 2 tag bits (Universal → Application → Context → Private → …).
    CORRUPT_TAG_BUMP       = 1u << 2,  ///< Tag number ±1 (small type drift).
    CORRUPT_TAG_JUMP       = 1u << 3,  ///< Tag number += 6 (larger drift; targets unregistered alternatives).
    CORRUPT_LEN_BIT_FLIP   = 1u << 4,  ///< XOR bit 0 of first length byte.
    CORRUPT_LEN_INDEF      = 1u << 5,  ///< Force first length byte = 0x80 (indefinite form — illegal on primitives per X.690 §8.1.3.2 a).
    CORRUPT_LEN_OVERSTATE  = 1u << 6,  ///< First length byte += 0x10 (claims more bytes than present).
    CORRUPT_LEN_UNDERSTATE = 1u << 7,  ///< First length byte -= small delta (clamped ≥ 1).

    CORRUPT_ALL = CORRUPT_FLIP_PC | CORRUPT_ROTATE_CLASS | CORRUPT_TAG_BUMP |
                  CORRUPT_TAG_JUMP | CORRUPT_LEN_BIT_FLIP | CORRUPT_LEN_INDEF |
                  CORRUPT_LEN_OVERSTATE | CORRUPT_LEN_UNDERSTATE, ///< All header mutations combined.

    /// Value-preserving: rewrite a universally tagged BIT STRING, OCTET STRING or
    /// character string into the constructed form (X.690 §8.6.4, §8.7.3, §8.23.3) —
    /// random segment sizes, definite or indefinite length, sometimes nested — and
    /// re-encode the enclosing lengths. A conforming decoder gives the same value,
    /// except inside an ANY or open type, whose octets a decoder keeps as they are.
    /// IMPLICIT-tagged strings are left alone: without the schema their type is unknown.
    /// Not part of \c CORRUPT_ALL, so header-mutation runs keep their seeds.
    CORRUPT_SEGMENT        = 1u << 8,
    /// \c CORRUPT_SEGMENT, and also every primitive TLV of application, context
    /// or private class, as OCTET STRING segments. An IMPLICIT-tagged string
    /// keeps its value; any other type gets a form X.690 forbids (a constructed
    /// INTEGER, X.690 §8.3.1), which a decoder must reject. Not value-preserving:
    /// it drives the decoders' IMPLICIT-tag segment paths for crash fuzzing.
    CORRUPT_SEGMENT_IMPLICIT = 1u << 9,
};

inline std::string_view corrupt_mode_name(CorruptModeBit m) {
    switch (m) {
    case CORRUPT_FLIP_PC:        return "flip-pc";
    case CORRUPT_ROTATE_CLASS:   return "rotate-class";
    case CORRUPT_TAG_BUMP:       return "tag-bump";
    case CORRUPT_TAG_JUMP:       return "tag-jump";
    case CORRUPT_LEN_BIT_FLIP:   return "len-bit-flip";
    case CORRUPT_LEN_INDEF:      return "len-indef";
    case CORRUPT_LEN_OVERSTATE:  return "len-overstate";
    case CORRUPT_LEN_UNDERSTATE: return "len-understate";
    case CORRUPT_ALL:            return "all";
    case CORRUPT_SEGMENT:        return "segment";
    case CORRUPT_SEGMENT_IMPLICIT: return "segment-implicit";
    }
    return "?";
}

inline bool parse_corrupt_mode_token(std::string_view name, CorruptMask& bit) {
    if (name == "all")             { bit = CORRUPT_ALL;             return true; }
    if (name == "flip-pc")         { bit = CORRUPT_FLIP_PC;         return true; }
    if (name == "rotate-class")    { bit = CORRUPT_ROTATE_CLASS;    return true; }
    if (name == "tag-bump")        { bit = CORRUPT_TAG_BUMP;        return true; }
    if (name == "tag-jump")        { bit = CORRUPT_TAG_JUMP;        return true; }
    if (name == "len-bit-flip")    { bit = CORRUPT_LEN_BIT_FLIP;    return true; }
    if (name == "len-indef")       { bit = CORRUPT_LEN_INDEF;       return true; }
    if (name == "len-overstate")   { bit = CORRUPT_LEN_OVERSTATE;   return true; }
    if (name == "len-understate")  { bit = CORRUPT_LEN_UNDERSTATE;  return true; }
    if (name == "segment")         { bit = CORRUPT_SEGMENT;         return true; }
    if (name == "segment-implicit") { bit = CORRUPT_SEGMENT_IMPLICIT; return true; }
    return false;
}

/// @brief Parse a CLI mask spec into a \c CorruptMask.
/// Accepts one or more mode names joined by \c '+' or \c ',' (e.g. \c "flip-pc+tag-jump"),
/// or a hex/decimal numeric mask (\c "0x21" / \c "33") of header modes: a
/// numeric mask is limited to \c CORRUPT_ALL's bits, so the segment modes,
/// which change the record's size, are only chosen by name.  Empty input → \c CORRUPT_ALL.
/// @param spec  Input string.
/// @param out   Receives the parsed mask on success.
/// @return True on success; false if any token is unknown or the result would be zero.
inline bool parse_corrupt_mask(std::string_view spec, CorruptMask& out) {
    if (spec.empty()) { out = CORRUPT_ALL; return true; }
    // Hex / decimal numeric mask
    if (spec.size() > 1 && (spec[0] == '0') &&
        (spec[1] == 'x' || spec[1] == 'X')) {
        char* end = nullptr;
        std::string s(spec);
        unsigned long v = std::strtoul(s.c_str(), &end, 16);
        if (end && *end == '\0') { out = static_cast<CorruptMask>(v) & CORRUPT_ALL; return out != 0; }
        return false;
    }
    if (!spec.empty() && std::isdigit(static_cast<unsigned char>(spec[0]))) {
        char* end = nullptr;
        std::string s(spec);
        unsigned long v = std::strtoul(s.c_str(), &end, 10);
        if (end && *end == '\0') { out = static_cast<CorruptMask>(v) & CORRUPT_ALL; return out != 0; }
        return false;
    }
    CorruptMask mask = 0;
    std::size_t i = 0;
    while (i < spec.size()) {
        std::size_t j = i;
        while (j < spec.size() && spec[j] != '+' && spec[j] != ',') ++j;
        CorruptMask bit = 0;
        if (!parse_corrupt_mode_token(spec.substr(i, j - i), bit)) return false;
        mask |= bit;
        i = (j < spec.size()) ? j + 1 : j;
    }
    if (mask == 0) return false;
    out = mask;
    return true;
}

namespace detail {

inline int64_t corrupt_read_length(const std::vector<uint8_t>& buf, std::size_t off,
                                   int& len_bytes) {
    if (off >= buf.size()) { len_bytes = 0; return -2; }
    uint8_t b0 = buf[off];
    if (b0 == 0x80) { len_bytes = 1; return -1; }
    if ((b0 & 0x80) == 0) { len_bytes = 1; return b0; }
    int n = b0 & 0x7f;
    if (n > 8 || off + 1 + n > buf.size()) { len_bytes = 0; return -2; }
    int64_t v = 0;
    for (int i = 0; i < n; ++i) v = (v << 8) | buf[off + 1 + i];
    len_bytes = 1 + n;
    return v;
}

inline bool corrupt_read_tag(const std::vector<uint8_t>& buf, std::size_t off,
                             int& tag_bytes) {
    if (off >= buf.size()) { tag_bytes = 0; return false; }
    uint8_t b0 = buf[off];
    bool constructed = (b0 & 0x20) != 0;
    if ((b0 & 0x1f) != 0x1f) { tag_bytes = 1; return constructed; }
    int n = 1;
    while (off + n < buf.size() && (buf[off + n] & 0x80)) ++n;
    if (off + n >= buf.size()) { tag_bytes = 0; return constructed; }
    tag_bytes = n + 1;
    return constructed;
}

// Pick one set bit from `mask` uniformly at random.
inline CorruptMask pick_one_bit(CorruptMask mask, std::mt19937& rng) {
    int n = 0;
    for (CorruptMask m = mask; m; m &= m - 1) ++n;
    if (n == 0) return 0;
    int idx = std::uniform_int_distribution<int>{0, n - 1}(rng);
    for (CorruptMask m = mask; m; m &= m - 1) {
        if (idx == 0) return m & static_cast<CorruptMask>(-static_cast<int32_t>(m));
        --idx;
    }
    return 0;
}

// Apply one mode bit to the TLV header at `off`. Mutations stay in-place
// (buffer size unchanged).
inline void apply_corrupt_bit(std::vector<uint8_t>& buf, std::size_t off,
                              CorruptMask bit, std::mt19937& /*rng*/) {
    int tag_bytes = 0;
    corrupt_read_tag(buf, off, tag_bytes);
    if (tag_bytes == 0) return;

    int len_bytes = 0;
    corrupt_read_length(buf, off + tag_bytes, len_bytes);
    if (len_bytes == 0) return;

    std::size_t len_off = off + tag_bytes;

    switch (bit) {
    case CORRUPT_FLIP_PC:
        buf[off] ^= 0x20;
        break;
    case CORRUPT_ROTATE_CLASS:
        buf[off] = static_cast<uint8_t>((buf[off] & 0x3f) |
                                        (((buf[off] >> 6) + 1) & 0x03) << 6);
        break;
    case CORRUPT_TAG_BUMP: {
        uint8_t low = buf[off] & 0x1f;
        if (low < 0x1e) buf[off] = static_cast<uint8_t>((buf[off] & 0xe0) | (low + 1));
        else if (low > 0) buf[off] = static_cast<uint8_t>((buf[off] & 0xe0) | (low - 1));
        break;
    }
    case CORRUPT_TAG_JUMP: {
        uint8_t low = buf[off] & 0x1f;
        if (low == 0x1f) break;
        uint8_t newlow = static_cast<uint8_t>((low + 6) & 0x1f);
        if (newlow == 0x1f) newlow = 0x1e;
        buf[off] = static_cast<uint8_t>((buf[off] & 0xe0) | newlow);
        break;
    }
    case CORRUPT_LEN_BIT_FLIP:
        buf[len_off] ^= 0x01;
        break;
    case CORRUPT_LEN_INDEF:
        buf[len_off] = 0x80;
        break;
    case CORRUPT_LEN_OVERSTATE: {
        uint8_t b = buf[len_off];
        if ((b & 0x80) == 0) {
            buf[len_off] = (b > 0x6f) ? 0x7f
                                       : static_cast<uint8_t>(b + 0x10);
        }
        break;
    }
    case CORRUPT_LEN_UNDERSTATE: {
        uint8_t b = buf[len_off];
        if ((b & 0x80) == 0 && b > 1) {
            uint8_t sub = static_cast<uint8_t>(std::min<int>(b - 1, 0x10));
            buf[len_off] = static_cast<uint8_t>(b - sub);
        }
        break;
    }
    default:
        break;
    }
}

inline void corrupt_ber_range(std::vector<uint8_t>& buf, std::size_t begin,
                              std::size_t end, double percent, CorruptMask mask,
                              std::mt19937& rng) {
    std::bernoulli_distribution roll(percent / 100.0);
    std::size_t off = begin;
    while (off < end) {
        std::size_t tlv_start = off;
        int tag_bytes = 0;
        bool constructed = corrupt_read_tag(buf, off, tag_bytes);
        if (tag_bytes == 0) return;

        int len_bytes = 0;
        int64_t L = corrupt_read_length(buf, off + tag_bytes, len_bytes);
        if (len_bytes == 0) return;

        std::size_t header_size = tag_bytes + len_bytes;
        std::size_t value_off = tlv_start + header_size;

        bool can_recurse = constructed && L >= 0 &&
                           value_off + L <= end;
        std::size_t child_begin = value_off;
        std::size_t child_end   = can_recurse ? value_off + L : value_off;
        std::size_t advance     = (L >= 0)
                                      ? header_size + static_cast<std::size_t>(L)
                                      : header_size;

        if (roll(rng)) {
            CorruptMask bit = pick_one_bit(mask, rng);
            if (bit) apply_corrupt_bit(buf, tlv_start, bit, rng);
        }

        if (can_recurse)
            corrupt_ber_range(buf, child_begin, child_end, percent, mask, rng);

        if (advance == 0 || tlv_start + advance > end) return;
        off = tlv_start + advance;
    }
}

/// @brief True for a universal tag number whose type BER may send in
///        constructed form: BIT STRING, OCTET STRING, ObjectDescriptor and
///        the character strings, UTCTime and GeneralizedTime included
///        (X.690 §8.6.4, §8.7.3, §8.23.3; X.680 Table 1). Part of
///        \c segment_range.
/// @param number  Universal tag number.
/// @return True for a string type.
inline bool segmentable_universal(uint32_t number) {
    switch (number) {
    case 3: case 4: case 7: case 12: case 18: case 19: case 20: case 21: case 22:
    case 23: case 24: case 25: case 26: case 27: case 28: case 30:
        return true;
    }
    return false;
}

/// @brief Append definite length octets for \p n, in the shortest form (X.690 §8.1.3.3).
/// @param out  Buffer to append to.
/// @param n    Contents length.
inline void segment_write_length(std::vector<uint8_t>& out, std::size_t n) {
    if (n < 0x80) { out.push_back(static_cast<uint8_t>(n)); return; }
    uint8_t tmp[8]; int k = 0;
    for (std::size_t v = n; v; v >>= 8) tmp[k++] = static_cast<uint8_t>(v);
    out.push_back(static_cast<uint8_t>(0x80 | k));
    while (k) out.push_back(tmp[--k]);
}

/// @brief Append a constructed TLV: identifier \p id (constructed bit set),
///        \p body as contents, definite or (when \p indefinite) closed by
///        end-of-contents octets (X.690 §8.1.3.6).
/// @param out         Buffer to append to.
/// @param id          Identifier octets; the constructed bit is set on the copy.
/// @param body        Contents octets.
/// @param indefinite  Indefinite length instead of definite.
inline void segment_write_constructed(std::vector<uint8_t>& out, std::span<const uint8_t> id,
                                      const std::vector<uint8_t>& body, bool indefinite) {
    out.insert(out.end(), id.begin(), id.end());
    out[out.size() - id.size()] |= 0x20;
    if (indefinite) out.push_back(0x80);
    else segment_write_length(out, body.size());
    out.insert(out.end(), body.begin(), body.end());
    if (indefinite) { out.push_back(0); out.push_back(0); }
}

/// @brief Append the segments of a string's contents \p v to \p out: OCTET
///        STRING segments (tag 4) for OCTET STRING and the character strings,
///        BIT STRING segments (tag 3) for BIT STRING, whose unused-bits count
///        goes in the last one. Now and then a run of segments is wrapped in
///        a nested constructed segment.
/// @param out    Buffer to append the segment TLVs to.
/// @param v      The string's contents; for BIT STRING with its unused-bits octet first.
/// @param bits   BIT STRING segments (tag 3) instead of OCTET STRING (tag 4).
/// @param rng    Picks segment sizes, nesting and length forms.
/// @param depth  Nesting level of this call; nesting stops at 3.
inline void segment_contents(std::vector<uint8_t>& out, std::span<const uint8_t> v, bool bits,
                             std::mt19937& rng, int depth) {
    uint8_t unused = 0;
    if (bits) { unused = v.empty() ? 0 : v[0]; v = v.empty() ? v : v.subspan(1); }
    const uint8_t seg_id = bits ? 0x03 : 0x04;
    std::size_t pos = 0;
    do {
        std::size_t left = v.size() - pos;
        std::size_t n = left == 0 ? 0 : std::uniform_int_distribution<std::size_t>{1, left}(rng);
        auto piece = v.subspan(pos, n);
        pos += n;
        const bool last = pos == v.size();
        if (depth < 3 && left > 1 && std::bernoulli_distribution{0.2}(rng)) {
            std::vector<uint8_t> inner;
            if (bits) {
                // A nested BIT STRING segment carries the unused bits only
                // when it ends the whole value.
                std::vector<uint8_t> sub(1, last ? unused : 0);
                sub.insert(sub.end(), piece.begin(), piece.end());
                segment_contents(inner, sub, true, rng, depth + 1);
            } else {
                segment_contents(inner, piece, false, rng, depth + 1);
            }
            segment_write_constructed(out, std::span<const uint8_t>(&seg_id, 1), inner,
                                      std::bernoulli_distribution{0.5}(rng));
            continue;
        }
        out.push_back(seg_id);
        segment_write_length(out, piece.size() + (bits ? 1 : 0));
        if (bits) out.push_back(last ? unused : 0);
        out.insert(out.end(), piece.begin(), piece.end());
    } while (pos < v.size());
}

/// @brief Copy the TLVs in \p in to \p out, rewriting each universally tagged
///        primitive string into constructed form with probability \p percent,
///        and re-encoding the length of every definite constructed TLV around
///        it. Input it cannot parse, or an indefinite length, is copied as is.
///        Part of \c corrupt_ber for \c CORRUPT_SEGMENT.
/// @param in       TLVs to copy.
/// @param out      Buffer to append the rewritten TLVs to.
/// @param percent  Chance, in percent, that a string is rewritten.
/// @param rng      Picks which strings and how.
/// @param tagged  \c CORRUPT_SEGMENT_IMPLICIT: rewrite primitive TLVs of
///                application, context and private class too, as OCTET
///                STRING segments.
inline void segment_range(std::span<const uint8_t> in, std::vector<uint8_t>& out,
                          double percent, std::mt19937& rng, bool tagged) {
    std::bernoulli_distribution roll(percent / 100.0);
    const std::vector<uint8_t> view(in.begin(), in.end());
    std::size_t off = 0;
    while (off < view.size()) {
        int tag_bytes = 0, len_bytes = 0;
        bool constructed = corrupt_read_tag(view, off, tag_bytes);
        int64_t L = tag_bytes ? corrupt_read_length(view, off + tag_bytes, len_bytes) : -2;
        std::size_t value_off = off + tag_bytes + len_bytes;
        if (tag_bytes == 0 || len_bytes == 0 || L < 0 ||
            value_off + static_cast<std::size_t>(L) > view.size()) {
            out.insert(out.end(), view.begin() + static_cast<std::ptrdiff_t>(off), view.end());
            return;
        }
        auto id = std::span<const uint8_t>(view.data() + off, static_cast<std::size_t>(tag_bytes));
        auto value = std::span<const uint8_t>(view.data() + value_off, static_cast<std::size_t>(L));
        const bool universal = (view[off] & 0xC0) == 0 && tag_bytes == 1;
        if (constructed) {
            std::vector<uint8_t> body;
            segment_range(value, body, percent, rng, tagged);
            out.insert(out.end(), id.begin(), id.end());
            segment_write_length(out, body.size());
            out.insert(out.end(), body.begin(), body.end());
        } else if (((universal && segmentable_universal(view[off] & 0x1F)) || (tagged && (view[off] & 0xC0) != 0))
                   && roll(rng)) {
            std::vector<uint8_t> body;
            segment_contents(body, value, universal && (view[off] & 0x1F) == 3, rng, 0);
            segment_write_constructed(out, id, body, std::bernoulli_distribution{0.5}(rng));
        } else {
            out.insert(out.end(), view.begin() + static_cast<std::ptrdiff_t>(off),
                       view.begin() + static_cast<std::ptrdiff_t>(value_off) + L);
        }
        off = value_off + static_cast<std::size_t>(L);
    }
}

} // namespace detail

/// @brief Mutate a BER buffer in-place, corrupting TLV headers with probability \p percent.
///
/// Walks the buffer recursively (recurses into constructed TLVs).  On each TLV visit
/// a Bernoulli trial with probability \c percent/100 decides whether to apply a mutation.
/// When triggered, one bit from \p mask is picked uniformly at random and applied.
///
/// The header mutations never change the buffer size. With \c CORRUPT_SEGMENT in
/// \p mask the strings are first rewritten into constructed form (the buffer
/// grows, the value stays), then the other modes in \p mask are applied.
///
/// @param buf      BER-encoded buffer to mutate.
/// @param percent  Corruption probability in percent (e.g. \c 5.0 = 5% per TLV).
/// @param rng      Random number generator.
/// @param mask     Which mutation modes to use (default: \c CORRUPT_ALL).
///
/// @see CorruptModeBit — individual mode descriptions and affected X.690 rules.
inline void corrupt_ber(std::vector<uint8_t>& buf, double percent,
                        std::mt19937& rng,
                        CorruptMask mask = CORRUPT_ALL) {
    if (percent <= 0.0 || buf.empty() || mask == 0) return;
    constexpr CorruptMask segment_modes = CORRUPT_SEGMENT | CORRUPT_SEGMENT_IMPLICIT;
    if (mask & segment_modes) {
        std::vector<uint8_t> out;
        out.reserve(buf.size() * 2);
        detail::segment_range(buf, out, percent, rng, (mask & CORRUPT_SEGMENT_IMPLICIT) != 0);
        buf = std::move(out);
        mask &= ~segment_modes;
        if (mask == 0) return;
    }
    detail::corrupt_ber_range(buf, 0, buf.size(), percent, mask, rng);
}

} // namespace asn1
