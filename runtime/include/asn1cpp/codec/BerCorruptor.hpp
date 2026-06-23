/// @file BerCorruptor.hpp
/// @brief Post-encode BER byte-level wire fuzzer.
///
/// Walks a well-formed BER buffer and occasionally mutates TLV header bytes to produce
/// malformed-but-plausible records.  Applied \b after normal encoding — orthogonal to
/// the schema-constraint fuzz path in \c RandomFiller (\c FillConfig::invalid_percent).
///
/// All mutations are in-place: buffer size stays unchanged so sibling TLV offsets remain
/// valid for the recursive walker.
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
                  CORRUPT_LEN_OVERSTATE | CORRUPT_LEN_UNDERSTATE, ///< All modes combined.
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
    return false;
}

/// @brief Parse a CLI mask spec into a \c CorruptMask.
/// Accepts one or more mode names joined by \c '+' or \c ',' (e.g. \c "flip-pc+tag-jump"),
/// or a hex/decimal numeric mask (\c "0x21" / \c "33").  Empty input → \c CORRUPT_ALL.
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
        if (end && *end == '\0') { out = static_cast<CorruptMask>(v); return v != 0; }
        return false;
    }
    if (!spec.empty() && std::isdigit(static_cast<unsigned char>(spec[0]))) {
        char* end = nullptr;
        std::string s(spec);
        unsigned long v = std::strtoul(s.c_str(), &end, 10);
        if (end && *end == '\0') { out = static_cast<CorruptMask>(v); return v != 0; }
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

} // namespace detail

/// @brief Mutate a BER buffer in-place, corrupting TLV headers with probability \p percent.
///
/// Walks the buffer recursively (recurses into constructed TLVs).  On each TLV visit
/// a Bernoulli trial with probability \c percent/100 decides whether to apply a mutation.
/// When triggered, one bit from \p mask is picked uniformly at random and applied.
///
/// Buffer size is never changed — mutations only alter existing header bytes.
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
    detail::corrupt_ber_range(buf, 0, buf.size(), percent, mask, rng);
}

} // namespace asn1
