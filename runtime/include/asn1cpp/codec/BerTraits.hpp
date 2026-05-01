#pragma once
#include "BerWriter.hpp"
#include "BerReader.hpp"
#include "../Error.hpp"
#include "../Expected.hpp"
#include <optional>
#include <vector>

namespace asn1 {

// Primary template — must be specialised for each encodable type.
// Specialisations are provided in the types/ headers and in compiler-generated .hpp files.
template<typename T>
struct BerTraits {
    // static Tag       tag();
    // static void      encode(BerWriter&, const T&);
    // static Expected<T, DecodeError> decode(BerReader&);
};

// Helper: encode a value with an explicit tag override (for IMPLICIT/EXPLICIT tagging).
// By default just delegates to BerTraits<T>::encode after substituting the tag.
template<typename T>
void ber_encode_with_tag(BerWriter& w, Tag override_tag, const T& v) {
    // Get the normal encoding into a temp buffer
    std::vector<uint8_t> tmp;
    BerWriter inner(tmp);
    BerTraits<T>::encode(inner, v);

    // tmp now holds tag+length+value for the natural tag.
    // We replace the tag bytes. For IMPLICIT we just swap the tag.
    // For EXPLICIT we wrap the whole encoded form.
    // This helper assumes IMPLICIT — the caller handles EXPLICIT by wrapping.
    if (tmp.empty()) {
        w.write_primitive(override_tag, {});
        return;
    }
    // Strip the original tag from tmp, preserving length+value
    BerReader strip(tmp);
    auto orig_tag = strip.read_tag(); (void)orig_tag;
    auto rest = strip.peek(strip.remaining());
    // Emit override tag + rest (length + value)
    w.write_tag(override_tag);
    w.append(rest);
}

// Generic BerTraits for std::optional<T> — transparent; presence handled by the caller.
template<typename T>
struct BerTraits<std::optional<T>> {
    static Tag tag() { return BerTraits<T>::tag(); }
    static void encode(BerWriter& w, const std::optional<T>& v) {
        if (v) BerTraits<T>::encode(w, *v);
    }
    static Expected<std::optional<T>, DecodeError> decode(BerReader& r) {
        auto val = BerTraits<T>::decode(r);
        if (!val) return make_unexpected<std::optional<T>, DecodeError>(val.error());
        return std::optional<T>{std::move(*val)};
    }
};

// Generic BerTraits for std::vector<T> — encodes as SEQUENCE OF (universal 16, constructed).
template<typename T>
struct BerTraits<std::vector<T>> {
    static Tag tag() { return Tag::universal(16, true); }
    static void encode(BerWriter& w, const std::vector<T>& v) {
        w.write_constructed(tag(), [&](BerWriter& inner) {
            for (const auto& elem : v)
                BerTraits<T>::encode(inner, elem);
        });
    }
    static Expected<std::vector<T>, DecodeError> decode(BerReader& r) {
        auto tlv = r.read_tlv();
        if (!tlv) return make_unexpected<std::vector<T>, DecodeError>(tlv.error());
        std::vector<T> result;
        BerReader inner = r.sub(tlv->value);
        while (!inner.at_end()) {
            auto val = BerTraits<T>::decode(inner);
            if (!val) return make_unexpected<std::vector<T>, DecodeError>(val.error());
            result.push_back(std::move(*val));
        }
        return result;
    }
};

} // namespace asn1
