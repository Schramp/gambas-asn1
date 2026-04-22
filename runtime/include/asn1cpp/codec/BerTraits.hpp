#pragma once
#include "BerWriter.hpp"
#include "BerReader.hpp"
#include "../Error.hpp"
#include "../Expected.hpp"

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

} // namespace asn1
