#pragma once
#include <vector>
#include <span>
#include "BerWriter.hpp"
#include "BerReader.hpp"
#include "BerTraits.hpp"
#include "../Error.hpp"
#include "../Expected.hpp"

namespace asn1 {

// Encoding tags
struct BER {};
struct DER {};  // DER is canonical BER: definite-length, minimal, unique values

// ---- Encode ----------------------------------------------------------------

template<typename Enc, typename T>
    requires std::same_as<Enc, BER> || std::same_as<Enc, DER>
std::vector<uint8_t> encode(const T& value) {
    std::vector<uint8_t> buf;
    BerWriter w(buf);
    BerTraits<T>::encode(w, value);
    return buf;
}

// ---- Decode ----------------------------------------------------------------

template<typename Enc, typename T>
    requires std::same_as<Enc, BER> || std::same_as<Enc, DER>
Expected<T, DecodeError> decode(std::span<const uint8_t> data) {
    BerReader r(data);
    return BerTraits<T>::decode(r);
}

// Convenience overload for vector
template<typename Enc, typename T>
    requires std::same_as<Enc, BER> || std::same_as<Enc, DER>
Expected<T, DecodeError> decode(const std::vector<uint8_t>& data) {
    return decode<Enc, T>(std::span<const uint8_t>(data));
}

// ---- SEQUENCE OF helpers ---------------------------------------------------

// Encode a sequence of elements with a wrapping SEQUENCE tag.
template<typename Enc, typename T>
    requires std::same_as<Enc, BER> || std::same_as<Enc, DER>
std::vector<uint8_t> encode_sequence_of(const std::vector<T>& items) {
    std::vector<uint8_t> buf;
    BerWriter w(buf);
    w.write_constructed(Tag::universal(UniversalTag::Sequence, true), [&](BerWriter& inner) {
        for (const auto& item : items)
            BerTraits<T>::encode(inner, item);
    });
    return buf;
}

template<typename Enc, typename T>
    requires std::same_as<Enc, BER> || std::same_as<Enc, DER>
Expected<std::vector<T>, DecodeError> decode_sequence_of(std::span<const uint8_t> data) {
    BerReader r(data);
    auto tlv = r.read_tlv();
    if (!tlv) return make_unexpected<std::vector<T>, DecodeError>(tlv.error());

    std::vector<T> result;
    BerReader inner = r.sub(tlv->value);
    while (!inner.at_end()) {
        auto item = BerTraits<T>::decode(inner);
        if (!item) return make_unexpected<std::vector<T>, DecodeError>(item.error());
        result.push_back(std::move(*item));
    }
    return result;
}

} // namespace asn1
