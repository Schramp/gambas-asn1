#pragma once
#include <cstdint>

namespace asn1 {

enum class TagClass : uint8_t {
    Universal   = 0,
    Application = 1,
    Context     = 2,
    Private     = 3,
};

struct Tag {
    TagClass  cls;
    uint32_t  number;
    bool      constructed;

    static constexpr Tag universal(uint32_t n, bool c = false) {
        return {TagClass::Universal, n, c};
    }
    static constexpr Tag context(uint32_t n, bool c = false) {
        return {TagClass::Context, n, c};
    }
    static constexpr Tag application(uint32_t n, bool c = false) {
        return {TagClass::Application, n, c};
    }
    static constexpr Tag priv(uint32_t n, bool c = false) {
        return {TagClass::Private, n, c};
    }

    bool operator==(const Tag&) const = default;
};

// Universal tag numbers (X.680 §8.4 table)
namespace UniversalTag {
    inline constexpr uint32_t Boolean          =  1;
    inline constexpr uint32_t Integer          =  2;
    inline constexpr uint32_t BitString        =  3;
    inline constexpr uint32_t OctetString      =  4;
    inline constexpr uint32_t Null             =  5;
    inline constexpr uint32_t Oid              =  6;
    inline constexpr uint32_t ObjectDescriptor =  7;
    inline constexpr uint32_t External         =  8;
    inline constexpr uint32_t Real             =  9;
    inline constexpr uint32_t Enumerated       = 10;
    inline constexpr uint32_t EmbeddedPdv      = 11;
    inline constexpr uint32_t Utf8String       = 12;
    inline constexpr uint32_t RelativeOid      = 13;
    inline constexpr uint32_t Sequence         = 16;
    inline constexpr uint32_t Set              = 17;
    inline constexpr uint32_t NumericString    = 18;
    inline constexpr uint32_t PrintableString  = 19;
    inline constexpr uint32_t T61String        = 20;
    inline constexpr uint32_t VideotexString   = 21;
    inline constexpr uint32_t Ia5String        = 22;
    inline constexpr uint32_t UtcTime          = 23;
    inline constexpr uint32_t GeneralizedTime  = 24;
    inline constexpr uint32_t GraphicString    = 25;
    inline constexpr uint32_t VisibleString    = 26;
    inline constexpr uint32_t GeneralString    = 27;
    inline constexpr uint32_t UniversalString  = 28;
    inline constexpr uint32_t CharacterString  = 29;
    inline constexpr uint32_t BmpString        = 30;
}

} // namespace asn1
