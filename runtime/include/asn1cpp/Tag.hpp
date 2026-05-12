#pragma once
#include <cstdint>

namespace asn1 {

enum class TagClass : uint8_t {
    Universal   = 0,
    Application = 1,
    Context     = 2,
    Private     = 3,
};

// Universal tag numbers (X.680 §8.4 table)
namespace UniversalTag {
    inline constexpr uint32_t EndOfContents    =  0;  // EOC / reserved
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
    inline constexpr uint32_t LongForm         = 31;  // long-form tag number escape (not a type)
}

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

    // Type predicates — true when this tag identifies the named universal type.
    constexpr bool is_boolean()         const { return cls == TagClass::Universal && number == UniversalTag::Boolean; }
    constexpr bool is_integer()         const { return cls == TagClass::Universal && number == UniversalTag::Integer; }
    constexpr bool is_null()            const { return cls == TagClass::Universal && number == UniversalTag::Null; }
    constexpr bool is_real()            const { return cls == TagClass::Universal && number == UniversalTag::Real; }
    constexpr bool is_bitstring()       const { return cls == TagClass::Universal && number == UniversalTag::BitString; }
    constexpr bool is_oid()             const { return cls == TagClass::Universal && number == UniversalTag::Oid; }
    constexpr bool is_relative_oid()    const { return cls == TagClass::Universal && number == UniversalTag::RelativeOid; }
    constexpr bool is_utctime()         const { return cls == TagClass::Universal && number == UniversalTag::UtcTime; }
    constexpr bool is_generalizedtime() const { return cls == TagClass::Universal && number == UniversalTag::GeneralizedTime; }
    constexpr bool is_octetstring()     const { return cls == TagClass::Universal && number == UniversalTag::OctetString; }
    constexpr bool is_bmp_string()      const { return cls == TagClass::Universal && number == UniversalTag::BmpString; }
    constexpr bool is_universal_string() const { return cls == TagClass::Universal && number == UniversalTag::UniversalString; }
    constexpr bool is_hex_string() const {
        if (cls != TagClass::Universal) return false;
        switch (number) {
        case UniversalTag::T61String: case UniversalTag::VideotexString:
        case UniversalTag::GraphicString: case UniversalTag::GeneralString:
            return true;
        default: return false;
        }
    }
    // X.691 §23: character string types (includes UtcTime/GeneralizedTime, used by PER).
    constexpr bool is_character_string() const {
        if (cls != TagClass::Universal) return false;
        switch (number) {
        case UniversalTag::ObjectDescriptor:
        case UniversalTag::NumericString:
        case UniversalTag::PrintableString:
        case UniversalTag::T61String:
        case UniversalTag::VideotexString:
        case UniversalTag::UtcTime:
        case UniversalTag::GeneralizedTime:
        case UniversalTag::GraphicString:
        case UniversalTag::VisibleString:
        case UniversalTag::GeneralString:
        case UniversalTag::UniversalString:
        case UniversalTag::BmpString:
            return true;
        default: return false;
        }
    }
    constexpr bool is_primitive_string() const {
        if (cls != TagClass::Universal) return false;
        switch (number) {
        case UniversalTag::ObjectDescriptor:
        case UniversalTag::Utf8String:
        case UniversalTag::NumericString:
        case UniversalTag::PrintableString:
        case UniversalTag::T61String:
        case UniversalTag::VideotexString:
        case UniversalTag::Ia5String:
        case UniversalTag::GraphicString:
        case UniversalTag::VisibleString:
        case UniversalTag::GeneralString:
        case UniversalTag::UniversalString:
        case UniversalTag::BmpString:
            return true;
        default: return false;
        }
    }
};

} // namespace asn1
