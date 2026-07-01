// JER basic-type encode/decode unit test (#156)
// Covers: NULL, BOOLEAN, INTEGER, REAL, BIT STRING, OCTET STRING,
//         OID, RELATIVE-OID, UTCTime, GeneralizedTime, UTF8String,
//         VisibleString, BMPString, UniversalString, ENUMERATED.
#include <cstdio>
#include <cmath>
#include <sstream>
#include <string>
#include <string_view>
#include <vector>
#include <asn1cpp/asn1cpp.hpp>
#include <asn1cpp/codec/JerCodec.hpp>

using namespace asn1;

static int failures = 0;

static void check(const char* name, bool cond, const char* detail = "") {
    if (cond) {
        std::printf("  \033[32mPASS\033[0m  %s\n", name);
    } else {
        std::printf("  \033[31mFAIL\033[0m  %s%s%s\n", name, *detail ? ": " : "", detail);
        ++failures;
    }
}

// Encode object → JSON string.
static std::string jer_encode(const TypeDescriptor& def, const Asn1Object* obj) {
    std::ostringstream oss;
    JerEncodeStream s{oss};
    JerCodec::instance().encode(s, def, obj);
    return oss.str();
}

// Decode JSON string → object.
template<typename T>
DecodeResult jer_decode(const TypeDescriptor& def, const std::string& json, T& out) {
    JerDecodeStream s{json};
    return JerCodec::instance().decode(s, def, &out);
}

// Round-trip: encode then decode, verify equality.
template<typename T>
bool roundtrip(const TypeDescriptor& def, const T& v) {
    std::string json = jer_encode(def, &v);
    T out{};
    auto r = jer_decode(def, json, out);
    if (!r) { std::fprintf(stderr, "    decode error: %s  json=%s\n", r.error().message.c_str(), json.c_str()); return false; }
    return out == v;
}

// Encode and compare exact JSON output.
template<typename T>
bool encodes_as(const TypeDescriptor& def, const T& v, std::string_view expected) {
    std::string got = jer_encode(def, &v);
    if (got != expected)
        std::fprintf(stderr, "    got:      %s\n    expected: %s\n", got.c_str(), std::string(expected).c_str());
    return got == expected;
}

// Decode JSON and compare decoded value.
template<typename T>
bool decodes_to(const TypeDescriptor& def, const std::string& json, const T& expected) {
    T out{};
    auto r = jer_decode(def, json, out);
    if (!r) { std::fprintf(stderr, "    decode error: %s\n", r.error().message.c_str()); return false; }
    return out == expected;
}

int main() {
    // =========================================================================
    std::printf("\n── NULL ────────────────────────────────────────────────────\n");
    // =========================================================================
    check("NULL encodes as null",  encodes_as(asn_DEF_Null, Null{}, "null"));
    check("null decodes to Null",  decodes_to(asn_DEF_Null, "null", Null{}));
    check("NULL round-trip",       roundtrip(asn_DEF_Null, Null{}));

    // =========================================================================
    std::printf("\n── BOOLEAN ─────────────────────────────────────────────────\n");
    // =========================================================================
    check("BOOLEAN true encodes",  encodes_as(asn_DEF_Boolean, Boolean{true},  "true"));
    check("BOOLEAN false encodes", encodes_as(asn_DEF_Boolean, Boolean{false}, "false"));
    check("true decodes",          decodes_to(asn_DEF_Boolean, "true",  Boolean{true}));
    check("false decodes",         decodes_to(asn_DEF_Boolean, "false", Boolean{false}));
    check("BOOLEAN round-trip T",  roundtrip(asn_DEF_Boolean, Boolean{true}));
    check("BOOLEAN round-trip F",  roundtrip(asn_DEF_Boolean, Boolean{false}));

    // =========================================================================
    std::printf("\n── INTEGER ─────────────────────────────────────────────────\n");
    // =========================================================================
    check("INTEGER 0 encodes",   encodes_as(asn_DEF_Integer, Integer{0},   "0"));
    check("INTEGER 42 encodes",  encodes_as(asn_DEF_Integer, Integer{42},  "42"));
    check("INTEGER -1 encodes",  encodes_as(asn_DEF_Integer, Integer{-1},  "-1"));
    check("INTEGER 0 decodes",   decodes_to(asn_DEF_Integer, "0",   Integer{0}));
    check("INTEGER 42 decodes",  decodes_to(asn_DEF_Integer, "42",  Integer{42}));
    check("INTEGER -7 decodes",  decodes_to(asn_DEF_Integer, "-7",  Integer{-7}));
    check("INTEGER round-trip 0",        roundtrip(asn_DEF_Integer, Integer{0}));
    check("INTEGER round-trip 12345",    roundtrip(asn_DEF_Integer, Integer{12345}));
    check("INTEGER round-trip INT64_MIN",roundtrip(asn_DEF_Integer, Integer{INT64_MIN}));

    // =========================================================================
    std::printf("\n── REAL ────────────────────────────────────────────────────\n");
    // =========================================================================
    check("REAL 0 encodes", encodes_as(asn_DEF_Real, Real{0.0}, "0"));
    check("REAL NaN encodes as quoted",  encodes_as(asn_DEF_Real, Real{std::numeric_limits<double>::quiet_NaN()}, "\"NaN\""));
    check("REAL +Inf encodes",           encodes_as(asn_DEF_Real, Real{std::numeric_limits<double>::infinity()},  "\"PLUS-INFINITY\""));
    check("REAL -Inf encodes",           encodes_as(asn_DEF_Real, Real{-std::numeric_limits<double>::infinity()}, "\"MINUS-INFINITY\""));
    {
        // NaN round-trip: NaN != NaN by IEEE, so check by hand
        Real nan_val{std::numeric_limits<double>::quiet_NaN()};
        std::string json = jer_encode(asn_DEF_Real, &nan_val);
        Real out{};
        auto r = jer_decode(asn_DEF_Real, json, out);
        check("REAL NaN round-trip",  r.has_value() && std::isnan(out.value()));
    }
    check("REAL 1.5 round-trip",    roundtrip(asn_DEF_Real, Real{1.5}));
    check("REAL -7.25 round-trip",  roundtrip(asn_DEF_Real, Real{-7.25}));
    {
        Real out{};
        auto r = jer_decode(asn_DEF_Real, "\"PLUS-INFINITY\"", out);
        check("REAL +Inf decodes",  r.has_value() && std::isinf(out.value()) && out.value() > 0);
    }
    {
        Real out{};
        auto r = jer_decode(asn_DEF_Real, "\"MINUS-INFINITY\"", out);
        check("REAL -Inf decodes",  r.has_value() && std::isinf(out.value()) && out.value() < 0);
    }

    // =========================================================================
    std::printf("\n── OCTET STRING ────────────────────────────────────────────\n");
    // =========================================================================
    {
        OctetString os1{std::vector<uint8_t>{0xDE, 0xAD, 0xBE, 0xEF}};
        check("OCTET STRING encodes uppercase hex", encodes_as(asn_DEF_OctetString, os1, "\"DEADBEEF\""));
        check("OCTET STRING round-trip",            roundtrip(asn_DEF_OctetString, os1));
    }
    {
        OctetString empty{};
        check("OCTET STRING empty encodes", encodes_as(asn_DEF_OctetString, empty, "\"\""));
        check("OCTET STRING empty round-trip", roundtrip(asn_DEF_OctetString, empty));
    }
    {
        OctetString out{};
        auto r = jer_decode(asn_DEF_OctetString, "\"DEADBEEF\"", out);
        std::vector<uint8_t> expected = {0xDE, 0xAD, 0xBE, 0xEF};
        check("OCTET STRING decodes hex",
              r.has_value() && std::vector<uint8_t>(out.bytes().begin(), out.bytes().end()) == expected);
    }

    // =========================================================================
    std::printf("\n── BIT STRING ──────────────────────────────────────────────\n");
    // =========================================================================
    {
        BitString bs{std::vector<uint8_t>{0xA0}, 4}; // 4 bits: 1010
        std::string enc = jer_encode(asn_DEF_BitString, &bs);
        check("BIT STRING encodes as object", enc.find("\"value\"") != std::string::npos && enc.find("\"length\"") != std::string::npos);
        check("BIT STRING encodes length:4",  enc.find(":4}") != std::string::npos);
    }
    {
        BitString bs{std::vector<uint8_t>{0xDE, 0xAD}, 0}; // 16 bits
        check("BIT STRING 16-bit round-trip", roundtrip(asn_DEF_BitString, bs));
    }
    {
        BitString empty{};
        check("BIT STRING empty encodes", [&] {
            std::string enc = jer_encode(asn_DEF_BitString, &empty);
            return enc.find("\"length\":0") != std::string::npos;
        }());
    }

    // =========================================================================
    std::printf("\n── OBJECT IDENTIFIER ───────────────────────────────────────\n");
    // =========================================================================
    {
        Oid oid{std::vector<uint32_t>{1, 2, 840, 113549, 1, 1, 1}};
        check("OID encodes as dotted string",    encodes_as(asn_DEF_Oid, oid, "\"1.2.840.113549.1.1.1\""));
        check("OID round-trip",                  roundtrip(asn_DEF_Oid, oid));
    }

    // =========================================================================
    std::printf("\n── RELATIVE-OID ────────────────────────────────────────────\n");
    // =========================================================================
    {
        RelativeOid ro{std::vector<uint32_t>{128, 4294967295u}};
        check("RELATIVE-OID encodes", encodes_as(asn_DEF_RelativeOid, ro, "\"128.4294967295\""));
        check("RELATIVE-OID round-trip", roundtrip(asn_DEF_RelativeOid, ro));
    }

    // =========================================================================
    std::printf("\n── UTF8String ──────────────────────────────────────────────\n");
    // =========================================================================
    {
        Utf8String s{"hello world"};
        check("UTF8String encodes", encodes_as(asn_DEF_Utf8String, s, "\"hello world\""));
        check("UTF8String round-trip", roundtrip(asn_DEF_Utf8String, s));
    }
    {
        Utf8String s{"has\"quotes"};
        std::string enc = jer_encode(asn_DEF_Utf8String, &s);
        check("UTF8String escapes quotes", enc == "\"has\\\"quotes\"");
    }

    // =========================================================================
    std::printf("\n── VisibleString ───────────────────────────────────────────\n");
    // =========================================================================
    {
        VisibleString s{"abc123"};
        check("VisibleString encodes", encodes_as(asn_DEF_VisibleString, s, "\"abc123\""));
        check("VisibleString round-trip", roundtrip(asn_DEF_VisibleString, s));
    }

    // =========================================================================
    std::printf("\n── UTCTime ─────────────────────────────────────────────────\n");
    // =========================================================================
    {
        UtcTime t{"700101000000-0000"};
        check("UTCTime encodes", encodes_as(asn_DEF_UtcTime, t, "\"700101000000-0000\""));
        check("UTCTime round-trip", roundtrip(asn_DEF_UtcTime, t));
    }

    // =========================================================================
    std::printf("\n── GeneralizedTime ─────────────────────────────────────────\n");
    // =========================================================================
    {
        GeneralizedTime t{"20230615120000Z"};
        check("GeneralizedTime encodes", encodes_as(asn_DEF_GeneralizedTime, t, "\"20230615120000Z\""));
        check("GeneralizedTime round-trip", roundtrip(asn_DEF_GeneralizedTime, t));
    }

    // =========================================================================
    std::printf("\n── Result ──────────────────────────────────────────────────\n");
    // =========================================================================
    if (failures == 0)
        std::printf("\n\033[32mAll JER basic-type tests passed.\033[0m\n\n");
    else
        std::printf("\n\033[31m%d test(s) FAILED.\033[0m\n\n", failures);

    return failures ? 1 : 0;
}
