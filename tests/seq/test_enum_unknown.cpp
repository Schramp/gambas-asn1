// ENUMERATED items of a newer schema version (X.680 §52.1).
// Schema: tests/asn1/enum_unknown_test.asn1
//   ColorV1 ::= ENUMERATED { red, green, ..., cyan }
//   ColorV2 ::= ENUMERATED { red, green, ..., cyan, magenta(10), yellow }
// A version-2 value decoded with the version-1 type is kept as an unknown
// item, re-encodes unchanged in the codec it came from, and fails to encode
// in a codec that cannot represent it.
#include <cstdio>
#include <span>
#include <sstream>
#include <string>
#include <vector>
#include <asn1cpp/asn1cpp.hpp>
#include <asn1cpp/codec/PerCodec.hpp>
#include "ColorV1.hpp"
#include "ColorV2.hpp"
#include "FixedColor.hpp"
#include "PaletteV1.hpp"

using namespace asn1;
static int failures = 0;

static void check(const char* name, bool cond) {
    if (cond) printf("  \033[32mPASS\033[0m  %s\n", name);
    else     { printf("  \033[31mFAIL\033[0m  %s\n", name); ++failures; }
}

static std::vector<uint8_t> ber_enc(const TypeDescriptor& def, const Asn1Object* v, bool* failed = nullptr) {
    std::vector<uint8_t> buf; BerWriter w{buf}; BerEncodeStream s{w};
    BerCodec::instance().encode(s, def, v);
    if (failed) *failed = s.encode_failed();
    return buf;
}
static bool ber_dec(const std::vector<uint8_t>& b, const TypeDescriptor& def, Asn1Object* out) {
    BerReader r{b}; BerDecodeStream s{r};
    return BerCodec::instance().decode(s, def, out).has_value();
}
static std::vector<uint8_t> per_enc(const TypeDescriptor& def, const Asn1Object* v, bool* failed = nullptr) {
    std::vector<uint8_t> buf; PerEncodeStream s{buf};
    PerCodec::instance().encode(s, def, v); s.flush();
    if (failed) *failed = s.encode_failed();
    return buf;
}
static bool per_dec(const std::vector<uint8_t>& b, const TypeDescriptor& def, Asn1Object* out) {
    PerDecodeStream s{std::span<const uint8_t>(b)};
    return PerCodec::instance().decode(s, def, out).has_value();
}
static std::string xer_enc(const TypeDescriptor& def, const Asn1Object* v, bool* failed) {
    std::ostringstream o; XerEncodeStream s{o};
    XerCodec::instance().encode(s, def, v);
    *failed = s.encode_failed();
    return o.str();
}
static bool xer_dec(const std::string& x, const TypeDescriptor& def, Asn1Object* out) {
    XerDecodeStream s{x};
    return XerCodec::instance().decode(s, def, out).has_value();
}
static std::string jer_enc(const TypeDescriptor& def, const Asn1Object* v, bool* failed) {
    std::ostringstream o; JerEncodeStream s{o};
    JerCodec::instance().encode(s, def, v);
    *failed = s.encode_failed();
    return o.str();
}
static bool jer_dec(const std::string& j, const TypeDescriptor& def, Asn1Object* out) {
    JerDecodeStream s{j};
    return JerCodec::instance().decode(s, def, out).has_value();
}

static void test_per() {
    printf("\n── PER: unknown extension ordinal ───────────────────────────────\n");
    ColorV2 v2{ColorV2::yellow};                       // extension ordinal 2
    auto wire = per_enc(ColorV2::asn_DEF, &v2);
    ColorV1 v1{};
    check("v1 decodes v2 yellow", per_dec(wire, ColorV1::asn_DEF, &v1));
    check("  ...as unknown ordinal 2", v1.unknown_kind() == EnumValue::Unknown::Ordinal && v1.value() == 2);
    check("  ...matches no item", !(v1 == ColorV1::red) && !(v1 == ColorV1::cyan));
    check("  ...re-encodes to the same bits", per_enc(ColorV1::asn_DEF, &v1) == wire);
    ColorV2 back{};
    check("  ...v2 reads yellow back", per_dec(per_enc(ColorV1::asn_DEF, &v1), ColorV2::asn_DEF, &back)
                                       && back == ColorV2::yellow);
    bool failed = false;
    ber_enc(ColorV1::asn_DEF, &v1, &failed);
    check("  ...BER encode fails", failed);
    xer_enc(ColorV1::asn_DEF, &v1, &failed);
    check("  ...XER encode fails", failed);
    jer_enc(ColorV1::asn_DEF, &v1, &failed);
    check("  ...JER encode fails", failed);
    v1 = ColorV1::green;
    check("assigning an item clears unknown", !v1.is_unknown() && v1 == ColorV1::green);
}

static void test_ber() {
    printf("\n── BER: unknown value ───────────────────────────────────────────\n");
    ColorV2 v2{ColorV2::magenta};                      // value 10
    auto wire = ber_enc(ColorV2::asn_DEF, &v2);
    ColorV1 v1{};
    check("v1 decodes v2 magenta", ber_dec(wire, ColorV1::asn_DEF, &v1));
    check("  ...as unknown value 10", v1.unknown_kind() == EnumValue::Unknown::Value && v1.value() == 10);
    check("  ...re-encodes to the same octets", ber_enc(ColorV1::asn_DEF, &v1) == wire);
    bool failed = false;
    per_enc(ColorV1::asn_DEF, &v1, &failed);
    check("  ...PER encode fails", failed);
    FixedColor f{};
    check("non-extensible keeps the number as today", ber_dec(wire, FixedColor::asn_DEF, &f) && !f.is_unknown());
}

static void test_text() {
    printf("\n── XER / JER: unknown identifier ────────────────────────────────\n");
    ColorV1 v1{};
    check("XER unknown identifier accepted", xer_dec("<ColorV1><yellow/></ColorV1>", ColorV1::asn_DEF, &v1)
                                             && v1.unknown_kind() == EnumValue::Unknown::Identifier);
    bool failed = false;
    xer_enc(ColorV1::asn_DEF, &v1, &failed);
    check("  ...XER re-encode fails (name not kept)", failed);
    ColorV1 j{};
    check("JER unknown identifier accepted", jer_dec("\"yellow\"", ColorV1::asn_DEF, &j)
                                             && j.unknown_kind() == EnumValue::Unknown::Identifier);
    FixedColor f{};
    check("non-extensible XER still rejects", !xer_dec("<FixedColor><yellow/></FixedColor>", FixedColor::asn_DEF, &f));
    check("non-extensible JER still rejects", !jer_dec("\"yellow\"", FixedColor::asn_DEF, &f));
    PaletteV1 p{};
    check("XER list with unknown item accepted",
          xer_dec("<PaletteV1><red/><yellow/></PaletteV1>", asn_DEF_PaletteV1, &p)
          && p.size() == 2 && p[1].is_unknown());
}

int main() {
    test_per();
    test_ber();
    test_text();
    printf("\n");
    if (failures) { printf("  %d test(s) FAILED\n", failures); return 1; }
    printf("  All tests passed.\n");
    return 0;
}
