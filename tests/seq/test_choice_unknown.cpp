// CHOICE alternatives of a newer schema version (X.680 §52.1).
// Schema: tests/asn1/choice_unknown_test.asn1
//   MsgV1 ::= CHOICE { a INTEGER, b BOOLEAN, ... }
//   MsgV2 ::= CHOICE { a INTEGER, b BOOLEAN, ..., c IA5String, d SEQUENCE {...} }
// A version-2 alternative decoded with the version-1 type is kept, written
// back unchanged in the codec it came from, and fails to encode elsewhere.
#include <cstdio>
#include <span>
#include <sstream>
#include <string>
#include <vector>
#include <asn1cpp/asn1cpp.hpp>
#include <asn1cpp/codec/PerCodec.hpp>
#include "MsgV1.hpp"
#include "MsgV2.hpp"

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
static bool xer_fails(const TypeDescriptor& def, const Asn1Object* v) {
    std::ostringstream o; XerEncodeStream s{o};
    XerCodec::instance().encode(s, def, v);
    return s.encode_failed();
}

static MsgV2 v2_d() {
    MsgV2 m;
    m.set_present(MsgV2::PR::d);
    m.d().x = Integer{300};
    m.d().y = Boolean{true};
    return m;
}

static void test_ber() {
    printf("\n── BER: unknown extension alternative ───────────────────────────\n");
    MsgV2 m2 = v2_d();
    auto wire = ber_enc(MsgV2::asn_DEF, &m2);
    MsgV1 m1;
    check("v1 decodes v2 alternative d", ber_dec(wire, MsgV1::asn_DEF, &m1));
    check("  ...nothing selected, extension kept",
          m1._present == 0 && m1.unknown_extension()
          && m1.unknown_extension()->origin == ChoiceUnknownExtension::Origin::Ber);
    check("  ...re-encodes to the same octets", ber_enc(MsgV1::asn_DEF, &m1) == wire);
    MsgV2 back;
    check("  ...v2 reads d back", ber_dec(ber_enc(MsgV1::asn_DEF, &m1), MsgV2::asn_DEF, &back)
                                  && back.present() == MsgV2::PR::d && back.d().x.value() == 300);
    bool failed = false;
    per_enc(MsgV1::asn_DEF, &m1, &failed);
    check("  ...PER encode fails", failed);
    check("  ...XER encode fails", xer_fails(MsgV1::asn_DEF, &m1));
    MsgV1 copy = m1;
    check("  ...copy keeps it", copy.unknown_extension() && ber_enc(MsgV1::asn_DEF, &copy) == wire);
    MsgV1 moved = std::move(copy);
    check("  ...move keeps it", moved.unknown_extension() && !copy.unknown_extension());
    m1.set_present(MsgV1::PR::a);
    check("selecting an alternative drops it", !m1.unknown_extension() && m1._present == 1);
}

static void test_per() {
    printf("\n── PER: unknown extension alternative ───────────────────────────\n");
    MsgV2 m2 = v2_d();
    auto wire = per_enc(MsgV2::asn_DEF, &m2);
    MsgV1 m1;
    check("v1 decodes v2 alternative d", per_dec(wire, MsgV1::asn_DEF, &m1));
    check("  ...kept as extension index 1",
          m1.unknown_extension() && m1.unknown_extension()->origin == ChoiceUnknownExtension::Origin::Per
          && m1.unknown_extension()->index == 1);
    check("  ...re-encodes to the same bits", per_enc(MsgV1::asn_DEF, &m1) == wire);
    bool failed = false;
    ber_enc(MsgV1::asn_DEF, &m1, &failed);
    check("  ...BER encode fails", failed);
    MsgV1 known;
    known.set_present(MsgV1::PR::b);
    known.b() = Boolean{true};
    auto kw = per_enc(MsgV1::asn_DEF, &known);
    check("known alternative after unknown decodes", per_dec(kw, MsgV1::asn_DEF, &m1)
                                                  && m1._present == 2 && !m1.unknown_extension());
}

int main() {
    test_ber();
    test_per();
    printf("\n");
    if (failures) { printf("  %d test(s) FAILED\n", failures); return 1; }
    printf("  All tests passed.\n");
    return 0;
}
