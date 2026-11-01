// SIZE on non-known-multiplier strings in PER (per_nkm_size_test.asn1),
// built once per --per-nkm-size mode. NKM_MODE selects the expected bytes:
//   strict  — X.691 §10.3.18, §30.6: no PER-visible SIZE on UTF8String /
//             GeneralString. Expected bytes are Erlang/OTP asn1 UPER output
//             (asn1c has no strict mode; asn1c on the schema with those SIZE
//             constraints removed gives the same bytes).
//   visible — SIZE encoded as if PER-visible. Expected bytes are asn1c's.
//   mixed   — strict default with sidecar overrides (type Name, member
//             Rec.g visible). Expected bytes are asn1c's for the schema with
//             the SIZE of the strict members removed.
// The IA5String member is a known-multiplier control: its SIZE is
// PER-visible in every mode.
#include <cstdio>
#include <cstdint>
#include <span>
#include <string>
#include <vector>
#include <asn1cpp/asn1cpp.hpp>
#include <asn1cpp/codec/PerCodec.hpp>
#include "Rec.hpp"

using namespace asn1;

#if !defined(NKM_MODE_STRICT) && !defined(NKM_MODE_VISIBLE) && !defined(NKM_MODE_MIXED)
#error "define one of NKM_MODE_STRICT, NKM_MODE_VISIBLE, NKM_MODE_MIXED"
#endif

static int failures = 0;

static void check(const std::string& label, bool cond) {
    if (cond) printf("  \033[32mPASS\033[0m  %s\n", label.c_str());
    else      { printf("  \033[31mFAIL\033[0m  %s\n", label.c_str()); ++failures; }
}

static std::string hex(const std::vector<uint8_t>& b) {
    std::string s;
    char buf[3];
    for (auto c : b) { snprintf(buf, sizeof buf, "%02x", c); s += buf; }
    return s;
}

static bool per_enc(const Rec& v, std::vector<uint8_t>& buf) {
    PerEncodeStream s{buf};
    IEncodeStream& es = s;
    PerCodec::instance().encode(es, Rec::asn_DEF, &v);
    s.flush();
    return !s.encode_failed();
}

static Rec value() {
    Rec r{};
    r.s = Utf8String{"ab"};
    r.ext = Utf8String{"abc"};
    r.named = Utf8String{"xyz"};
    r.g = GeneralString{"AB"};
    r.ia5 = Ia5String{"hi"};
    return r;
}

int main() {
#if defined(NKM_MODE_STRICT)
    const char* mode = "strict";
    const std::string expected = "026162036162630378797a0241420b4690";
#elif defined(NKM_MODE_VISIBLE)
    const char* mode = "visible";
    const std::string expected = "09858804c2c4c60278797a505082d1a4";
#else
    const char* mode = "mixed";
    const std::string expected = "02616203616263013c3cbd28284168d2";
#endif
    printf("=== PER SIZE on non-known-multiplier strings: %s ===\n", mode);
    std::vector<uint8_t> buf;
    check("encodes", per_enc(value(), buf));
    check(std::string("bytes ") + hex(buf) + " == " + expected, hex(buf) == expected);

    Rec back{};
    PerDecodeStream ds{std::span<const uint8_t>(buf)};
    IDecodeStream& is = ds;
    auto r = PerCodec::instance().decode(is, Rec::asn_DEF, &back);
    check("decodes", r.has_value());
    check("round-trips", back.s.str() == "ab" && back.ext.str() == "abc"
          && back.named.str() == "xyz" && back.g.str() == "AB" && back.ia5.str() == "hi");

    // 40 characters exceed SIZE(0..32). With no PER-visible SIZE the length
    // is unconstrained, so PER itself can carry the value; with a visible,
    // non-extensible SIZE it cannot.
    Rec big = value();
    big.s = Utf8String{std::string(40, 'x')};
    std::vector<uint8_t> bbuf;
    bool big_ok = per_enc(big, bbuf);
#if defined(NKM_MODE_VISIBLE)
    check("40-char s rejected by the visible SIZE(0..32)", !big_ok);
#else
    check("40-char s carried with an unconstrained length", big_ok && bbuf.size() > 40 && bbuf[0] == 40);
#endif
    const Constraints& sc = Rec::asn_DEF.sequence_spec->members[0].type_descriptor->constraints;
    check("validate() still applies SIZE(0..32)", big.s.validate(sc) != 0 && value().s.validate(sc) == 0);

    printf("%s\n", failures ? "FAILED" : "all passed");
    return failures ? 1 : 0;
}
