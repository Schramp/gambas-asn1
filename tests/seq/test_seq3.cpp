// BER / XER / PER round-trip tests for a plain 3-field SEQUENCE.
// Schema: tests/asn1/seq3_test.asn1  —  Rec3 { id MyByte, flag BOOLEAN, label MyStr }
#include <cstdio>
#include <vector>
#include <span>
#include <sstream>
#include <string>
#include <asn1cpp/asn1cpp.hpp>
#include <asn1cpp/codec/PerCodec.hpp>
#include "Rec3.hpp"

using namespace asn1;
static int failures = 0;

static void check(const char* name, bool cond) {
    if (cond) printf("  \033[32mPASS\033[0m  %s\n", name);
    else     { printf("  \033[31mFAIL\033[0m  %s\n", name); ++failures; }
}

static std::vector<uint8_t> ber_enc(const Rec3& v) {
    std::vector<uint8_t> buf; BerWriter w{buf};
    BerEncodeStream s{w}; BerCodec::instance().encode(s, asn_DEF_Rec3, &v); return buf;
}
static bool ber_dec(std::span<const uint8_t> b, Rec3& out) {
    BerReader r{b}; BerDecodeStream s{r};
    return BerCodec::instance().decode(s, asn_DEF_Rec3, &out).has_value();
}
static std::string xer_enc(const Rec3& v) {
    std::ostringstream o; XerEncodeStream s{o};
    XerCodec::instance().encode(s, asn_DEF_Rec3, &v); return o.str();
}
static bool xer_dec(const std::string& xml, Rec3& out) {
    XerDecodeStream s{xml};
    return XerCodec::instance().decode(s, asn_DEF_Rec3, &out).has_value();
}
static std::vector<uint8_t> per_enc(const Rec3& v) {
    std::vector<uint8_t> buf; PerEncodeStream s{buf};
    PerCodec::instance().encode(s, asn_DEF_Rec3, &v); s.flush(); return buf;
}
static bool per_dec(std::span<const uint8_t> b, Rec3& out) {
    PerDecodeStream s{b};
    return PerCodec::instance().decode(s, asn_DEF_Rec3, &out).has_value();
}

static bool ber_rt(MyByte id, bool flag, const char* label) {
    Rec3 v; v.id = id; v.flag = Boolean{flag}; v.label = VisibleString{label};
    auto enc = ber_enc(v); Rec3 got{};
    if (!ber_dec(enc, got)) return false;
    return got.id == id && got.flag.value() == flag
        && got.label.str() == std::string(label);
}
static bool xer_rt(MyByte id, bool flag, const char* label) {
    Rec3 v; v.id = id; v.flag = Boolean{flag}; v.label = VisibleString{label};
    auto xml = xer_enc(v); Rec3 got{};
    if (!xer_dec(xml, got)) return false;
    return got.id == id && got.flag.value() == flag
        && got.label.str() == std::string(label);
}
static bool per_rt(MyByte id, bool flag, const char* label) {
    Rec3 v; v.id = id; v.flag = Boolean{flag}; v.label = VisibleString{label};
    auto enc = per_enc(v); Rec3 got{};
    if (!per_dec(enc, got)) return false;
    return got.id == id && got.flag.value() == flag
        && got.label.str() == std::string(label);
}

int main() {
    printf("\n── Rec3 BER round-trip ───────────────────────────────────────────\n");
    check("Rec3{1, true, \"hi\"} BER",    ber_rt(1,  true,  "hi"));
    check("Rec3{0, false, \"ab\"} BER",   ber_rt(0,  false, "ab"));
    check("Rec3{255, true, \"ABCDEFGH\"} BER", ber_rt(255, true, "ABCDEFGH"));

    printf("\n── Rec3 XER round-trip ───────────────────────────────────────────\n");
    check("Rec3{42, false, \"test\"} XER", xer_rt(42, false, "test"));
    check("Rec3{7, true, \"ok\"} XER",     xer_rt(7,  true,  "ok"));
    {
        Rec3 v; v.id = 5; v.flag = Boolean{true}; v.label = VisibleString{"hi"};
        auto xml = xer_enc(v);
        check("XER has <Rec3>",  xml.find("<Rec3>")  != std::string::npos);
        check("XER has <id>",    xml.find("<id>")    != std::string::npos);
        check("XER has <flag>",  xml.find("<flag>")  != std::string::npos);
        check("XER has <label>", xml.find("<label>") != std::string::npos);
    }

    printf("\n── Rec3 PER round-trip ───────────────────────────────────────────\n");
    check("Rec3{1, true, \"hi\"} PER",    per_rt(1,  true,  "hi"));
    check("Rec3{0, false, \"ab\"} PER",   per_rt(0,  false, "ab"));
    check("Rec3{255, true, \"test\"} PER", per_rt(255, true, "test"));

    printf("\n");
    if (failures) { printf("  %d test(s) FAILED\n", failures); return 1; }
    printf("  All tests passed.\n");
    return 0;
}
