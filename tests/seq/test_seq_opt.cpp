// BER / XER / PER tests for SEQUENCE with OPTIONAL members.
// Schema: tests/asn1/seq_opt_test.asn1
// Rec5 { id MyByte, note MyStr OPTIONAL, flag BOOLEAN, extra MyByte OPTIONAL }
#include <cstdio>
#include <vector>
#include <span>
#include <sstream>
#include <string>
#include <memory>
#include <asn1cpp/asn1cpp.hpp>
#include <asn1cpp/codec/PerCodec.hpp>
#include "Rec5.hpp"

using namespace asn1;
static int failures = 0;

static void check(const char* name, bool cond) {
    if (cond) printf("  \033[32mPASS\033[0m  %s\n", name);
    else     { printf("  \033[31mFAIL\033[0m  %s\n", name); ++failures; }
}

static std::vector<uint8_t> ber_enc(const Rec5& v) {
    std::vector<uint8_t> buf; BerWriter w{buf};
    BerEncodeStream s{w}; BerCodec::instance().encode(s, asn_DEF_Rec5, &v); return buf;
}
static bool ber_dec(std::span<const uint8_t> b, Rec5& out) {
    BerReader r{b}; BerDecodeStream s{r};
    return BerCodec::instance().decode(s, asn_DEF_Rec5, &out).has_value();
}
static std::string xer_enc(const Rec5& v) {
    std::ostringstream o; XerEncodeStream s{o};
    XerCodec::instance().encode(s, asn_DEF_Rec5, &v); return o.str();
}
static bool xer_dec(const std::string& xml, Rec5& out) {
    XerDecodeStream s{xml};
    return XerCodec::instance().decode(s, asn_DEF_Rec5, &out).has_value();
}
static std::vector<uint8_t> per_enc(const Rec5& v) {
    std::vector<uint8_t> buf; PerEncodeStream s{buf};
    PerCodec::instance().encode(s, asn_DEF_Rec5, &v); s.flush(); return buf;
}
static bool per_dec(std::span<const uint8_t> b, Rec5& out) {
    PerDecodeStream s{b};
    return PerCodec::instance().decode(s, asn_DEF_Rec5, &out).has_value();
}

static bool ber_rt(const Rec5& v, MyByte id, bool flag,
                   const char* note, MyByte extra, bool has_note, bool has_extra) {
    auto enc = ber_enc(v); Rec5 got{};
    if (!ber_dec(enc, got)) return false;
    if (got.id != id || got.flag.value() != flag) return false;
    if (has_note != (got.note != nullptr)) return false;
    if (has_extra != (got.extra != nullptr)) return false;
    if (has_note  && got.note->str() != std::string(note)) return false;
    if (has_extra && *got.extra != extra) return false;
    return true;
}
static bool xer_rt(const Rec5& v, MyByte id, bool flag,
                   const char* note, MyByte extra, bool has_note, bool has_extra) {
    auto xml = xer_enc(v); Rec5 got{};
    if (!xer_dec(xml, got)) return false;
    if (got.id != id || got.flag.value() != flag) return false;
    if (has_note != (got.note != nullptr)) return false;
    if (has_extra != (got.extra != nullptr)) return false;
    if (has_note  && got.note->str() != std::string(note)) return false;
    if (has_extra && *got.extra != extra) return false;
    return true;
}
static bool per_rt(const Rec5& v) {
    auto enc = per_enc(v); Rec5 got{};
    if (!per_dec(enc, got)) return false;
    if (got.id != v.id || got.flag.value() != v.flag.value()) return false;
    if ((got.note  != nullptr) != (v.note  != nullptr)) return false;
    if ((got.extra != nullptr) != (v.extra != nullptr)) return false;
    if (v.note  && got.note->str()  != v.note->str())  return false;
    if (v.extra && *got.extra       != *v.extra)       return false;
    return true;
}

int main() {
    // Build the 4 combinations
    Rec5 none_none, note_only, extra_only, both;
    none_none.id = 1; none_none.flag = Boolean{true};
    note_only.id = 2; note_only.flag = Boolean{false};
    note_only.note = std::make_unique<MyStr>("hello");
    extra_only.id = 3; extra_only.flag = Boolean{true};
    extra_only.extra = std::make_unique<MyByte>(42);
    both.id = 4; both.flag = Boolean{false};
    both.note = std::make_unique<MyStr>("hi");
    both.extra = std::make_unique<MyByte>(99);

    printf("\n── Rec5 BER: optional combinations ──────────────────────────────\n");
    check("none_none BER", ber_rt(none_none,  1, true,  "",      0,  false, false));
    check("note_only BER", ber_rt(note_only,  2, false, "hello", 0,  true,  false));
    check("extra_only BER",ber_rt(extra_only, 3, true,  "",      42, false, true));
    check("both BER",      ber_rt(both,       4, false, "hi",    99, true,  true));

    printf("\n── Rec5 XER: optional combinations ──────────────────────────────\n");
    check("none_none XER", xer_rt(none_none,  1, true,  "",      0,  false, false));
    check("note_only XER", xer_rt(note_only,  2, false, "hello", 0,  true,  false));
    check("extra_only XER",xer_rt(extra_only, 3, true,  "",      42, false, true));
    check("both XER",      xer_rt(both,       4, false, "hi",    99, true,  true));

    printf("\n── Rec5 PER: optional combinations ──────────────────────────────\n");
    check("none_none PER",  per_rt(none_none));
    check("note_only PER",  per_rt(note_only));
    check("extra_only PER", per_rt(extra_only));
    check("both PER",       per_rt(both));

    // XER absent-optional fields must not appear in output
    {
        auto xml = xer_enc(none_none);
        check("none_none XER: no <note>",  xml.find("<note>")  == std::string::npos);
        check("none_none XER: no <extra>", xml.find("<extra>") == std::string::npos);
    }
    {
        auto xml = xer_enc(both);
        check("both XER: has <note>",  xml.find("<note>")  != std::string::npos);
        check("both XER: has <extra>", xml.find("<extra>") != std::string::npos);
    }

    printf("\n");
    if (failures) { printf("  %d test(s) FAILED\n", failures); return 1; }
    printf("  All tests passed.\n");
    return 0;
}
