// BER / XER / PER tests for CHOICE types.
// Schema: tests/asn1/choice_test.asn1
// Alt2 ::= CHOICE { num MyByte, flag BOOLEAN }
// Alt4 ::= CHOICE { num MyByte, str MyStr, flag BOOLEAN, raw OCTET STRING }
#include <cstdio>
#include <vector>
#include <span>
#include <sstream>
#include <string>
#include <asn1cpp/asn1cpp.hpp>
#include <asn1cpp/codec/PerCodec.hpp>
#include "HasAlt2.hpp"
#include "HasAlt4.hpp"

using namespace asn1;
static int failures = 0;

static void check(const char* name, bool cond) {
    if (cond) printf("  \033[32mPASS\033[0m  %s\n", name);
    else     { printf("  \033[31mFAIL\033[0m  %s\n", name); ++failures; }
}

template<typename T>
static std::vector<uint8_t> ber_enc(const T& v, const TypeDescriptor& def) {
    std::vector<uint8_t> buf; BerWriter w{buf};
    BerEncodeStream s{w}; BerCodec::instance().encode(s, def, &v); return buf;
}
template<typename T>
static bool ber_dec(std::span<const uint8_t> b, T& out, const TypeDescriptor& def) {
    BerReader r{b}; BerDecodeStream s{r};
    return BerCodec::instance().decode(s, def, &out).has_value();
}
template<typename T>
static std::string xer_enc(const T& v, const TypeDescriptor& def) {
    std::ostringstream o; XerEncodeStream s{o};
    XerCodec::instance().encode(s, def, &v); return o.str();
}
template<typename T>
static bool xer_dec(const std::string& xml, T& out, const TypeDescriptor& def) {
    XerDecodeStream s{xml};
    return XerCodec::instance().decode(s, def, &out).has_value();
}
template<typename T>
static std::vector<uint8_t> per_enc(const T& v, const TypeDescriptor& def) {
    std::vector<uint8_t> buf; PerEncodeStream s{buf};
    PerCodec::instance().encode(s, def, &v); s.flush(); return buf;
}
template<typename T>
static bool per_dec(std::span<const uint8_t> b, T& out, const TypeDescriptor& def) {
    PerDecodeStream s{b};
    return PerCodec::instance().decode(s, def, &out).has_value();
}

int main() {
    printf("\n── Alt2 (2-alternative CHOICE) BER ──────────────────────────────\n");
    {
        HasAlt2 v; v.val.present = Alt2::PR::num; v.val.num = 42;
        auto enc = ber_enc(v, asn_DEF_HasAlt2); HasAlt2 got{};
        check("Alt2::num=42 BER rt",
              ber_dec(enc, got, asn_DEF_HasAlt2)
              && got.val.present == Alt2::PR::num && got.val.num == 42);
    }
    {
        HasAlt2 v; v.val.present = Alt2::PR::flag; v.val.flag = Boolean{true};
        auto enc = ber_enc(v, asn_DEF_HasAlt2); HasAlt2 got{};
        check("Alt2::flag=true BER rt",
              ber_dec(enc, got, asn_DEF_HasAlt2)
              && got.val.present == Alt2::PR::flag && got.val.flag.value() == true);
    }

    printf("\n── Alt2 XER ──────────────────────────────────────────────────────\n");
    {
        HasAlt2 v; v.val.present = Alt2::PR::num; v.val.num = 7;
        auto xml = xer_enc(v, asn_DEF_HasAlt2); HasAlt2 got{};
        check("Alt2::num=7 XER rt",
              xer_dec(xml, got, asn_DEF_HasAlt2)
              && got.val.present == Alt2::PR::num && got.val.num == 7);
        check("Alt2::num XER has <num>", xml.find("<num>") != std::string::npos);
    }
    {
        HasAlt2 v; v.val.present = Alt2::PR::flag; v.val.flag = Boolean{false};
        auto xml = xer_enc(v, asn_DEF_HasAlt2);
        check("Alt2::flag XER has <flag>", xml.find("<flag>") != std::string::npos);
    }

    printf("\n── Alt4 (4-alternative CHOICE) BER ──────────────────────────────\n");
    {
        HasAlt4 v; v.val.present = Alt4::PR::num; v.val.num = 100;
        auto enc = ber_enc(v, asn_DEF_HasAlt4); HasAlt4 got{};
        check("Alt4::num=100 BER rt",
              ber_dec(enc, got, asn_DEF_HasAlt4)
              && got.val.present == Alt4::PR::num && got.val.num == 100);
    }
    {
        HasAlt4 v; v.val.present = Alt4::PR::str; v.val.str = VisibleString{"hi"};
        auto enc = ber_enc(v, asn_DEF_HasAlt4); HasAlt4 got{};
        check("Alt4::str=\"hi\" BER rt",
              ber_dec(enc, got, asn_DEF_HasAlt4)
              && got.val.present == Alt4::PR::str && got.val.str.str() == "hi");
    }
    {
        HasAlt4 v; v.val.present = Alt4::PR::flag; v.val.flag = Boolean{true};
        auto enc = ber_enc(v, asn_DEF_HasAlt4); HasAlt4 got{};
        check("Alt4::flag=true BER rt",
              ber_dec(enc, got, asn_DEF_HasAlt4)
              && got.val.present == Alt4::PR::flag && got.val.flag.value() == true);
    }
    {
        HasAlt4 v; v.val.present = Alt4::PR::raw;
        static const uint8_t rb[] = {0xde, 0xad};
        v.val.raw = OctetString{std::span<const uint8_t>{rb, 2}};
        auto enc = ber_enc(v, asn_DEF_HasAlt4); HasAlt4 got{};
        bool raw_ok = ber_dec(enc, got, asn_DEF_HasAlt4)
                   && got.val.present == Alt4::PR::raw;
        if (raw_ok) {
            auto b = got.val.raw.bytes();
            raw_ok = std::vector<uint8_t>(b.begin(), b.end()) == std::vector<uint8_t>{0xde, 0xad};
        }
        check("Alt4::raw BER rt", raw_ok);
    }

    printf("\n── Alt4 XER ──────────────────────────────────────────────────────\n");
    {
        HasAlt4 v; v.val.present = Alt4::PR::str; v.val.str = VisibleString{"ok"};
        auto xml = xer_enc(v, asn_DEF_HasAlt4); HasAlt4 got{};
        check("Alt4::str XER rt",
              xer_dec(xml, got, asn_DEF_HasAlt4)
              && got.val.present == Alt4::PR::str && got.val.str.str() == "ok");
        check("Alt4::str XER has <str>", xml.find("<str>") != std::string::npos);
    }

    printf("\n── Alt2/Alt4 PER round-trips ─────────────────────────────────────\n");
    {
        HasAlt2 v; v.val.present = Alt2::PR::num; v.val.num = 200;
        auto enc = per_enc(v, asn_DEF_HasAlt2); HasAlt2 got{};
        check("Alt2::num=200 PER rt",
              per_dec(enc, got, asn_DEF_HasAlt2)
              && got.val.present == Alt2::PR::num && got.val.num == 200);
    }
    {
        HasAlt4 v; v.val.present = Alt4::PR::flag; v.val.flag = Boolean{false};
        auto enc = per_enc(v, asn_DEF_HasAlt4); HasAlt4 got{};
        check("Alt4::flag=false PER rt",
              per_dec(enc, got, asn_DEF_HasAlt4)
              && got.val.present == Alt4::PR::flag && got.val.flag.value() == false);
    }

    printf("\n");
    if (failures) { printf("  %d test(s) FAILED\n", failures); return 1; }
    printf("  All tests passed.\n");
    return 0;
}
