// BER / XER / PER tests for SEQUENCE OF types.
// Schema: tests/asn1/seq_of_test.asn1
// ByteList = SEQUENCE OF MyByte,  StrList = SEQUENCE OF MyStr
#include <cstdio>
#include <vector>
#include <span>
#include <sstream>
#include <string>
#include <asn1cpp/asn1cpp.hpp>
#include <asn1cpp/codec/PerCodec.hpp>
#include "ByteList.hpp"
#include "StrList.hpp"

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
    printf("\n── ByteList BER round-trips ──────────────────────────────────────\n");
    {
        ByteList empty{};
        auto enc = ber_enc(empty, asn_DEF_ByteList); ByteList got{};
        check("empty ByteList BER", ber_dec(enc, got, asn_DEF_ByteList) && got.empty());
    }
    {
        ByteList v{1};
        auto enc = ber_enc(v, asn_DEF_ByteList); ByteList got{};
        check("ByteList{1} BER", ber_dec(enc, got, asn_DEF_ByteList) && got == v);
    }
    {
        ByteList v{0, 127, 255};
        auto enc = ber_enc(v, asn_DEF_ByteList); ByteList got{};
        check("ByteList{0,127,255} BER", ber_dec(enc, got, asn_DEF_ByteList) && got == v);
    }

    printf("\n── ByteList XER round-trips ──────────────────────────────────────\n");
    {
        ByteList v{10, 20};
        auto xml = xer_enc(v, asn_DEF_ByteList); ByteList got{};
        check("ByteList{10,20} XER", xer_dec(xml, got, asn_DEF_ByteList) && got == v);
        check("ByteList XER has <ByteList>", xml.find("<ByteList>") != std::string::npos);
    }

    printf("\n── StrList BER round-trips ───────────────────────────────────────\n");
    {
        StrList empty{};
        auto enc = ber_enc(empty, asn_DEF_StrList); StrList got{};
        check("empty StrList BER", ber_dec(enc, got, asn_DEF_StrList) && got.empty());
    }
    {
        StrList v{VisibleString{"ab"}, VisibleString{"cd"}};
        auto enc = ber_enc(v, asn_DEF_StrList); StrList got{};
        check("StrList{ab,cd} BER rt",
              ber_dec(enc, got, asn_DEF_StrList) && got.size() == 2
              && got[0].str() == "ab" && got[1].str() == "cd");
    }

    printf("\n── StrList XER round-trips ───────────────────────────────────────\n");
    {
        StrList v{VisibleString{"hi"}, VisibleString{"yo"}};
        auto xml = xer_enc(v, asn_DEF_StrList); StrList got{};
        check("StrList{hi,yo} XER rt",
              xer_dec(xml, got, asn_DEF_StrList) && got.size() == 2
              && got[0].str() == "hi" && got[1].str() == "yo");
    }

    printf("\n── ByteList PER round-trips ──────────────────────────────────────\n");
    {
        ByteList v{0, 128, 255};
        auto enc = per_enc(v, asn_DEF_ByteList); ByteList got{};
        check("ByteList{0,128,255} PER", per_dec(enc, got, asn_DEF_ByteList) && got == v);
    }

    printf("\n");
    if (failures) { printf("  %d test(s) FAILED\n", failures); return 1; }
    printf("  All tests passed.\n");
    return 0;
}
