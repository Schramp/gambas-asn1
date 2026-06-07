// BER / XER / PER tests for constrained INTEGER types.
// Schema: tests/asn1/int_range_test.asn1
// MyBit1 (0..1), MyByte (0..255), MySigned (-128..127), MyNarrow (123456..123457), MyWord (0..65535)
#include <cstdio>
#include <vector>
#include <span>
#include <sstream>
#include <string>
#include <asn1cpp/asn1cpp.hpp>
#include <asn1cpp/codec/PerCodec.hpp>
#include "HasBit1.hpp"
#include "HasByte.hpp"
#include "HasSigned.hpp"
#include "HasNarrow.hpp"
#include "HasWord.hpp"

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
static std::vector<uint8_t> per_enc(const T& v, const TypeDescriptor& def) {
    std::vector<uint8_t> buf; PerEncodeStream s{buf};
    PerCodec::instance().encode(s, def, &v); s.flush(); return buf;
}
template<typename T>
static bool per_dec(std::span<const uint8_t> b, T& out, const TypeDescriptor& def) {
    PerDecodeStream s{b};
    return PerCodec::instance().decode(s, def, &out).has_value();
}

static bool ber_rt_byte(int64_t val) {
    HasByte v; v.value = val;
    auto enc = ber_enc(v, HasByte::asn_DEF); HasByte got{};
    return ber_dec(enc, got, HasByte::asn_DEF) && got.value == val;
}
static bool per_rt_byte(int64_t val) {
    HasByte v; v.value = val;
    auto enc = per_enc(v, HasByte::asn_DEF); HasByte got{};
    return per_dec(enc, got, HasByte::asn_DEF) && got.value == val;
}

int main() {
    printf("\n── HasBit1 (0..1) PER encoding ──────────────────────────────────\n");
    {
        HasBit1 v0; v0.value = 0;
        HasBit1 v1; v1.value = 1;
        // 1-bit encoding: 0→0x00, 1→0x80
        check("HasBit1{0} PER = 0x00", per_enc(v0, HasBit1::asn_DEF) == std::vector<uint8_t>{0x00});
        check("HasBit1{1} PER = 0x80", per_enc(v1, HasBit1::asn_DEF) == std::vector<uint8_t>{0x80});
        HasBit1 r{};
        check("HasBit1{0} PER rt", per_dec(per_enc(v0, HasBit1::asn_DEF), r, HasBit1::asn_DEF) && r.value == 0);
        check("HasBit1{1} PER rt", per_dec(per_enc(v1, HasBit1::asn_DEF), r, HasBit1::asn_DEF) && r.value == 1);
    }

    printf("\n── HasByte (0..255) BER + PER ───────────────────────────────────\n");
    check("HasByte{0} BER rt",   ber_rt_byte(0));
    check("HasByte{127} BER rt", ber_rt_byte(127));
    check("HasByte{255} BER rt", ber_rt_byte(255));
    {
        HasByte v; v.value = 42;
        // 8-bit encoding: 42 = 0x2a
        check("HasByte{42} PER = 0x2a", per_enc(v, HasByte::asn_DEF) == std::vector<uint8_t>{0x2a});
    }
    check("HasByte{0} PER rt",   per_rt_byte(0));
    check("HasByte{255} PER rt", per_rt_byte(255));

    printf("\n── HasSigned (-128..127) PER ────────────────────────────────────\n");
    {
        HasSigned v; v.value = -128;
        check("HasSigned{-128} PER = 0x00", per_enc(v, HasSigned::asn_DEF) == std::vector<uint8_t>{0x00});
        HasSigned r{};
        check("HasSigned{-128} PER rt", per_dec(per_enc(v, HasSigned::asn_DEF), r, HasSigned::asn_DEF) && r.value == -128);
    }
    {
        HasSigned v; v.value = 0;
        check("HasSigned{0} PER = 0x80", per_enc(v, HasSigned::asn_DEF) == std::vector<uint8_t>{0x80});
    }
    {
        HasSigned v; v.value = 127;
        check("HasSigned{127} PER = 0xff", per_enc(v, HasSigned::asn_DEF) == std::vector<uint8_t>{0xff});
    }

    printf("\n── HasNarrow (123456..123457) PER ───────────────────────────────\n");
    {
        HasNarrow v0; v0.value = 123456;
        HasNarrow v1; v1.value = 123457;
        check("HasNarrow{123456} PER = 0x00", per_enc(v0, HasNarrow::asn_DEF) == std::vector<uint8_t>{0x00});
        check("HasNarrow{123457} PER = 0x80", per_enc(v1, HasNarrow::asn_DEF) == std::vector<uint8_t>{0x80});
        HasNarrow r{};
        check("HasNarrow{123457} PER rt", per_dec(per_enc(v1, HasNarrow::asn_DEF), r, HasNarrow::asn_DEF) && r.value == 123457);
    }

    printf("\n── HasWord (0..65535) PER ───────────────────────────────────────\n");
    {
        HasWord v; v.value = 0x1234;
        check("HasWord{0x1234} PER = {0x12,0x34}", per_enc(v, HasWord::asn_DEF) == std::vector<uint8_t>{0x12, 0x34});
        HasWord r{};
        check("HasWord{0x1234} PER rt", per_dec(per_enc(v, HasWord::asn_DEF), r, HasWord::asn_DEF) && r.value == 0x1234);
    }

    printf("\n── BER round-trips ──────────────────────────────────────────────\n");
    {
        HasSigned vs; vs.value = -50;
        auto enc = ber_enc(vs, HasSigned::asn_DEF); HasSigned r{};
        check("HasSigned{-50} BER rt", ber_dec(enc, r, HasSigned::asn_DEF) && r.value == -50);
    }
    {
        HasNarrow vn; vn.value = 123456;
        auto enc = ber_enc(vn, HasNarrow::asn_DEF); HasNarrow r{};
        check("HasNarrow{123456} BER rt", ber_dec(enc, r, HasNarrow::asn_DEF) && r.value == 123456);
    }
    {
        HasWord vw; vw.value = 65535;
        auto enc = ber_enc(vw, HasWord::asn_DEF); HasWord r{};
        check("HasWord{65535} BER rt", ber_dec(enc, r, HasWord::asn_DEF) && r.value == 65535);
    }

    printf("\n");
    if (failures) { printf("  %d test(s) FAILED\n", failures); return 1; }
    printf("  All tests passed.\n");
    return 0;
}
