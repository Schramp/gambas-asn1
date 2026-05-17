// BER round-trip tests for SEQUENCE containing a BIT STRING member.
// Schema: tests/asn1/bitstring_test.asn1  —  generated HasBitString.hpp/cpp.
//
// BER wire format:
//   HasBitString{ flags=BitString({0xA0}, 3 unused) }
//   BIT STRING TLV: 03 02 03 A0  (tag=0x03, len=2, unused=3, payload=0xA0)
//   SEQUENCE:       30 04 03 02 03 A0
//
//   HasBitString{ flags=BitString({}, 0 unused) }  — empty bit string
//   BIT STRING TLV: 03 01 00  (tag=0x03, len=1, unused=0)
//   SEQUENCE:       30 03 03 01 00
#include <cstdio>
#include <vector>
#include <span>
#include <asn1cpp/asn1cpp.hpp>
#include "HasBitString.hpp"

using namespace asn1;

static int failures = 0;

static void check(const char* name, bool cond) {
    if (cond) printf("  \033[32mPASS\033[0m  %s\n", name);
    else { printf("  \033[31mFAIL\033[0m  %s\n", name); ++failures; }
}

static std::vector<uint8_t> ber_encode(const HasBitString& v) {
    std::vector<uint8_t> buf;
    BerWriter w{buf};
    BerEncodeStream s{w};
    BerCodec::instance().encode(s, asn_DEF_HasBitString, &v);
    return buf;
}

static bool ber_decode(std::span<const uint8_t> bytes, HasBitString& out) {
    BerReader r{bytes};
    BerDecodeStream s{r};
    return BerCodec::instance().decode(s, asn_DEF_HasBitString, &out).has_value();
}

static bool roundtrip(BitString bs) {
    HasBitString v; v.flags = bs;
    auto enc = ber_encode(v);
    HasBitString got{};
    if (!ber_decode(enc, got)) return false;
    return got.flags == bs;
}

int main() {
    printf("\n── BIT STRING member — HasBitString BER ─────────────────────────\n");

    // Empty bit string: SEQUENCE { BIT STRING{unused=0, no payload} }
    // = 30 03 03 01 00
    HasBitString empty; empty.flags = BitString{{}, 0};
    auto enc_empty = ber_encode(empty);
    check("HasBitString{empty} BER encodes as 30 03 03 01 00",
          enc_empty == std::vector<uint8_t>({0x30, 0x03, 0x03, 0x01, 0x00}));

    // {0xA0}, 3 unused bits: SEQUENCE { 03 02 03 A0 } = 30 04 03 02 03 A0
    HasBitString one_byte; one_byte.flags = BitString{{0xA0}, 3};
    auto enc_one = ber_encode(one_byte);
    check("HasBitString{0xA0,3unused} BER encodes as 30 04 03 02 03 A0",
          enc_one == std::vector<uint8_t>({0x30, 0x04, 0x03, 0x02, 0x03, 0xA0}));

    check("empty BitString round-trip",            roundtrip(BitString{{}, 0}));
    check("single byte, 0 unused round-trip",      roundtrip(BitString{{0xFF}, 0}));
    check("single byte, 3 unused round-trip",      roundtrip(BitString{{0xA0}, 3}));
    check("multi-byte, 0 unused round-trip",       roundtrip(BitString{{0xDE, 0xAD, 0xBE}, 0}));
    check("multi-byte, 5 unused round-trip",       roundtrip(BitString{{0xDE, 0xAD, 0x60}, 5}));

    printf("\n");
    if (failures) { printf("  %d test(s) FAILED\n", failures); return 1; }
    printf("  All tests passed.\n");
    return 0;
}
