// BER round-trip tests for SEQUENCE containing OID and RELATIVE-OID members.
// Schema: tests/asn1/oid_test.asn1  —  generated HasOid.hpp/cpp, HasRelOid.hpp/cpp.
//
// OID {1,2,840}: first two arcs = 1*40+2 = 42 = 0x2A; arc 840 = 0x86 0x48
//   OID TLV:      06 03 2A 86 48
//   SEQUENCE:     30 05 06 03 2A 86 48
//
// RELATIVE-OID {1,2,3}: arcs encoded directly as 01 02 03
//   RELATIVE-OID TLV: 0D 03 01 02 03
//   SEQUENCE:         30 05 0D 03 01 02 03
#include <cstdio>
#include <vector>
#include <span>
#include <asn1cpp/asn1cpp.hpp>
#include "HasOid.hpp"
#include "HasRelOid.hpp"

using namespace asn1;

static int failures = 0;

static void check(const char* name, bool cond) {
    if (cond) printf("  \033[32mPASS\033[0m  %s\n", name);
    else { printf("  \033[31mFAIL\033[0m  %s\n", name); ++failures; }
}

// ---- OID helpers -----------------------------------------------------------

static std::vector<uint8_t> ber_encode_oid(const HasOid& v) {
    std::vector<uint8_t> buf;
    BerWriter w{buf};
    BerEncodeStream s{w};
    BerCodec::instance().encode(s, asn_DEF_HasOid, &v);
    return buf;
}

static bool ber_decode_oid(std::span<const uint8_t> bytes, HasOid& out) {
    BerReader r{bytes};
    BerDecodeStream s{r};
    return BerCodec::instance().decode(s, asn_DEF_HasOid, &out).has_value();
}

static bool roundtrip_oid(Oid oid) {
    HasOid v; v.id = oid;
    auto enc = ber_encode_oid(v);
    HasOid got{};
    if (!ber_decode_oid(enc, got)) return false;
    return got.id == oid;
}

// ---- RELATIVE-OID helpers --------------------------------------------------

static std::vector<uint8_t> ber_encode_reloid(const HasRelOid& v) {
    std::vector<uint8_t> buf;
    BerWriter w{buf};
    BerEncodeStream s{w};
    BerCodec::instance().encode(s, asn_DEF_HasRelOid, &v);
    return buf;
}

static bool ber_decode_reloid(std::span<const uint8_t> bytes, HasRelOid& out) {
    BerReader r{bytes};
    BerDecodeStream s{r};
    return BerCodec::instance().decode(s, asn_DEF_HasRelOid, &out).has_value();
}

static bool roundtrip_reloid(RelativeOid oid) {
    HasRelOid v; v.id = oid;
    auto enc = ber_encode_reloid(v);
    HasRelOid got{};
    if (!ber_decode_reloid(enc, got)) return false;
    return got.id == oid;
}

int main() {
    printf("\n── OBJECT IDENTIFIER — HasOid BER ───────────────────────────────\n");

    // {1,2,840}: 0x2A = 42, 840 = base128 0x86 0x48
    HasOid v_oid; v_oid.id = Oid{{1, 2, 840}};
    auto enc_oid = ber_encode_oid(v_oid);
    check("HasOid{1.2.840} BER encodes as 30 05 06 03 2A 86 48",
          enc_oid == std::vector<uint8_t>({0x30, 0x05, 0x06, 0x03, 0x2A, 0x86, 0x48}));

    check("OID {1,2,840} round-trip",         roundtrip_oid(Oid{{1, 2, 840}}));
    check("OID {1,2,3} round-trip",            roundtrip_oid(Oid{{1, 2, 3}}));
    check("OID {2,16,840,1,101} round-trip",   roundtrip_oid(Oid{{2, 16, 840, 1, 101}}));
    check("OID empty round-trip",              roundtrip_oid(Oid{}));

    printf("\n── RELATIVE-OID — HasRelOid BER ─────────────────────────────────\n");

    // {1,2,3}: arcs encoded directly as 01 02 03; tag 0x0D
    HasRelOid v_rel; v_rel.id = RelativeOid{{1, 2, 3}};
    auto enc_rel = ber_encode_reloid(v_rel);
    check("HasRelOid{1,2,3} BER encodes as 30 05 0D 03 01 02 03",
          enc_rel == std::vector<uint8_t>({0x30, 0x05, 0x0D, 0x03, 0x01, 0x02, 0x03}));

    check("RELATIVE-OID {1,2,3} round-trip",    roundtrip_reloid(RelativeOid{{1, 2, 3}}));
    check("RELATIVE-OID {128} round-trip",       roundtrip_reloid(RelativeOid{{128}}));
    check("RELATIVE-OID {1,2,840} round-trip",   roundtrip_reloid(RelativeOid{{1, 2, 840}}));

    printf("\n");
    if (failures) { printf("  %d test(s) FAILED\n", failures); return 1; }
    printf("  All tests passed.\n");
    return 0;
}
