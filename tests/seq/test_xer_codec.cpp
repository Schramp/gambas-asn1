// XER codec coverage test.
// Schema: tests/asn1/xer_codec_test.asn1
//
// Exercises:
//   EnumeratedXerHandler::encode + ::decode  (was zero-coverage)
//   AnyBerHandler::encode + ::decode          (was zero-coverage)
//   AnyXerHandler::encode + ::decode          (was zero-coverage)
#include <cstdio>
#include <algorithm>
#include <sstream>
#include <string>
#include <vector>
#include <span>
#include <asn1cpp/asn1cpp.hpp>
#include "Direction.hpp"
#include "HasDirection.hpp"
#include "HasAny.hpp"

using namespace asn1;

static int failures = 0;

static void check(const char* name, bool cond) {
    if (cond) printf("  \033[32mPASS\033[0m  %s\n", name);
    else     { printf("  \033[31mFAIL\033[0m  %s\n", name); ++failures; }
}

// ---------------------------------------------------------------------------
// BER helpers

static std::vector<uint8_t> ber_enc_dir(const HasDirection& v) {
    std::vector<uint8_t> buf;
    BerWriter w{buf}; BerEncodeStream s{w};
    BerCodec::instance().encode(s, HasDirection::asn_DEF, &v);
    return buf;
}
static bool ber_dec_dir(std::span<const uint8_t> b, HasDirection& out) {
    BerReader r{b}; BerDecodeStream s{r};
    return BerCodec::instance().decode(s, HasDirection::asn_DEF, &out).has_value();
}

static std::vector<uint8_t> ber_enc_any(const HasAny& v) {
    std::vector<uint8_t> buf;
    BerWriter w{buf}; BerEncodeStream s{w};
    BerCodec::instance().encode(s, HasAny::asn_DEF, &v);
    return buf;
}
static bool ber_dec_any(std::span<const uint8_t> b, HasAny& out) {
    BerReader r{b}; BerDecodeStream s{r};
    return BerCodec::instance().decode(s, HasAny::asn_DEF, &out).has_value();
}

// ---------------------------------------------------------------------------
// XER helpers

static std::string xer_enc_dir(const HasDirection& v) {
    std::ostringstream oss;
    XerEncodeStream s{oss};
    XerCodec::instance().encode(s, HasDirection::asn_DEF, &v);
    return oss.str();
}
static bool xer_dec_dir(const std::string& xml, HasDirection& out) {
    XerDecodeStream s{xml};
    return XerCodec::instance().decode(s, HasDirection::asn_DEF, &out).has_value();
}

static std::string xer_enc_any(const HasAny& v) {
    std::ostringstream oss;
    XerEncodeStream s{oss};
    XerCodec::instance().encode(s, HasAny::asn_DEF, &v);
    return oss.str();
}
static bool xer_dec_any(const std::string& xml, HasAny& out) {
    XerDecodeStream s{xml};
    return XerCodec::instance().decode(s, HasAny::asn_DEF, &out).has_value();
}

int main() {

    // -------------------------------------------------------------------------
    printf("\n── Direction ENUMERATED BER ─────────────────────────────────────\n");
    {
        HasDirection v; v.dir = Direction::east;
        auto enc = ber_enc_dir(v);
        HasDirection got{};
        check("HasDirection{east} BER decode ok", ber_dec_dir(enc, got));
        check("HasDirection{east} BER round-trip value", got.dir == Direction::east);
    }
    {
        HasDirection v; v.dir = Direction::west;
        auto enc = ber_enc_dir(v);
        HasDirection got{};
        check("HasDirection{west} BER round-trip", ber_dec_dir(enc, got) && got.dir == Direction::west);
    }

    // -------------------------------------------------------------------------
    printf("\n── Direction ENUMERATED XER ─────────────────────────────────────\n");

    struct { Direction val; const char* name; } cases[] = {
        { Direction::north, "north" },
        { Direction::south, "south" },
        { Direction::east,  "east"  },
        { Direction::west,  "west"  },
    };

    for (auto& c : cases) {
        HasDirection v; v.dir = c.val;
        auto xml = xer_enc_dir(v);
        // XER output should contain <north/> / <south/> / etc.
        char tag[32];
        std::snprintf(tag, sizeof(tag), "<%s/>", c.name);
        char label[64];
        std::snprintf(label, sizeof(label), "Direction XER encode contains <%s/>", c.name);
        check(label, xml.find(tag) != std::string::npos);

        // XER decode round-trip
        HasDirection got{};
        std::snprintf(label, sizeof(label), "Direction XER decode %s", c.name);
        check(label, xer_dec_dir(xml, got) && got.dir == c.val);
    }

    // -------------------------------------------------------------------------
    printf("\n── HasAny BER (AnyBerHandler) ───────────────────────────────────\n");
    {
        // Put a BER-encoded INTEGER (value=66 = 0x42) into the ANY slot.
        // BER for INTEGER 66: 02 01 42
        std::vector<uint8_t> any_bytes = {0x02, 0x01, 0x42};
        HasAny orig;
        orig.id = Integer{7};
        orig.value = OctetString(any_bytes);

        auto enc = ber_enc_any(orig);
        HasAny got{};
        check("HasAny BER decode ok", ber_dec_any(enc, got));
        check("HasAny BER round-trip id",  got.id.value() == 7);
        check("HasAny BER round-trip ANY bytes",
              std::ranges::equal(got.value.bytes(), std::span<const uint8_t>(any_bytes)));
    }
    {
        // ANY holding NULL: 05 00
        std::vector<uint8_t> null_bytes = {0x05, 0x00};
        HasAny orig;
        orig.id = Integer{0};
        orig.value = OctetString(null_bytes);
        auto enc = ber_enc_any(orig);
        HasAny got{};
        check("HasAny BER round-trip NULL-valued ANY",
              ber_dec_any(enc, got) && std::ranges::equal(got.value.bytes(), std::span<const uint8_t>(null_bytes)));
    }

    // -------------------------------------------------------------------------
    printf("\n── HasAny XER (AnyXerHandler) ───────────────────────────────────\n");
    {
        // ANY content: INTEGER 42 = 02 01 2A
        std::vector<uint8_t> any_bytes = {0x02, 0x01, 0x2A};
        HasAny orig;
        orig.id = Integer{3};
        orig.value = OctetString(any_bytes);

        auto xml = xer_enc_any(orig);
        // XER output for ANY is hex: "02 01 2A"
        check("HasAny XER output contains hex for ANY",
              xml.find("02 01 2A") != std::string::npos);

        HasAny got{};
        check("HasAny XER decode ok", xer_dec_any(xml, got));
        check("HasAny XER round-trip id",  got.id.value() == 3);
        check("HasAny XER round-trip ANY bytes",
              std::ranges::equal(got.value.bytes(), std::span<const uint8_t>(any_bytes)));
    }
    {
        // ANY content: OCTET STRING (tag 04) containing "hi" = 04 02 68 69
        std::vector<uint8_t> any_bytes = {0x04, 0x02, 0x68, 0x69};
        HasAny orig;
        orig.id = Integer{1};
        orig.value = OctetString(any_bytes);
        auto xml = xer_enc_any(orig);
        HasAny got{};
        check("HasAny XER round-trip OCTET STRING-valued ANY",
              xer_dec_any(xml, got) && std::ranges::equal(got.value.bytes(), std::span<const uint8_t>(any_bytes)));
    }

    printf("\n");
    if (failures) { printf("  %d test(s) FAILED\n", failures); return 1; }
    printf("  All tests passed.\n");
    return 0;
}
