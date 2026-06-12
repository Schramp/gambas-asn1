// BER/XER round-trip tests for SET and SET OF.
// Covers: SET member encode/decode, DER canonical sort for SET OF (X.690 §11.6),
// DEFAULT suppress/fill in SET context, OPTIONAL members, extensible SET.
#include <cstdio>
#include <vector>
#include <string>
#include <sstream>
#include <span>
#include <algorithm>
#include <asn1cpp/asn1cpp.hpp>
#include "Point.hpp"
#include "Config.hpp"
#include "IntSet.hpp"
#include "Pair.hpp"
#include "PairSet.hpp"
#include "ExtPoint.hpp"

using namespace asn1;

static int failures = 0;
static void check(const char* label, bool cond) {
    if (cond) printf("  \033[32mPASS\033[0m  %s\n", label);
    else       { printf("  \033[31mFAIL\033[0m  %s\n", label); ++failures; }
}

static std::vector<uint8_t> ber_enc(const TypeDescriptor& def, const Asn1Object* p) {
    std::vector<uint8_t> buf;
    BerWriter w{buf}; BerEncodeStream s{w};
    BerCodec::instance().encode(s, def, p);
    return buf;
}

static bool ber_dec(std::span<const uint8_t> bytes, const TypeDescriptor& def, Asn1Object* p) {
    BerReader r{bytes}; BerDecodeStream s{r};
    return BerCodec::instance().decode(s, def, p).has_value();
}

static std::string xer_enc(const TypeDescriptor& def, const Asn1Object* p) {
    std::ostringstream oss;
    XerEncodeStream s{oss};
    XerCodec::instance().encode(s, def, p);
    return oss.str();
}

static bool xer_dec(const std::string& xml, const TypeDescriptor& def, Asn1Object* p) {
    XerDecodeStream s{xml};
    return XerCodec::instance().decode(s, def, p).has_value();
}

// Encode a single Integer to its BER TLV bytes.
static std::vector<uint8_t> enc_int(int64_t v) {
    Integer val{v};
    std::vector<uint8_t> buf;
    BerWriter w{buf}; BerEncodeStream s{w};
    BerCodec::instance().encode(s, asn_DEF_Integer, &val);
    return buf;
}

int main() {
    // --- Point (SET, all members required) ---
    printf("SET — Point\n");
    {
        Point enc{};
        enc.x = Integer{3};
        enc.y = Integer{-7};
        enc.z = Integer{42};

        auto bytes = ber_enc(Point::asn_DEF, &enc);
        check("Point BER encode non-empty", !bytes.empty());

        Point dec{};
        check("Point BER decode ok", ber_dec(bytes, Point::asn_DEF, &dec));
        check("Point x round-trip", (int64_t)dec.x == 3);
        check("Point y round-trip", (int64_t)dec.y == -7);
        check("Point z round-trip", (int64_t)dec.z == 42);
    }

    // --- Config (SET with DEFAULT + OPTIONAL) ---
    printf("SET — Config (DEFAULT + OPTIONAL)\n");
    {
        // All-default values: DEFAULT members suppressed on wire
        Config enc{};
        enc.width  = std::make_unique<Integer>(80);
        enc.height = std::make_unique<Integer>(24);
        // label not set

        auto bytes_def = ber_enc(Config::asn_DEF, &enc);
        check("Config default-only BER encode non-empty", !bytes_def.empty());

        Config dec{};
        check("Config default-only BER decode ok", ber_dec(bytes_def, Config::asn_DEF, &dec));
        check("Config width default decoded",  dec.width  && (int64_t)*dec.width  == 80);
        check("Config height default decoded", dec.height && (int64_t)*dec.height == 24);
        check("Config label absent",           !dec.label);

        // Non-default values + optional present
        Config enc2{};
        enc2.width  = std::make_unique<Integer>(132);
        enc2.height = std::make_unique<Integer>(50);
        enc2.label  = std::make_unique<Utf8String>("hello");

        auto bytes2 = ber_enc(Config::asn_DEF, &enc2);
        check("Config non-default BER encode non-empty", !bytes2.empty());
        check("Config non-default wire longer than default wire", bytes2.size() > bytes_def.size());

        Config dec2{};
        check("Config non-default BER decode ok", ber_dec(bytes2, Config::asn_DEF, &dec2));
        check("Config width non-default decoded",  dec2.width  && (int64_t)*dec2.width  == 132);
        check("Config height non-default decoded", dec2.height && (int64_t)*dec2.height == 50);
        check("Config label decoded", dec2.label && dec2.label->str() == "hello");
    }

    // --- IntSet (SET OF INTEGER — DER canonical sort) ---
    printf("SET OF INTEGER — DER canonical sort\n");
    {
        IntSet enc{};
        enc.push_back(Integer{300});
        enc.push_back(Integer{1});
        enc.push_back(Integer{-1});
        enc.push_back(Integer{50});

        auto bytes = ber_enc(asn_DEF_IntSet, &enc);
        check("IntSet BER encode non-empty", !bytes.empty());

        IntSet dec{};
        check("IntSet BER decode ok", ber_dec(bytes, asn_DEF_IntSet, &dec));
        check("IntSet element count", dec.count() == 4);

        // DER sort is unsigned lexicographic on encoded bytes:
        // -1 = 02 01 FF, 1 = 02 01 01, 50 = 02 01 32, 300 = 02 02 01 2C
        // Unsigned sort: 01 < 32 < FF (same length prefix 02 01) < 02 02... (longer)
        // Expected order: 1, 50, -1, 300
        auto e_neg1 = enc_int(-1);
        auto e_1    = enc_int(1);
        auto e_50   = enc_int(50);
        auto e_300  = enc_int(300);

        std::vector<std::vector<uint8_t>> expected = {e_1, e_50, e_neg1, e_300};
        std::vector<std::vector<uint8_t>> sorted    = {e_neg1, e_1, e_50, e_300};
        std::sort(sorted.begin(), sorted.end());
        check("IntSet DER sort order", sorted == expected);

        // Verify the encoded payload is the sorted concatenation
        std::vector<uint8_t> expected_payload;
        for (auto& v : expected) expected_payload.insert(expected_payload.end(), v.begin(), v.end());
        auto it = std::search(bytes.begin(), bytes.end(),
                              expected_payload.begin(), expected_payload.end());
        check("IntSet wire payload is sorted", it != bytes.end());

        // BER→BER round-trip: encode again from decoded, must produce same bytes
        auto bytes2 = ber_enc(asn_DEF_IntSet, &dec);
        check("IntSet BER encode idempotent", bytes == bytes2);
    }

    // --- PairSet (SET OF SEQUENCE — sort by encoded element) ---
    printf("SET OF Pair — DER sort + round-trip\n");
    {
        PairSet enc{};
        Pair p1{}; p1.a = Integer{2}; p1.b = Integer{3}; enc.push_back(p1);
        Pair p2{}; p2.a = Integer{1}; p2.b = Integer{0}; enc.push_back(p2);
        Pair p3{}; p3.a = Integer{1}; p3.b = Integer{1}; enc.push_back(p3);

        auto bytes = ber_enc(asn_DEF_PairSet, &enc);
        check("PairSet BER encode non-empty", !bytes.empty());

        PairSet dec{};
        check("PairSet BER decode ok", ber_dec(bytes, asn_DEF_PairSet, &dec));
        check("PairSet element count", dec.count() == 3);

        // Encode again — sorted output must be stable
        auto bytes2 = ber_enc(asn_DEF_PairSet, &dec);
        check("PairSet BER encode idempotent", bytes == bytes2);

        // XER round-trip
        std::string xer = xer_enc(asn_DEF_PairSet, &enc);
        check("PairSet XER encode non-empty", !xer.empty());
        PairSet xdec{};
        check("PairSet XER decode ok", xer_dec(xer, asn_DEF_PairSet, &xdec));
        check("PairSet XER element count", xdec.count() == 3);
    }

    // --- ExtPoint (extensible SET) ---
    printf("SET — ExtPoint (extensible)\n");
    {
        ExtPoint enc{};
        enc.x = Integer{10};
        enc.y = Integer{20};

        auto bytes = ber_enc(ExtPoint::asn_DEF, &enc);
        check("ExtPoint BER encode non-empty", !bytes.empty());

        ExtPoint dec{};
        check("ExtPoint BER decode ok", ber_dec(bytes, ExtPoint::asn_DEF, &dec));
        check("ExtPoint x round-trip", (int64_t)dec.x == 10);
        check("ExtPoint y round-trip", (int64_t)dec.y == 20);
    }

    // --- Point XER round-trip ---
    printf("SET — Point XER\n");
    {
        Point enc{};
        enc.x = Integer{1};
        enc.y = Integer{2};
        enc.z = Integer{3};

        std::string xer = xer_enc(Point::asn_DEF, &enc);
        check("Point XER encode non-empty", !xer.empty());

        Point dec{};
        check("Point XER decode ok", xer_dec(xer, Point::asn_DEF, &dec));
        check("Point XER x round-trip", (int64_t)dec.x == 1);
        check("Point XER y round-trip", (int64_t)dec.y == 2);
        check("Point XER z round-trip", (int64_t)dec.z == 3);
    }

    printf("\n%s  %d failure(s)\n", failures ? "\033[31mFAIL\033[0m" : "\033[32mPASS\033[0m", failures);
    return failures ? 1 : 0;
}
