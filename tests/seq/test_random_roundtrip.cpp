// Randomised BER/XER round-trip test covering all primitive types.
//
// Schema: tests/asn1/roundtrip_test.asn1 (Container — wraps all primitives
// that RandomFiller supports: BOOLEAN, INTEGER, REAL, NULL, OCTET STRING,
// BIT STRING, OID, UTCTime, GeneralizedTime, all string types, ENUMERATED).
//
// For each seed the test:
//   1. RandomFiller → Container instance
//   2. BER round-trip: encode → decode → re-encode; assert bytes identical
//   3. XER round-trip: encode → decode → re-encode; assert strings identical
//   4. BER→XER→BER: encode BER, decode, encode XER, decode, encode BER; assert
//      first and last BER byte sequences identical (codec consistency)
//
// Any mismatch is a codec bug. No intentional corruption — this is correctness
// testing, not robustness testing (test_fuzz_ber.cpp covers corruption).

#include <cstdio>
#include <random>
#include <vector>
#include <string>
#include <sstream>
#include <span>
#include <asn1cpp/asn1cpp.hpp>
#include <asn1cpp/codec/RandomFiller.hpp>

#include "Container.hpp"

using namespace asn1;

static int total = 0;
static int failures = 0;

static void check(const char* label, bool cond) {
    ++total;
    if (!cond) {
        printf("  FAIL  %s\n", label);
        ++failures;
    }
}

static std::vector<uint8_t> ber_encode(const Container& v) {
    std::vector<uint8_t> buf;
    BerWriter w{buf}; BerEncodeStream s{w};
    BerCodec::instance().encode(s, Container::asn_DEF, &v);
    return buf;
}

static bool ber_decode(const std::vector<uint8_t>& buf, Container& out) {
    BerReader r{std::span<const uint8_t>{buf.data(), buf.size()}};
    BerDecodeStream s{r};
    return BerCodec::instance().decode(s, Container::asn_DEF, &out).has_value();
}

static std::string xer_encode(const Container& v) {
    std::ostringstream oss;
    XerEncodeStream s{oss};
    XerCodec::instance().encode(s, Container::asn_DEF, &v);
    return oss.str();
}

static bool xer_decode(const std::string& xml, Container& out) {
    XerDecodeStream s{xml};
    return XerCodec::instance().decode(s, Container::asn_DEF, &out).has_value();
}

static void run_seed(int seed, int records) {
    std::mt19937 rng(static_cast<uint64_t>(seed));
    FillConfig cfg;
    cfg.max_depth  = 5;
    cfg.max_seq_of = 6;
    RandomFiller filler{rng, cfg};

    int ber_ok = 0, xer_ok = 0, cross_ok = 0;

    for (int rec = 0; rec < records; ++rec) {
        Container v{};
        filler.fill(&v, Container::asn_DEF);

        // BER round-trip
        auto ber1 = ber_encode(v);
        Container v2{};
        bool dec_ok = ber_decode(ber1, v2);
        if (dec_ok) {
            auto ber2 = ber_encode(v2);
            if (ber1 == ber2) ++ber_ok;
        }

        // XER round-trip
        std::string xer1 = xer_encode(v);
        Container v3{};
        bool xdec_ok = xer_decode(xer1, v3);
        if (xdec_ok) {
            std::string xer2 = xer_encode(v3);
            if (xer1 == xer2) ++xer_ok;
        }

        // Cross-codec: BER → decode → XER → decode → BER; first == last
        Container v4{};
        if (ber_decode(ber1, v4)) {
            std::string xer_cross = xer_encode(v4);
            Container v5{};
            if (xer_decode(xer_cross, v5)) {
                auto ber_cross = ber_encode(v5);
                if (ber1 == ber_cross) ++cross_ok;
            }
        }
    }

    char label[64];
    snprintf(label, sizeof(label), "seed=%d  BER idempotent", seed);
    check(label, ber_ok == records);
    snprintf(label, sizeof(label), "seed=%d  XER idempotent", seed);
    check(label, xer_ok == records);
    snprintf(label, sizeof(label), "seed=%d  BER→XER→BER consistent", seed);
    check(label, cross_ok == records);
}

int main() {
    constexpr int RECORDS = 50;
    constexpr int SEEDS[] = {1, 7, 42, 99, 137};

    printf("Randomised BER/XER round-trip — %d records × %zu seeds\n",
           RECORDS, sizeof(SEEDS) / sizeof(SEEDS[0]));

    for (int seed : SEEDS)
        run_seed(seed, RECORDS);

    printf("\n%s  %d/%d checks passed\n",
           failures ? "FAIL" : "PASS", total - failures, total);
    return failures ? 1 : 0;
}
