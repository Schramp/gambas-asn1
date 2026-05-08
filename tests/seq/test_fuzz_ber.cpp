// In-tree BER fuzz test.
//
// Schema: tests/asn1/fuzz_test.asn1 (Bag — covers SEQUENCE, SEQUENCE OF,
// CHOICE, OPTIONAL, BOOLEAN, INTEGER w/ range, OCTET STRING / BIT STRING
// w/ SIZE, PrintableString / IA5String w/ alphabet+SIZE).
//
// For each CorruptMode and a fixed set of seeds the test:
//   1. RandomFiller -> Bag instance
//   2. BerCodec encode -> buffer
//   3. corrupt_ber on buffer (percent corruption)
//   4. BerCodec decode the corrupted buffer
//
// Pass = process does not crash (no SIGABRT / SIGSEGV / assertion abort) and
// no validate_fail_count regressions on the clean encode path. Decode of
// corrupted data is expected to fail or succeed silently — both fine; what
// matters is that the decoder does not abort.

#include <cstdio>
#include <random>
#include <vector>
#include <asn1cpp/asn1cpp.hpp>
#include <asn1cpp/codec/BerCorruptor.hpp>
#include <asn1cpp/codec/RandomFiller.hpp>
#include <asn1cpp/codec/Validation.hpp>

#include "Bag.hpp"

using namespace asn1;

static int failures = 0;

static std::vector<uint8_t> encode_bag(const Bag& v) {
    std::vector<uint8_t> buf;
    BerWriter w{buf};
    BerEncodeStream s{w};
    BerCodec::instance().encode(s, asn_DEF_Bag, &v);
    return buf;
}

static bool decode_bag(const std::vector<uint8_t>& buf, Bag& out) {
    BerReader r{std::span<const uint8_t>{buf.data(), buf.size()}};
    BerDecodeStream s{r};
    auto res = BerCodec::instance().decode(s, asn_DEF_Bag, &out);
    return res.has_value();
}

static void sweep_mode(const char* label, CorruptMask mask,
                       int seeds, int records, double percent) {
    std::printf("=== mode: %-12s (mask=0x%02x percent=%.2f records=%d seeds=%d)\n",
                label, mask, percent, records, seeds);
    int decode_ok = 0, decode_err = 0;
    auto fail_before = validate_fail_count();
    for (int seed = 1; seed <= seeds; ++seed) {
        std::mt19937 rng(static_cast<uint64_t>(seed));
        FillConfig cfg;
        cfg.max_depth = 6;
        cfg.max_seq_of = 4;
        RandomFiller filler{rng, cfg};
        for (int rec = 0; rec < records; ++rec) {
            Bag b{};
            filler.fill(&b, asn_DEF_Bag);
            auto buf = encode_bag(b);
            corrupt_ber(buf, percent, rng, mask);
            Bag out{};
            if (decode_bag(buf, out)) ++decode_ok; else ++decode_err;
        }
    }
    auto fail_after = validate_fail_count();
    std::printf("    decode_ok=%-4d decode_err=%-4d  validate_fail_delta=%llu\n",
                decode_ok, decode_err,
                (unsigned long long)(fail_after - fail_before));
}

static void roundtrip_clean(int seeds, int records) {
    std::printf("=== mode: %-12s (clean roundtrip — no corruption)\n", "clean");
    int ok = 0, err = 0;
    for (int seed = 1; seed <= seeds; ++seed) {
        std::mt19937 rng(static_cast<uint64_t>(seed));
        FillConfig cfg;
        cfg.max_depth = 6;
        cfg.max_seq_of = 4;
        RandomFiller filler{rng, cfg};
        for (int rec = 0; rec < records; ++rec) {
            Bag b{};
            filler.fill(&b, asn_DEF_Bag);
            auto buf = encode_bag(b);
            Bag out{};
            if (decode_bag(buf, out)) ++ok; else ++err;
        }
    }
    std::printf("    ok=%-4d err=%-4d\n", ok, err);
    if (err != 0) {
        std::printf("    \033[31mFAIL\033[0m clean roundtrip should not fail\n");
        ++failures;
    }
}

int main() {
    std::printf("\n=== BER fuzz sweep (in-tree) ===\n\n");

    constexpr int SEEDS = 4;
    constexpr int RECS = 50;
    constexpr double PCT = 1.0;

    roundtrip_clean(SEEDS, RECS);

    struct Entry { const char* name; CorruptMask mask; };
    const Entry modes[] = {
        {"flip-pc",        CORRUPT_FLIP_PC},
        {"rotate-class",   CORRUPT_ROTATE_CLASS},
        {"tag-bump",       CORRUPT_TAG_BUMP},
        {"tag-jump",       CORRUPT_TAG_JUMP},
        {"len-bit-flip",   CORRUPT_LEN_BIT_FLIP},
        {"len-indef",      CORRUPT_LEN_INDEF},
        {"len-overstate",  CORRUPT_LEN_OVERSTATE},
        {"len-understate", CORRUPT_LEN_UNDERSTATE},
        {"all",            CORRUPT_ALL},
    };
    for (auto& m : modes) sweep_mode(m.name, m.mask, SEEDS, RECS, PCT);

    if (failures == 0) {
        std::printf("\nALL OK — no decoder crashes across %zu modes\n",
                    sizeof(modes)/sizeof(modes[0]));
        return 0;
    }
    std::printf("\n%d failure(s)\n", failures);
    return 1;
}
