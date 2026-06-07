// BER round-trip tests for EXPLICIT tagging on non-CHOICE types.
// Schema: tests/asn1/explicit_tag_test.asn1
//
// Key invariant: [N] EXPLICIT T must emit Tag{Context,N,true} (constructed)
// regardless of whether T is primitive.  Previously INTEGER produced
// Tag{Context,N,false} (primitive) — wrong per X.690 §8.14.3.
#include <cstdio>
#include <vector>
#include <span>
#include <asn1cpp/asn1cpp.hpp>
#include "WithExplicitInt.hpp"
#include "WithExplicitSeq.hpp"
#include "Mixed.hpp"
#include "Inner.hpp"

using namespace asn1;

static int failures = 0;

static void check(const char* name, bool cond) {
    if (cond) printf("  \033[32mPASS\033[0m  %s\n", name);
    else { printf("  \033[31mFAIL\033[0m  %s\n", name); ++failures; }
}

template<typename T>
static std::vector<uint8_t> encode(const T& v, const TypeDescriptor& def) {
    std::vector<uint8_t> buf;
    BerWriter w{buf};
    BerEncodeStream s{w};
    BerCodec::instance().encode(s, def, &v);
    return buf;
}

template<typename T>
static bool decode(std::span<const uint8_t> bytes, const TypeDescriptor& def, T& out) {
    BerReader r{bytes};
    BerDecodeStream s{r};
    return BerCodec::instance().decode(s, def, &out).has_value();
}

int main() {
    printf("\n── EXPLICIT tag on non-CHOICE — BER ────────────────────────────\n");

    // WithExplicitInt { num = 42 }
    // Expected BER:
    //   30 06            SEQUENCE, 6 bytes
    //     a0 04          [0] EXPLICIT, constructed, 4 bytes   ← must be constructed
    //       02 02 00 2a  INTEGER 42
    {
        WithExplicitInt v{};
        v.set_num(42);
        auto enc = encode(v, WithExplicitInt::asn_DEF);

        check("[0] EXPLICIT INTEGER: outer tag constructed (0xa0)",
              enc.size() >= 2 && enc[2] == 0xa0);
        check("[0] EXPLICIT INTEGER: full BER correct",
              enc == std::vector<uint8_t>({0x30,0x05, 0xa0,0x03, 0x02,0x01,0x2a}));

        WithExplicitInt got{};
        check("[0] EXPLICIT INTEGER: decode ok",  decode(enc, WithExplicitInt::asn_DEF, got));
        check("[0] EXPLICIT INTEGER: round-trip",  got.num.value() == 42);
    }

    printf("\n── EXPLICIT tag on SEQUENCE ─────────────────────────────────────\n");

    // WithExplicitSeq { inner = Inner{x=7} }
    // Expected BER:
    //   30 08              SEQUENCE
    //     a1 06            [1] EXPLICIT, constructed
    //       30 04          SEQUENCE (Inner)
    //         02 02 00 07  INTEGER 7
    {
        WithExplicitSeq v{};
        v.inner.x.set(7);
        auto enc = encode(v, WithExplicitSeq::asn_DEF);

        check("[1] EXPLICIT SEQUENCE: outer tag constructed (0xa1)",
              enc.size() >= 4 && enc[2] == 0xa1);
        check("[1] EXPLICIT SEQUENCE: full BER correct",
              enc == std::vector<uint8_t>({0x30,0x07, 0xa1,0x05, 0x30,0x03, 0x02,0x01,0x07}));

        WithExplicitSeq got{};
        check("[1] EXPLICIT SEQUENCE: decode ok",  decode(enc, WithExplicitSeq::asn_DEF, got));
        check("[1] EXPLICIT SEQUENCE: round-trip",  got.inner.x.value() == 7);
    }

    printf("\n── IMPLICIT vs EXPLICIT mixed ───────────────────────────────────\n");

    // Mixed { implicit=1, explicit=2 }
    // Expected BER:
    //   30 09
    //     80 01 01     [0] IMPLICIT INTEGER 1  (primitive)
    //     a1 04        [1] EXPLICIT INTEGER 2  (constructed)
    //       02 02 00 02
    {
        Mixed v{};
        v.set_implicit(1);
        v.set_explicit_(2);
        auto enc = encode(v, Mixed::asn_DEF);

        check("IMPLICIT [0] INTEGER: primitive tag (0x80)",
              enc.size() >= 3 && enc[2] == 0x80);
        check("EXPLICIT [1] INTEGER: constructed tag (0xa1)",
              enc.size() >= 6 && enc[5] == 0xa1);
        check("Mixed: full BER correct",
              enc == std::vector<uint8_t>({0x30,0x08,
                                           0x80,0x01,0x01,
                                           0xa1,0x03, 0x02,0x01,0x02}));

        Mixed got{};
        check("Mixed: decode ok",     decode(enc, Mixed::asn_DEF, got));
        check("Mixed: implicit r/t",  got.implicit.value() == 1);
        check("Mixed: explicit r/t",  got.explicit_.value() == 2);
    }

    printf("\n");
    if (failures) { printf("  %d test(s) FAILED\n", failures); return 1; }
    printf("  All tests passed.\n");
    return 0;
}
