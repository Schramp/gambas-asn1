// UPER encode-time SIZE range constraint validation (issue #114).
// Verifies encode_failed() for strings that violate SIZE(lower..upper) constraints.
#include <cstdio>
#include <string>
#include <vector>
#include <asn1cpp/asn1cpp.hpp>
#include <asn1cpp/codec/PerCodec.hpp>
#include "HasFixed.hpp"
#include "HasRange14.hpp"
#include "HasRange8b.hpp"
#include "HasRange1b.hpp"
#include "HasFromSize.hpp"
#include "HasFromSizeExt.hpp"

using namespace asn1;

static int failures = 0;

static void check(const char* label, bool cond) {
    if (cond) std::printf("  \033[32mPASS\033[0m  %s\n", label);
    else     { std::printf("  \033[31mFAIL\033[0m  %s\n", label); ++failures; }
}

/// @brief UPER-encode a value and return whether encode_failed() was set.
/// @param def   TypeDescriptor for the top-level type.
/// @param val   Pointer to the value to encode.
/// @return True if encode signalled a constraint violation.
static bool per_fails(const TypeDescriptor& def, const Asn1Object* val) {
    std::vector<uint8_t> buf;
    PerEncodeStream s{buf};
    PerCodec::instance().encode(s, def, val);
    return s.encode_failed();
}

int main() {
    std::printf("\n── UPER SIZE range constraint validation (issue #114) ──\n");

    // HasFixed: MyFixed3 = VisibleString (SIZE(3))
    {
        HasFixed v;
        v.value = MyFixed3("ABC");
        check("HasFixed SIZE(3): len=3 (exact) → ok",   !per_fails(HasFixed::asn_DEF, &v));
        v.value = MyFixed3("AB");
        check("HasFixed SIZE(3): len=2 (short)  → fail", per_fails(HasFixed::asn_DEF, &v));
        v.value = MyFixed3("ABCD");
        check("HasFixed SIZE(3): len=4 (long)   → fail", per_fails(HasFixed::asn_DEF, &v));
    }

    // HasRange14: MyRange14 = VisibleString (SIZE(1..4))
    {
        HasRange14 v;
        v.value = MyRange14("A");
        check("HasRange14 SIZE(1..4): len=1 (lower) → ok",  !per_fails(HasRange14::asn_DEF, &v));
        v.value = MyRange14("AB");
        check("HasRange14 SIZE(1..4): len=2 (mid)   → ok",  !per_fails(HasRange14::asn_DEF, &v));
        v.value = MyRange14("ABCD");
        check("HasRange14 SIZE(1..4): len=4 (upper) → ok",  !per_fails(HasRange14::asn_DEF, &v));
        v.value = MyRange14("");
        check("HasRange14 SIZE(1..4): len=0 (empty) → fail", per_fails(HasRange14::asn_DEF, &v));
        v.value = MyRange14("ABCDE");
        check("HasRange14 SIZE(1..4): len=5 (long)  → fail", per_fails(HasRange14::asn_DEF, &v));
    }

    // HasRange8b: MyRange0-180 = VisibleString (SIZE(0..180))
    {
        HasRange8b v;
        v.value = MyRange0_180("");
        check("HasRange8b SIZE(0..180): len=0   → ok",   !per_fails(HasRange8b::asn_DEF, &v));
        v.value = MyRange0_180(std::string(180, 'X'));
        check("HasRange8b SIZE(0..180): len=180 → ok",   !per_fails(HasRange8b::asn_DEF, &v));
        v.value = MyRange0_180(std::string(181, 'X'));
        check("HasRange8b SIZE(0..180): len=181 → fail",  per_fails(HasRange8b::asn_DEF, &v));
    }

    // HasRange1b: MyRange180-181 = VisibleString (SIZE(180..181))
    {
        HasRange1b v;
        v.value = MyRange180_181(std::string(179, 'X'));
        check("HasRange1b SIZE(180..181): len=179 → fail", per_fails(HasRange1b::asn_DEF, &v));
        v.value = MyRange180_181(std::string(180, 'X'));
        check("HasRange1b SIZE(180..181): len=180 → ok",  !per_fails(HasRange1b::asn_DEF, &v));
        v.value = MyRange180_181(std::string(181, 'X'));
        check("HasRange1b SIZE(180..181): len=181 → ok",  !per_fails(HasRange1b::asn_DEF, &v));
        v.value = MyRange180_181(std::string(182, 'X'));
        check("HasRange1b SIZE(180..181): len=182 → fail", per_fails(HasRange1b::asn_DEF, &v));
    }

    // HasFromSize: MyFromSize = VisibleString (FROM("A"|"D")) (SIZE(1..4))
    {
        HasFromSize v;
        v.value = MyFromSize("AD");
        check("HasFromSize FROM+SIZE: \"AD\" len=2 in-alpha → ok",   !per_fails(HasFromSize::asn_DEF, &v));
        v.value = MyFromSize("ADADA");
        check("HasFromSize FROM+SIZE: \"ADADA\" len=5 too long → fail", per_fails(HasFromSize::asn_DEF, &v));
        v.value = MyFromSize("AZ");
        check("HasFromSize FROM+SIZE: \"AZ\" 'Z' not in alpha → fail", per_fails(HasFromSize::asn_DEF, &v));
        v.value = MyFromSize("");
        check("HasFromSize FROM+SIZE: \"\" len=0 too short  → fail",   per_fails(HasFromSize::asn_DEF, &v));
    }

    // HasFromSizeExt: MyFromSizeExt = VisibleString (FROM("A"|"D")) (SIZE(1..4,...))
    // Regression for #481: extensible SIZE+FROM previously classified a
    // value purely by size, never checking alphabet membership — an
    // in-size value with an out-of-alphabet character was wrongly rejected
    // as an encode failure instead of being encoded via the extensible
    // open-type escape (X.691 §26.5.7's in-root test is SIZE AND alphabet).
    {
        HasFromSizeExt v;
        v.value = MyFromSizeExt("AD");
        check("HasFromSizeExt FROM+SIZE ext: \"AD\" in-size, in-alpha → ok", !per_fails(HasFromSizeExt::asn_DEF, &v));

        v.value = MyFromSizeExt("AZ");
        check("HasFromSizeExt FROM+SIZE ext: \"AZ\" in-size, 'Z' not in alpha → ok (out-of-root escape)",
              !per_fails(HasFromSizeExt::asn_DEF, &v));

        // Round-trip the out-of-alphabet-but-in-size case through the open-type
        // escape path to confirm it's not just "doesn't crash" but byte-exact.
        std::vector<uint8_t> buf;
        PerEncodeStream es{buf};
        PerCodec::instance().encode(es, HasFromSizeExt::asn_DEF, &v);
        es.flush();
        HasFromSizeExt back{};
        PerDecodeStream ds{buf};
        auto dec_ok = PerCodec::instance().decode(ds, HasFromSizeExt::asn_DEF, &back).has_value();
        check("HasFromSizeExt FROM+SIZE ext: \"AZ\" round-trip decodes ok", dec_ok);
        check("HasFromSizeExt FROM+SIZE ext: \"AZ\" round-trip byte-exact",
              dec_ok && back.value.str() == v.value.str());
    }

    std::printf("\n  %d failed.\n", failures);
    if (failures) return 1;
    std::printf("  All tests passed.\n");
    return 0;
}
