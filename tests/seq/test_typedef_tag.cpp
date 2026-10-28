// BER tests for type assignments that put their own tag on a builtin type
// (X.680 §31.2): `TBool ::= [APPLICATION 1] BOOLEAN` and friends.
// Schema: tests/asn1/typedef_tag_test.asn1
//
// A reference to such a type must carry the type assignment's tag on the
// wire (IMPLICIT replaces the universal tag, X.690 §8.14.3; EXPLICIT wraps
// it, §8.14.2), and decode must accept only that tag. The builtin's
// universal tag is still what selects the value representation
// (TypeDescriptor::natural_tag / builtin_tag()), so RandomFiller, XER and
// JER keep treating TBool as a BOOLEAN.
#include <cstdio>
#include <random>
#include <span>
#include <vector>
#include <asn1cpp/asn1cpp.hpp>
#include <asn1cpp/codec/RandomFiller.hpp>
#include "TBool.hpp"
#include "Tagged.hpp"

using namespace asn1;

static int failures = 0;

static void check(const char* name, bool cond) {
    if (cond) printf("  \033[32mPASS\033[0m  %s\n", name);
    else { printf("  \033[31mFAIL\033[0m  %s\n", name); ++failures; }
}

static std::vector<uint8_t> encode(const Asn1Object& v, const TypeDescriptor& def) {
    std::vector<uint8_t> buf;
    BerWriter w{buf};
    BerEncodeStream s{w};
    BerCodec::instance().encode(s, def, &v);
    return buf;
}

static bool decode(std::span<const uint8_t> bytes, const TypeDescriptor& def, Asn1Object& out) {
    BerReader r{bytes};
    BerDecodeStream s{r};
    return BerCodec::instance().decode(s, def, &out).has_value();
}

static bool is_app(const Tag& t, uint32_t n) { return t.cls == TagClass::Application && t.number == n; }

int main() {
    printf("\n── Type-assignment tag on a builtin type ───────────────────────\n");

    {
        TBool v{true};
        auto enc = encode(v, asn_DEF_TBool);
        check("TBool standalone: [APPLICATION 1] primitive (41 01 FF)",
              enc == std::vector<uint8_t>{0x41, 0x01, 0xFF});
        TBool back{};
        const std::vector<uint8_t> app{0x41, 0x01, 0xFF};
        check("TBool decodes its own tag", decode(app, asn_DEF_TBool, back) && back.value());
        const std::vector<uint8_t> uni{0x01, 0x01, 0xFF};
        TBool wrong{};
        check("TBool rejects the universal BOOLEAN tag", !decode(uni, asn_DEF_TBool, wrong));
    }

    std::mt19937 rng(7);
    FillConfig cfg;
    for (int round = 0; round < 20; ++round) {
        Tagged v;
        RandomFiller f{rng, cfg};
        if (!f.fill(&v, Tagged::asn_DEF, 0, true)) { check("RandomFiller fills Tagged", false); break; }
        auto enc = encode(v, Tagged::asn_DEF);

        BerReader outer{enc};
        auto seq = outer.read_tlv();
        if (!seq) { check("Tagged encodes", false); break; }
        BerReader r{seq->value};
        std::vector<Tag> tags;
        std::vector<std::span<const uint8_t>> values;
        while (!r.at_end()) {
            auto t = r.read_tlv();
            if (!t) break;
            tags.push_back(t->tag);
            values.push_back(t->value);
        }
        // b o s t r l u i x z e q w → APPLICATION 1..13, then c, lst, lq, lw.
        bool ok = tags.size() >= 17;
        for (uint32_t n = 1; ok && n <= 13; ++n) ok = is_app(tags[n - 1], n);
        ok = ok && (is_app(tags[13], 1) || is_app(tags[13], 3) || is_app(tags[13], 8));
        auto elems_are = [](std::span<const uint8_t> content, uint32_t n) {
            BerReader er{content};
            while (!er.at_end()) {
                auto t = er.read_tlv();
                if (!t || !is_app(t->tag, n)) return false;
            }
            return true;
        };
        ok = ok && elems_are(values[14], 3) && elems_are(values[15], 12) && elems_are(values[16], 13);
        // TExp is EXPLICIT: [APPLICATION 13] wraps a universal INTEGER TLV.
        if (ok) {
            BerReader wr{values[12]};
            auto inner = wr.read_tlv();
            ok = inner && inner->tag == Tag::universal(UniversalTag::Integer);
        }
        if (!ok) { check("every member and element carries its type's own tag", false); break; }

        Tagged back;
        if (!decode(enc, Tagged::asn_DEF, back) || encode(back, Tagged::asn_DEF) != enc) {
            check("Tagged BER round-trip", false);
            break;
        }
        if (round == 19) {
            check("every member and element carries its type's own tag (20 random values)", true);
            check("Tagged BER round-trip (20 random values)", true);
        }
    }

    printf("\n%s (%d failure%s)\n", failures ? "FAILED" : "OK", failures, failures == 1 ? "" : "s");
    return failures ? 1 : 0;
}
