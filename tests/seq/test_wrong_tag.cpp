// BER decode must reject a TLV whose identifier octets are not the type's
// own tag (X.690 §8.1.2) wherever the value is decoded through its type:
// the PDU itself, an untagged SEQUENCE member, and a SEQUENCE OF element.
// Schema: tests/asn1/wrong_tag_test.asn1
//
// A reference to a tagged CONTAINING type assignment (`t TCont`, `e TContE`)
// carries that assignment's tag (X.680 §31.2), IMPLICIT or EXPLICIT, as a
// SEQUENCE member and as a CHOICE alternative.
#include <cstdio>
#include <span>
#include <vector>
#include <asn1cpp/asn1cpp.hpp>
#include "Inner.hpp"
#include "WtPick.hpp"
#include "WtSeq.hpp"
#include "WtListSeq.hpp"
#include "WtListOct.hpp"
#include "WtListList.hpp"

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

// Offsets of the identifier octet of the outer TLV and of each TLV directly
// inside it.
static std::vector<std::size_t> tag_offsets(const std::vector<uint8_t>& enc) {
    std::vector<std::size_t> out{0};
    BerReader r{std::span<const uint8_t>(enc)};
    auto outer = r.read_tlv();
    if (!outer) return out;
    BerReader inner{outer->value};
    while (!inner.at_end()) {
        auto raw = inner.read_raw_tlv();
        if (!raw) break;
        out.push_back(static_cast<std::size_t>(raw->data() - enc.data()));
    }
    return out;
}

// Change the tag class of each TLV in turn (universal ↔ context,
// application ↔ private) and expect decode to fail.
template<class T>
static void expect_each_rejected(const char* what, const std::vector<uint8_t>& enc,
                                 const TypeDescriptor& def) {
    for (std::size_t off : tag_offsets(enc)) {
        auto bad = enc;
        bad[off] ^= 0x80;
        T out{};
        char name[128];
        std::snprintf(name, sizeof name, "%s: tag %02X -> %02X at offset %zu rejected",
                      what, enc[off], bad[off], off);
        check(name, !decode(bad, def, out));
    }
}

static Inner make_inner(int64_t x) {
    Inner i;
    i.x = Integer{x};
    return i;
}

int main() {
    printf("\n── Wrong tag on a value decoded through its own type ───────────\n");

    {
        WtSeq v;
        v.a = make_inner(5);
        v.o.set(std::vector<uint8_t>{0x61});
        v.l.push_back(Integer{1});
        v.c.set_value(make_inner(7));
        v.t.set_value(make_inner(8));
        v.e.set_value(make_inner(9));
        v.p.set_present(WtPick::PR::n);
        v.p.n() = Integer{4};
        auto enc = encode(v, WtSeq::asn_DEF);
        auto offs = tag_offsets(enc);
        check("WtSeq has 7 members", offs.size() == 8);
        if (offs.size() == 8) {
            check("t carries [APPLICATION 5] IMPLICIT (45)", enc[offs[5]] == 0x45);
            check("e carries [APPLICATION 6] EXPLICIT (66) around 04",
                  enc[offs[6]] == 0x66 && enc[offs[6] + 2] == 0x04);
        }
        WtSeq back{};
        check("WtSeq round-trips", decode(enc, WtSeq::asn_DEF, back) &&
              back.t.value() && back.t.value()->x.value() == 8 &&
              back.e.value() && back.e.value()->x.value() == 9);
        expect_each_rejected<WtSeq>("WtSeq", enc, WtSeq::asn_DEF);
    }

    {
        WtPick p;
        p.set_present(WtPick::PR::t);
        p.t().set_value(make_inner(2));
        auto enc = encode(p, WtPick::asn_DEF);
        check("CHOICE alternative t carries [APPLICATION 5] (45)", !enc.empty() && enc[0] == 0x45);
        WtPick back{};
        check("CHOICE alternative t round-trips", decode(enc, WtPick::asn_DEF, back) &&
              back.present() == WtPick::PR::t && back.t().value() && back.t().value()->x.value() == 2);

        p.set_present(WtPick::PR::e);
        p.e().set_value(make_inner(3));
        enc = encode(p, WtPick::asn_DEF);
        check("CHOICE alternative e carries [APPLICATION 6] EXPLICIT around 04",
              enc.size() > 2 && enc[0] == 0x66 && enc[2] == 0x04);
        back = WtPick{};
        check("CHOICE alternative e round-trips", decode(enc, WtPick::asn_DEF, back) &&
              back.present() == WtPick::PR::e && back.e().value() && back.e().value()->x.value() == 3);
    }

    {
        WtListSeq v;
        v.push_back(make_inner(1));
        expect_each_rejected<WtListSeq>("SEQUENCE OF Inner", encode(v, asn_DEF_WtListSeq),
                                        asn_DEF_WtListSeq);
    }

    {
        WtListOct v;
        v.push_back(OctetString{});
        auto enc = encode(v, asn_DEF_WtListOct);
        expect_each_rejected<WtListOct>("SEQUENCE OF OCTET STRING", enc, asn_DEF_WtListOct);
        auto as_int = enc;
        as_int[2] = 0x02;
        WtListOct out{};
        check("SEQUENCE OF OCTET STRING: INTEGER element rejected",
              !decode(as_int, asn_DEF_WtListOct, out));
    }

    {
        WtListList v;
        WtListListAnon e;
        e.push_back(Integer{3});
        v.push_back(e);
        expect_each_rejected<WtListList>("SEQUENCE OF SEQUENCE OF", encode(v, asn_DEF_WtListList),
                                         asn_DEF_WtListList);
    }

    printf("\n%s (%d failure%s)\n", failures ? "FAILED" : "OK", failures, failures == 1 ? "" : "s");
    return failures ? 1 : 0;
}
