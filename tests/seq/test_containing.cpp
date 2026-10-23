// Contained values in generated code: OCTET STRING fields holding the
// encoding of another type, from a contents constraint (X.682 §11) or the
// containing_test.container.json sidecar. Generated from
// tests/asn1/containing_test.asn1.
#include <algorithm>
#include <cstdio>
#include <sstream>
#include <vector>
#include <asn1cpp/asn1cpp.hpp>
#include "Envelope.hpp"
#include "Holder.hpp"
#include "Inner.hpp"
#include "Pick.hpp"

using namespace asn1;

static int failures = 0;
static void check(const char* name, bool cond) {
    printf("  %s  %s\n", cond ? "PASS" : "FAIL", name);
    if (!cond) ++failures;
}

static std::vector<uint8_t> ber(const TypeDescriptor& def, const Asn1Object& v) {
    std::vector<uint8_t> out;
    BerWriter w(out);
    BerEncodeStream s{w};
    BerCodec::instance().encode(s, def, &v);
    return out;
}

template<class T>
static bool unber(const std::vector<uint8_t>& in, T& v, const ContainedOptions* opts = nullptr) {
    BerReader r(in);
    r.set_contained(opts);
    BerDecodeStream s{r};
    return BerCodec::instance().decode(s, T::asn_DEF, &v).has_value();
}

static std::vector<uint8_t> per(const TypeDescriptor& def, const Asn1Object& v) {
    std::vector<uint8_t> out;
    PerEncodeStream s(out);
    PerCodec::instance().encode(s, def, &v);
    s.flush();
    return out;
}

template<class T>
static bool unper(const std::vector<uint8_t>& in, T& v) {
    PerDecodeStream s(in);
    return PerCodec::instance().decode(s, T::asn_DEF, &v).has_value();
}

static Inner make_inner(int64_t id) {
    Inner i;
    i.id = Integer{id};
    return i;
}

static Holder make_holder(Kind::Enm kind) {
    Holder h;
    h.kind = kind;
    h.viaConstraint.set_value(make_inner(1));
    h.viaAlias.set_value(make_inner(2));
    // viaConfig is configured `decoder: zero_padding`: the encoding of an
    // Inner followed by block padding.
    auto bytes = ber(Inner::asn_DEF, make_inner(3));
    bytes.insert(bytes.end(), 5, 0x00);
    h.viaConfig.set(bytes);
    h.raw.set(std::vector<uint8_t>{0xDE, 0xAD});
    h.viaSized.set_value(make_inner(5));
    return h;
}

static void test_ber_sequence() {
    printf("BER SEQUENCE\n");
    auto wire = ber(Holder::asn_DEF, make_holder(Kind::plain));
    Holder d;
    check("decodes", unber(wire, d));
    check("CONTAINING member decoded", d.viaConstraint.status() == ContainedStatus::Decoded &&
                                       d.viaConstraint.value() && d.viaConstraint.value()->id.value() == 1);
    check("CONTAINING through an alias decoded", d.viaAlias.value() && d.viaAlias.value()->id.value() == 2);
    check("sidecar member decoded past its zero padding",
          d.viaConfig.status() == ContainedStatus::Decoded && d.viaConfig.value() &&
          d.viaConfig.value()->id.value() == 3 && d.viaConfig.error().empty());
    check("unconstrained OCTET STRING untouched", d.raw.size() == 2);
    check("not dirty after decode", !d.viaConstraint.dirty() && !d.viaConfig.dirty());
    check("re-encodes byte-exact (padding kept)", ber(Holder::asn_DEF, d) == wire);

    auto wire2 = ber(Holder::asn_DEF, make_holder(Kind::scrambled));
    Holder s;
    check("decodes with when sibling mismatch", unber(wire2, s));
    check("when mismatch skips the field", s.viaConfig.status() == ContainedStatus::Skipped && !s.viaConfig.has_value());
    check("other fields still decoded", s.viaConstraint.status() == ContainedStatus::Decoded);

    // A modified inner value is re-encoded.
    d.viaConstraint.value_mut()->id = Integer{77};
    Holder r;
    check("modified value round-trips", unber(ber(Holder::asn_DEF, d), r) &&
                                        r.viaConstraint.value() && r.viaConstraint.value()->id.value() == 77);

    // Copies (descriptor-driven deep_copy in generated copy constructors).
    Holder c = d;
    check("copy keeps inner values", c.viaConfig.value() && c.viaConfig.value()->id.value() == 3 &&
                                     c.viaConfig.value() != d.viaConfig.value());
}

static void test_bad_inner() {
    printf("BER inner failures\n");
    Holder h = make_holder(Kind::plain);
    h.viaConstraint.set(std::vector<uint8_t>{0x30, 0x05, 0x02});   // truncated SEQUENCE
    h.viaConfig.set(std::vector<uint8_t>{0x30, 0x03, 0x80, 0x01, 0x03, 0x00, 0x09});  // id [0] = 3, then 00 09
    auto wire = ber(Holder::asn_DEF, h);
    Holder d;
    check("outer decode survives a bad inner value", unber(wire, d));
    check("bad inner value is Failed, raw bytes kept",
          d.viaConstraint.status() == ContainedStatus::Failed && !d.viaConstraint.has_value() &&
          d.viaConstraint.size() == 3 && !d.viaConstraint.error().empty());
    check("non-zero padding keeps the value with a warning",
          d.viaConfig.status() == ContainedStatus::Decoded && d.viaConfig.value() &&
          !d.viaConfig.error().empty());
    check("failed value re-encodes its raw bytes", ber(Holder::asn_DEF, d) == wire);
}

static void test_options() {
    printf("Decode options\n");
    auto wire = ber(Holder::asn_DEF, make_holder(Kind::plain));
    ContainedOptions off;
    off.off = true;
    Holder d;
    check("off: decodes", unber(wire, d, &off));
    check("off: nothing decoded", d.viaConstraint.status() == ContainedStatus::Skipped &&
                                  d.viaConfig.status() == ContainedStatus::Skipped);

    // An application decoder replacing `zero_padding`, seeing the sibling.
    ContainedDecoders reg;
    int calls = 0;
    long seen_kind = -1;
    reg.add("zero_padding", [&](const ContainedDecodeArgs& a) {
        ++calls;
        seen_kind = static_cast<const Holder*>(a.outer)->kind.value();
        std::size_t used = 0;
        return ContainedDecoders::decode_value(a, a.raw, &used);
    });
    ContainedOptions opts{&reg};
    Holder h;
    check("hook: decodes", unber(wire, h, &opts));
    check("hook called once with the enclosing value", calls == 1 && seen_kind == Kind::plain);
    check("hook result stored", h.viaConfig.value() && h.viaConfig.value()->id.value() == 3);
    check("built-ins still used for the other fields", h.viaConstraint.status() == ContainedStatus::Decoded);
}

static void test_choice() {
    printf("BER CHOICE\n");
    Pick p;
    p.set_present(Pick::PR::inner);
    p.inner().set_value(make_inner(9));
    auto wire = ber(Pick::asn_DEF, p);
    Pick d;
    check("decodes", unber(wire, d));
    check("contained alternative decoded", d.present() == Pick::PR::inner && d.inner().value() &&
                                           d.inner().value()->id.value() == 9);
    Pick c = d;
    check("copy keeps the inner value", c.inner().value() && c.inner().value()->id.value() == 9);
}

static void test_recursion() {
    printf("Recursive contained type\n");
    Envelope e;
    e.depth = Integer{0};
    {
        Envelope e1;
        e1.depth = Integer{1};
        Envelope e2;
        e2.depth = Integer{2};
        e1.nested = std::make_unique<Containing<Envelope>>();
        e1.nested->set_value(std::move(e2));
        e.nested = std::make_unique<Containing<Envelope>>();
        e.nested->set_value(std::move(e1));
    }
    auto wire = ber(Envelope::asn_DEF, e);
    Envelope d;
    check("decodes", unber(wire, d));
    const Envelope* l1 = d.nested ? d.nested->value() : nullptr;
    const Envelope* l2 = l1 && l1->nested ? l1->nested->value() : nullptr;
    check("two levels decoded", l1 && l1->depth.value() == 1 && l2 && l2->depth.value() == 2 && !l2->nested);

    // A forged chain far deeper than the nesting limit: each level's bytes
    // are the next level's encoding. The limit spans levels, so a deep
    // level fails instead of overflowing the stack.
    std::vector<uint8_t> inner = ber(Envelope::asn_DEF, Envelope{});
    for (int i = 0; i < 400; ++i) {
        Envelope lvl;
        lvl.nested = std::make_unique<Containing<Envelope>>();
        lvl.nested->set(inner);
        inner = ber(Envelope::asn_DEF, lvl);
    }
    Envelope deep;
    check("deep chain: outer decode survives", unber(inner, deep));
    int levels = 0;
    const Envelope* cur = &deep;
    while (cur && cur->nested && cur->nested->value()) { cur = cur->nested->value(); ++levels; }
    check("deep chain: stops at the nesting limit",
          levels < 400 && cur && cur->nested && cur->nested->status() == ContainedStatus::Failed);
}

static void test_per() {
    printf("PER\n");
    auto wire = per(Holder::asn_DEF, make_holder(Kind::plain));
    Holder d;
    check("decodes", unper(wire, d));
    // Outer encoding for CONTAINING (X.682 §11.4): PER contents in a PER
    // outer value; the sidecar field is configured BER.
    check("CONTAINING member decoded as PER", d.viaConstraint.value() && d.viaConstraint.value()->id.value() == 1);
    check("sidecar member decoded as BER", d.viaConfig.value() && d.viaConfig.value()->id.value() == 3);
    check("re-encodes byte-exact", per(Holder::asn_DEF, d) == wire);

    // A sidecar member typed by a SIZE-constrained alias keeps the alias's
    // SIZE constraint: PER encodes its length as a constrained whole
    // number (X.691 §17.6), not as an unconstrained length.
    const auto& spec = *Holder::asn_DEF.sequence_spec;
    const TypeDescriptor* sized_def = nullptr;
    for (int i = 0; i < spec.count; ++i)
        if (std::string_view(spec.members[i].name) == "viaSized") sized_def = spec.members[i].type_descriptor;
    check("sized alias member keeps SIZE(1..200)",
          sized_def && sized_def->contained && (sized_def->constraints.flags & Constraints::SIZE_CONSTRAINED) &&
          sized_def->constraints.size_lower == 1 && sized_def->constraints.size_upper == 200);
    check("sized alias member decoded", d.viaSized.value() && d.viaSized.value()->id.value() == 5);
}

template<class T>
static std::string xer(const T& v, const ContainedOptions* opts = nullptr) {
    std::ostringstream os;
    XerEncodeStream s{os};
    s.set_contained(opts);
    XerCodec::instance().encode(s, T::asn_DEF, &v);
    return os.str();
}

template<class T>
static bool unxer(const std::string& text, T& v) {
    XerDecodeStream s{text};
    return XerCodec::instance().decode(s, T::asn_DEF, &v).has_value();
}

template<class T>
static std::string jer(const T& v, const ContainedOptions* opts = nullptr) {
    std::ostringstream os;
    JerEncodeStream s{os};
    s.set_contained(opts);
    JerCodec::instance().encode(s, T::asn_DEF, &v);
    return os.str();
}

template<class T>
static bool unjer(const std::string& text, T& v) {
    JerDecodeStream s{text};
    return JerCodec::instance().decode(s, T::asn_DEF, &v).has_value();
}

static void test_xer_jer() {
    printf("XER/JER\n");
    Holder h;
    check("BER decode for text tests", unber(ber(Holder::asn_DEF, make_holder(Kind::plain)), h));

    // Default (hex): the field is its raw bytes in hex; decoding the hex
    // decodes the inner value, as for BER.
    auto x = xer(h);
    check("XER default is hex", x.find("<viaConstraint>") != std::string::npos &&
                                x.find("<Inner>") == std::string::npos);
    Holder hx;
    check("XER hex decodes", unxer(x, hx) && hx.viaConstraint.value() &&
                             hx.viaConstraint.value()->id.value() == 1 && hx.viaConfig.value() &&
                             hx.viaConfig.value()->id.value() == 3);
    check("XER hex keeps the raw bytes", hx.viaConfig.size() == h.viaConfig.size());

    // Stream override: inline, hex suppressed (X.680 §22.4).
    ContainedOptions inl;
    inl.xer = ContainedText::Inline;
    inl.jer = ContainedText::Inline;
    auto xi = xer(h, &inl);
    check("XER inline writes the typed value", xi.find("<viaConstraint>\n") != std::string::npos &&
                                              xi.find("<Inner>") != std::string::npos &&
                                              xi.find("<!--") == std::string::npos);
    Holder hi;
    check("XER inline decodes", unxer(xi, hi) && hi.viaConstraint.value() &&
                                hi.viaConstraint.value()->id.value() == 1);
    check("XER inline: raw bytes are the inner value's BER",
          hi.viaConstraint.size() == h.viaConstraint.size() &&
          std::equal(hi.viaConstraint.bytes().begin(), hi.viaConstraint.bytes().end(), h.viaConstraint.bytes().begin()));
    check("XER inline: padding is not carried (raw differs)", hi.viaConfig.size() < h.viaConfig.size());

    auto ji = jer(h, &inl);
    check("JER inline writes {\"containing\": ...}", ji.find("\"viaConstraint\":{\"containing\":") != std::string::npos);
    Holder hj;
    check("JER inline decodes", unjer(ji, hj) && hj.viaConfig.value() && hj.viaConfig.value()->id.value() == 3);

    // Pick.inner is configured xer: inline, jer: inline_raw.
    Pick p;
    p.set_present(Pick::PR::inner);
    p.inner().set_value(make_inner(9));
    Pick pb;
    check("BER decode for Pick", unber(ber(Pick::asn_DEF, p), pb));
    auto px = xer(pb);
    check("configured XER inline", px.find("<Inner>") != std::string::npos);
    auto pj = jer(pb);
    check("configured JER inline_raw", pj.find("\"containing\":") != std::string::npos &&
                                       pj.find("\"raw\":\"") != std::string::npos);
    // Same text as the Rust runtime (tests/rust/containing); the C++ root
    // CHOICE wrapper adds an empty line before its closing tag.
    Pick pg;
    Inner gi = make_inner(9);
    gi.name = std::make_unique<Utf8String>("x");
    pg.set_present(Pick::PR::inner);
    pg.inner().set_value(std::move(gi));
    Pick pgd;
    check("BER decode for the golden Pick", unber(ber(Pick::asn_DEF, pg), pgd));
    check("golden XER inline", xer(pgd) == "<Pick>\n    <inner>\n        <Inner>\n            <id>9</id>\n"
                                            "            <name>x</name>\n        </Inner>\n    </inner>\n\n</Pick>\n");
    check("golden JER inline_raw", jer(pgd) == R"({"inner":{"containing":{"id":9,"name":"x"},"raw":"3006800109810178"}})");
    Pick pjd;
    check("JER inline_raw decodes, raw authoritative",
          unjer(pj, pjd) && pjd.inner().value() && pjd.inner().value()->id.value() == 9 &&
          pjd.inner().size() == pb.inner().size());
    // inline_raw keeps bytes that differ from the value's own encoding.
    std::string tampered = pj;
    auto pos = tampered.find("\"raw\":\"") + 7;
    tampered.insert(pos, "00");
    tampered.insert(tampered.find('"', pos + 2), "00");
    Pick pt;
    check("JER inline_raw: raw bytes kept as given",
          unjer(tampered, pt) && pt.inner().size() == pb.inner().size() + 2);
    ContainedOptions raw;
    raw.xer = ContainedText::InlineRaw;
    auto pxr = xer(pb, &raw);
    Pick pxd;
    check("XER inline_raw comment round-trips",
          pxr.find("<!-- raw: ") != std::string::npos && unxer(pxr, pxd) && pxd.inner().value() &&
          pxd.inner().size() == pb.inner().size());
}

int main() {
    test_ber_sequence();
    test_bad_inner();
    test_options();
    test_choice();
    test_recursion();
    test_per();
    test_xer_jer();
    printf("%s\n", failures ? "FAILED" : "all passed");
    return failures ? 1 : 0;
}
