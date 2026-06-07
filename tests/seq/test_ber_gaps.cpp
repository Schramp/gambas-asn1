// Covers BerCodec / XerCodec paths not reached by the ETSI xval sweep:
//   - DEFAULT suppress on encode / fill on decode
//   - ber_tags[] fast-path for optional untagged CHOICE in SEQUENCE
//   - Untagged CHOICE alternative decode (no context-tag peel)
//   - CHOICE extension-skip (unknown tag, ext_at >= 0)
//   - ENUMERATED XER unknown-value decode reject
//   - ENUMERATED XER non-name integer fallback encode
//   - SEQUENCE OF XER empty-element encode
#include <cstdio>
#include <vector>
#include <string>
#include <sstream>
#include <span>
#include <asn1cpp/asn1cpp.hpp>
#include "HasDefault.hpp"
#include "HasOptChoice.hpp"
#include "OuterChoice.hpp"
#include "LeafChoice.hpp"
#include "HasExtChoice.hpp"
#include "ExtChoice.hpp"
#include "HasEnum.hpp"
#include "SimpleEnum.hpp"
#include "HasSeqOf.hpp"

using namespace asn1;

static int failures = 0;
static void check(const char* label, bool cond) {
    if (cond) printf("  \033[32mPASS\033[0m  %s\n", label);
    else      { printf("  \033[31mFAIL\033[0m  %s\n", label); ++failures; }
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

// ── DEFAULT ──────────────────────────────────────────────────────────────────
static void test_default() {
    printf("\n── DEFAULT suppress / fill ──────────────────────────────────────\n");

    // All-default values — both members should be suppressed → SEQUENCE body empty.
    HasDefault hd{};
    hd.flag  = std::make_unique<Boolean>(false);
    hd.value = std::make_unique<Integer>(0LL);
    auto enc_default = ber_enc(HasDefault::asn_DEF, &hd);
    check("DEFAULT values suppressed (30 00)",
          enc_default == std::vector<uint8_t>{0x30, 0x00});

    // Decode empty SEQUENCE — set_default must fill both members.
    HasDefault hd2{};
    std::vector<uint8_t> empty_seq{0x30, 0x00};
    bool ok = ber_dec(empty_seq, HasDefault::asn_DEF, &hd2);
    check("Empty SEQUENCE decodes",       ok);
    check("DEFAULT flag filled as FALSE", hd2.flag  && *hd2.flag  == Boolean{false});
    check("DEFAULT value filled as 0",   hd2.value && *hd2.value == Integer{0LL});

    // Non-default values must appear in BER.
    HasDefault hd3{};
    hd3.flag  = std::make_unique<Boolean>(true);
    hd3.value = std::make_unique<Integer>(42LL);
    auto enc_nond = ber_enc(HasDefault::asn_DEF, &hd3);
    check("Non-default values encoded (size > 2)", enc_nond.size() > 2);

    HasDefault hd4{};
    bool ok2 = ber_dec(enc_nond, HasDefault::asn_DEF, &hd4);
    check("Non-default round-trip ok",        ok2);
    check("Non-default flag round-trips",     hd4.flag  && *hd4.flag  == Boolean{true});
    check("Non-default value round-trips",    hd4.value && *hd4.value == Integer{42LL});
}

// ── ber_tags fast-path + untagged CHOICE alt ─────────────────────────────────
static void test_untagged_choice() {
    printf("\n── ber_tags fast-path + untagged CHOICE decode ──────────────────\n");

    // HasOptChoice: pick = OuterChoice::inner, inner = LeafChoice::anInt(5).
    HasOptChoice h{};
    h.name = Utf8String{"hi"};
    h.pick = std::make_unique<OuterChoice>();
    h.pick->set_present(OuterChoice::PR::inner);
    h.pick->inner().set_present(LeafChoice::PR::anInt);
    h.pick->inner().anInt()   = Integer{5};

    auto enc = ber_enc(HasOptChoice::asn_DEF, &h);
    check("HasOptChoice with inner anInt encodes", !enc.empty());

    // Decode — ber_tags fast-path detects pick present (INTEGER tag matches);
    //          untagged CHOICE alt decode path (no context-tag peel).
    HasOptChoice h2{};
    bool ok = ber_dec(enc, HasOptChoice::asn_DEF, &h2);
    check("HasOptChoice with inner anInt decodes", ok);
    check("pick present after decode", h2.pick != nullptr);
    check("OuterChoice::inner selected",
          h2.pick && h2.pick->present() == OuterChoice::PR::inner);
    check("LeafChoice::anInt correct",
          h2.pick && h2.pick->inner().present() == LeafChoice::PR::anInt &&
          h2.pick->inner().anInt() == Integer{5});

    // pick absent — ber_tags fast-path decides NOT present.
    HasOptChoice h3{};
    h3.name = Utf8String{"no pick"};
    auto enc3 = ber_enc(HasOptChoice::asn_DEF, &h3);
    check("HasOptChoice without pick encodes", !enc3.empty());

    HasOptChoice h4{};
    bool ok3 = ber_dec(enc3, HasOptChoice::asn_DEF, &h4);
    check("HasOptChoice without pick decodes", ok3);
    check("pick absent after decode", h4.pick == nullptr);

    // OuterChoice::aFlag (BOOLEAN) — different ber_tags entry.
    HasOptChoice h5{};
    h5.name = Utf8String{"flag"};
    h5.pick = std::make_unique<OuterChoice>();
    h5.pick->set_present(OuterChoice::PR::aFlag);
    h5.pick->aFlag()       = Boolean{true};
    auto enc5 = ber_enc(HasOptChoice::asn_DEF, &h5);

    HasOptChoice h6{};
    bool ok5 = ber_dec(enc5, HasOptChoice::asn_DEF, &h6);
    check("HasOptChoice with aFlag decodes", ok5);
    check("aFlag value correct",
          h6.pick && h6.pick->present() == OuterChoice::PR::aFlag &&
          h6.pick->aFlag() == Boolean{true});

    // LeafChoice::aString path through ber_tags.
    HasOptChoice h7{};
    h7.name = Utf8String{"str"};
    h7.pick = std::make_unique<OuterChoice>();
    h7.pick->set_present(OuterChoice::PR::inner);
    h7.pick->inner().set_present(LeafChoice::PR::aString);
    h7.pick->inner().aString()  = Utf8String{"hello"};
    auto enc7 = ber_enc(HasOptChoice::asn_DEF, &h7);

    HasOptChoice h8{};
    bool ok7 = ber_dec(enc7, HasOptChoice::asn_DEF, &h8);
    check("LeafChoice::aString round-trips", ok7 &&
          h8.pick && h8.pick->present() == OuterChoice::PR::inner &&
          h8.pick->inner().present() == LeafChoice::PR::aString &&
          h8.pick->inner().aString() == Utf8String{"hello"});
}

// ── CHOICE extension-skip ─────────────────────────────────────────────────────
static void test_choice_ext_skip() {
    printf("\n── CHOICE extension-skip ────────────────────────────────────────\n");

    // ExtChoice expects INTEGER ([UNIVERSAL 2]), has ext_at >= 0.
    // Feed UTF8String ([UNIVERSAL 12] = 0x0c) — should be skipped as unknown extension.
    //   30 05        HasExtChoice SEQUENCE, 5 bytes
    //   0c 03 61 62 63   UTF8String "abc"
    std::vector<uint8_t> buf{0x30, 0x05, 0x0c, 0x03, 0x61, 0x62, 0x63};
    HasExtChoice h{};
    bool ok = ber_dec(buf, HasExtChoice::asn_DEF, &h);
    check("CHOICE extension-skip: decode succeeds", ok);
    check("CHOICE extension-skip: val not set",
          h.val.present() == ExtChoice::PR::NOTHING);
}

// ── XerCodec gap paths ────────────────────────────────────────────────────────
static void test_xer_gaps() {
    printf("\n── XerCodec gap paths ───────────────────────────────────────────\n");

    // Empty SEQUENCE OF → <HasSeqOf><items></items></HasSeqOf>
    {
        HasSeqOf hs{};
        auto xer = xer_enc(HasSeqOf::asn_DEF, &hs);
        check("Empty SEQUENCE OF XER encodes",
              xer.find("<items></items>") != std::string::npos);
    }

    // ENUMERATED XER normal round-trip.
    {
        HasEnum he{};
        he.kind = SimpleEnum::beta;
        auto xer = xer_enc(HasEnum::asn_DEF, &he);
        check("ENUMERATED XER encodes <beta/>", xer.find("<beta/>") != std::string::npos);
        HasEnum he2{};
        bool ok = xer_dec(xer, HasEnum::asn_DEF, &he2);
        check("ENUMERATED XER decodes", ok && he2.kind == SimpleEnum::beta);
    }

    // ENUMERATED XER encode with value not in name table → integer fallback (line 454).
    {
        HasEnum he{};
        *reinterpret_cast<long*>(&he.kind) = 99L;
        auto xer = xer_enc(HasEnum::asn_DEF, &he);
        check("ENUMERATED XER out-of-range → integer fallback",
              xer.find(">99<") != std::string::npos);
    }

    // ENUMERATED XER decode with unknown value name → must fail.
    {
        HasEnum he{};
        bool ok = xer_dec("<HasEnum><kind><unknown/></kind></HasEnum>",
                          HasEnum::asn_DEF, &he);
        check("ENUMERATED XER unknown value rejected", !ok);
    }
}

int main() {
    test_default();
    test_untagged_choice();
    test_choice_ext_skip();
    test_xer_gaps();

    printf("\n");
    if (failures) { printf("  %d test(s) FAILED\n", failures); return 1; }
    printf("  All tests passed.\n");
    return 0;
}
