// PER extension member test (issue #13).
//
// Exercises SEQUENCE and CHOICE extension members in UPER:
//   - Root-only encode/decode (ext flag = 0)
//   - Encode/decode with one extension member present
//   - Encode/decode with all extension members present
//   - CHOICE root alternative vs. extension alternative
//   - Skip: decode a stream containing more extension members than known
//   - Deep skip: extension member is itself a SEQUENCE (2 levels); old receiver
//     must skip the entire open-type payload and keep root members intact.
//
// Cross-validated against asn1c (converter-SeqWithExt -iuper) during development;
// encoding bytes were confirmed identical.
#include <cstdio>
#include <cstdlib>
#include <memory>
#include <span>
#include <vector>
#include <asn1cpp/asn1cpp.hpp>
#include <asn1cpp/codec/PerCodec.hpp>
#include "SeqWithExt.hpp"
#include "ChoiceWithExt.hpp"
#include "InnerSeq.hpp"
#include "SeqDeepExt.hpp"
#include "SeqDeepExtRootOnly.hpp"

using namespace asn1;

static int failures = 0;

static void check(const char* label, bool cond) {
    if (cond) printf("  \033[32mPASS\033[0m  %s\n", label);
    else      { printf("  \033[31mFAIL\033[0m  %s\n", label); ++failures; }
}

static std::vector<uint8_t> per_enc(const TypeDescriptor& def, const Asn1Object* obj) {
    std::vector<uint8_t> buf;
    PerEncodeStream s{buf};
    IEncodeStream& es = s;
    PerCodec::instance().encode(es, def, obj);
    s.flush();
    return buf;
}

static bool per_dec(std::span<const uint8_t> buf, const TypeDescriptor& def, Asn1Object* obj) {
    PerDecodeStream s{buf};
    IDecodeStream& ds = s;
    return PerCodec::instance().decode(ds, def, obj).has_value();
}

// ── SEQUENCE extension tests ──────────────────────────────────────────────────

static void test_seq_root_only() {
    SeqWithExt r{};
    r.id = Integer{42};
    r.flag = Boolean{true};

    auto enc = per_enc(SeqWithExt::asn_DEF, &r);
    check("seq root-only: encode non-empty", !enc.empty());

    SeqWithExt r2{};
    check("seq root-only: decode ok", per_dec(enc, SeqWithExt::asn_DEF, &r2));
    check("seq root-only: id==42", (int64_t)r2.id == 42);
    check("seq root-only: flag==true", r2.flag.value());
    check("seq root-only: note absent", r2.note == nullptr);
    check("seq root-only: extra absent", r2.extra == nullptr);
}

static void test_seq_one_ext() {
    SeqWithExt r{};
    r.id = Integer{7};
    r.flag = Boolean{false};
    r.note = std::make_unique<VisibleString>("hello");
    // extra not set

    auto enc = per_enc(SeqWithExt::asn_DEF, &r);
    check("seq one-ext: encode non-empty", !enc.empty());

    SeqWithExt r2{};
    bool ok = per_dec(enc, SeqWithExt::asn_DEF, &r2);
    check("seq one-ext: decode ok", ok);
    if (ok) {
        check("seq one-ext: id==7", (int64_t)r2.id == 7);
        check("seq one-ext: flag==false", !r2.flag.value());
        check("seq one-ext: note present", r2.note != nullptr);
        if (r2.note)
            check("seq one-ext: note==\"hello\"", r2.note->str() == "hello");
        check("seq one-ext: extra absent", r2.extra == nullptr);
    }
}

static void test_seq_both_ext() {
    SeqWithExt r{};
    r.id = Integer{99};
    r.flag = Boolean{true};
    r.note = std::make_unique<VisibleString>("world");
    r.extra = std::make_unique<Integer>(200);

    auto enc = per_enc(SeqWithExt::asn_DEF, &r);
    check("seq both-ext: encode non-empty", !enc.empty());

    SeqWithExt r2{};
    bool ok = per_dec(enc, SeqWithExt::asn_DEF, &r2);
    check("seq both-ext: decode ok", ok);
    if (ok) {
        check("seq both-ext: id==99",     (int64_t)r2.id == 99);
        check("seq both-ext: flag==true", r2.flag.value());
        check("seq both-ext: note present", r2.note != nullptr);
        if (r2.note)
            check("seq both-ext: note==\"world\"", r2.note->str() == "world");
        check("seq both-ext: extra present", r2.extra != nullptr);
        if (r2.extra)
            check("seq both-ext: extra==200", (int64_t)*r2.extra == 200);
    }
}

// ── CHOICE extension tests ────────────────────────────────────────────────────

static void test_choice_root() {
    ChoiceWithExt c{};
    c.set_present(ChoiceWithExt::PR::num);
    c.num() = Integer{77};

    auto enc = per_enc(ChoiceWithExt::asn_DEF, &c);
    check("choice root: encode non-empty", !enc.empty());

    ChoiceWithExt c2{};
    bool ok = per_dec(enc, ChoiceWithExt::asn_DEF, &c2);
    check("choice root: decode ok", ok);
    if (ok) {
        check("choice root: num selected", c2.present() == ChoiceWithExt::PR::num);
        if (c2.present() == ChoiceWithExt::PR::num)
            check("choice root: num==77", (int64_t)c2.num() == 77);
    }
}

static void test_choice_ext_alt() {
    ChoiceWithExt c{};
    c.set_present(ChoiceWithExt::PR::str);
    c.str() = VisibleString{"ext"};

    auto enc = per_enc(ChoiceWithExt::asn_DEF, &c);
    check("choice ext-alt: encode non-empty", !enc.empty());

    ChoiceWithExt c2{};
    bool ok = per_dec(enc, ChoiceWithExt::asn_DEF, &c2);
    check("choice ext-alt: decode ok", ok);
    if (ok) {
        check("choice ext-alt: str selected", c2.present() == ChoiceWithExt::PR::str);
        if (c2.present() == ChoiceWithExt::PR::str)
            check("choice ext-alt: str==\"ext\"", c2.str().str() == "ext");
    }
}

// ── Deep extension skip (forward compatibility) ───────────────────────────────
//
// Sender: SeqDeepExt — knows about extension member "detail" (an InnerSeq).
// Receiver: SeqDeepExtRootOnly — same root (id, name) + extension marker, but
//   zero known extension members.  The open-type payload for "detail" contains
//   a full PER-encoded InnerSeq (3 members), so the skip covers real nested data.
//
// After decoding: root fields id and name must be intact; no decode error.

static void test_deep_ext_skip() {
    // Sender encodes with a populated nested extension.
    SeqDeepExt sender{};
    sender.id = Integer{42};
    sender.name = VisibleString{"hello"};
    sender.detail = std::make_unique<InnerSeq>();
    sender.detail->a = Integer{10};
    sender.detail->b = Boolean{true};
    sender.detail->c = Integer{200};

    auto enc = per_enc(SeqDeepExt::asn_DEF, &sender);
    check("deep-skip: encode non-empty", !enc.empty());

    // Old receiver: same root layout, no knowledge of the extension.
    SeqDeepExtRootOnly receiver{};
    bool ok = per_dec(enc, SeqDeepExtRootOnly::asn_DEF, &receiver);
    check("deep-skip: decode ok (no error on unknown extension)", ok);
    if (ok) {
        check("deep-skip: id==42",     (int64_t)receiver.id == 42);
        check("deep-skip: name==hello", receiver.name.str() == "hello");
    }
}

// ── Round-trip consistency ────────────────────────────────────────────────────

static void test_roundtrip_idempotent() {
    // Encode twice from the same object, bytes must be identical.
    SeqWithExt r{};
    r.id = Integer{13};
    r.flag = Boolean{false};
    r.note = std::make_unique<VisibleString>("abc");

    auto enc1 = per_enc(SeqWithExt::asn_DEF, &r);
    auto enc2 = per_enc(SeqWithExt::asn_DEF, &r);
    check("idempotent: two encodes equal", enc1 == enc2);
}

// ── main ─────────────────────────────────────────────────────────────────────

int main() {
    printf("\n── PER extension members (issue #13) ─────────────────────────────────\n");

    test_seq_root_only();
    test_seq_one_ext();
    test_seq_both_ext();
    test_choice_root();
    test_choice_ext_alt();
    test_deep_ext_skip();
    test_roundtrip_idempotent();

    printf("\n  %d failure(s).\n", failures);
    if (failures) return 1;
    printf("  All tests passed.\n");
    return 0;
}
