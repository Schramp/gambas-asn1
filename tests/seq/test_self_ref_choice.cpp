// BER/XER round-trip + deep-copy tests for direct recursive CHOICE.
// RecChoice ::= CHOICE { a INTEGER, b INTEGER, c RecChoice }
// Unlike test_recursive_choice.cpp's Expr/ExprSeq (indirect recursion broken
// by an OPTIONAL SEQUENCE member's unique_ptr), alternative `c` is directly
// RecChoice itself, with no OPTIONAL to hang a unique_ptr off of. The cycle
// is broken by boxing that one alternative's val_storage_ slot as
// std::unique_ptr<RecChoice> instead of RecChoice inline (see
// CppBackend::emit_choice_declaration's val_storage_ comment).
#include <cstdio>
#include <vector>
#include <string>
#include <sstream>
#include <span>
#include <asn1cpp/asn1cpp.hpp>
#include <asn1cpp/codec/DecodeDepth.hpp>
#include <asn1cpp/codec/JerCodec.hpp>
#include <asn1cpp/codec/PerCodec.hpp>
#include "RecChoice.hpp"

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


// A RecChoice nested `levels` deep: c(c(...c(a(5))...)). Built directly
// rather than encoded, so a depth no encoder would survive can be tested.
static std::vector<uint8_t> deep_ber(int levels) {
    std::vector<uint8_t> v{0x80, 0x01, 0x05};
    for (int i = 0; i < levels; ++i) {
        std::vector<uint8_t> len;
        std::size_t n = v.size();
        if (n < 128) len.push_back(static_cast<uint8_t>(n));
        else {
            std::vector<uint8_t> b;
            for (; n; n >>= 8) b.insert(b.begin(), static_cast<uint8_t>(n));
            len.push_back(static_cast<uint8_t>(0x80 | b.size()));
            len.insert(len.end(), b.begin(), b.end());
        }
        std::vector<uint8_t> w{0xA2};
        w.insert(w.end(), len.begin(), len.end());
        w.insert(w.end(), v.begin(), v.end());
        v.swap(w);
    }
    return v;
}

static std::string deep_xer(int levels) {
    std::string s = "<RecChoice>";
    for (int i = 0; i < levels; ++i) s += "<c>";
    s += "<a>5</a>";
    for (int i = 0; i < levels; ++i) s += "</c>";
    return s + "</RecChoice>";
}

static std::string deep_jer(int levels) {
    std::string s;
    for (int i = 0; i < levels; ++i) s += "{\"c\":";
    s += "{\"a\":5}";
    return s + std::string(levels, '}');
}

// UPER: CHOICE index '10' (c) per level, then '00' (a), then INTEGER 5
// as an unconstrained whole number (length 1, one octet).
static std::vector<uint8_t> deep_per(int levels) {
    std::vector<bool> bits;
    for (int i = 0; i < levels; ++i) { bits.push_back(1); bits.push_back(0); }
    bits.push_back(0); bits.push_back(0);
    for (uint8_t b : {uint8_t{1}, uint8_t{5}})
        for (int k = 7; k >= 0; --k) bits.push_back((b >> k) & 1);
    std::vector<uint8_t> out((bits.size() + 7) / 8, 0);
    for (std::size_t i = 0; i < bits.size(); ++i)
        if (bits[i]) out[i / 8] |= static_cast<uint8_t>(0x80 >> (i % 8));
    return out;
}

static bool jer_dec(const std::string& json, const TypeDescriptor& def, Asn1Object* p) {
    JerDecodeStream s{json};
    return JerCodec::instance().decode(s, def, p).has_value();
}

static bool per_dec(std::span<const uint8_t> bytes, const TypeDescriptor& def, Asn1Object* p) {
    PerDecodeStream s{bytes};
    IDecodeStream& ds = s;
    return PerCodec::instance().decode(ds, def, p).has_value();
}

static RecChoice make_leaf(int64_t v) {
    RecChoice r;
    r.set_present(RecChoice::PR::a);
    r.a() = Integer{v};
    return r;
}

int main() {
    // --- Leaf: RecChoice = a(42) — no recursion exercised, sanity baseline. ---
    printf("RecChoice — leaf (a)\n");
    {
        RecChoice enc = make_leaf(42);

        auto bytes = ber_enc(RecChoice::asn_DEF, &enc);
        check("leaf BER encode non-empty", !bytes.empty());

        RecChoice dec{};
        check("leaf BER decode ok", ber_dec(bytes, RecChoice::asn_DEF, &dec));
        check("leaf alt a",         dec.present() == RecChoice::PR::a);
        check("leaf value",         dec.present() == RecChoice::PR::a &&
                                    (int64_t)dec.a() == 42);

        auto bytes2 = ber_enc(RecChoice::asn_DEF, &dec);
        check("leaf BER idempotent", bytes == bytes2);
    }

    // --- Depth-1 recursion: RecChoice = c(a(7)) — exercises the boxed alt. ---
    printf("RecChoice — depth 1 (c -> a)\n");
    {
        RecChoice enc;
        enc.set_present(RecChoice::PR::c);
        enc.c().set_present(RecChoice::PR::a);
        enc.c().a() = Integer{7};

        auto bytes = ber_enc(RecChoice::asn_DEF, &enc);
        check("depth-1 BER encode non-empty", !bytes.empty());

        RecChoice dec{};
        check("depth-1 BER decode ok",     ber_dec(bytes, RecChoice::asn_DEF, &dec));
        check("depth-1 alt c",             dec.present() == RecChoice::PR::c);
        check("depth-1 inner alt a",       dec.present() == RecChoice::PR::c &&
                                           dec.c().present() == RecChoice::PR::a);
        check("depth-1 inner value",       dec.present() == RecChoice::PR::c &&
                                           dec.c().present() == RecChoice::PR::a &&
                                           (int64_t)dec.c().a() == 7);

        auto bytes2 = ber_enc(RecChoice::asn_DEF, &dec);
        check("depth-1 BER idempotent",    bytes == bytes2);
    }

    // --- Depth-3 recursion: RecChoice = c(c(c(b(99)))). ---
    printf("RecChoice — depth 3 (c -> c -> c -> b)\n");
    {
        RecChoice enc;
        enc.set_present(RecChoice::PR::c);
        enc.c().set_present(RecChoice::PR::c);
        enc.c().c().set_present(RecChoice::PR::c);
        enc.c().c().c().set_present(RecChoice::PR::b);
        enc.c().c().c().b() = Integer{99};

        auto bytes = ber_enc(RecChoice::asn_DEF, &enc);
        check("depth-3 BER encode non-empty", !bytes.empty());

        RecChoice dec{};
        check("depth-3 BER decode ok", ber_dec(bytes, RecChoice::asn_DEF, &dec));
        bool path_ok = dec.present() == RecChoice::PR::c &&
                        dec.c().present() == RecChoice::PR::c &&
                        dec.c().c().present() == RecChoice::PR::c &&
                        dec.c().c().c().present() == RecChoice::PR::b;
        check("depth-3 path", path_ok);
        check("depth-3 value", path_ok && (int64_t)dec.c().c().c().b() == 99);

        auto bytes2 = ber_enc(RecChoice::asn_DEF, &dec);
        check("depth-3 BER idempotent", bytes == bytes2);
    }

    // --- XER round-trip through the boxed alternative. ---
    printf("RecChoice — XER depth 1 (c -> b)\n");
    {
        RecChoice enc;
        enc.set_present(RecChoice::PR::c);
        enc.c().set_present(RecChoice::PR::b);
        enc.c().b() = Integer{-13};

        std::string xer = xer_enc(RecChoice::asn_DEF, &enc);
        check("XER encode non-empty", !xer.empty());

        RecChoice dec{};
        check("XER decode ok",   xer_dec(xer, RecChoice::asn_DEF, &dec));
        check("XER alt c",       dec.present() == RecChoice::PR::c);
        check("XER inner alt b", dec.present() == RecChoice::PR::c &&
                                 dec.c().present() == RecChoice::PR::b);
        check("XER inner value", dec.present() == RecChoice::PR::c &&
                                 dec.c().present() == RecChoice::PR::b &&
                                 (int64_t)dec.c().b() == -13);
    }

    // --- Deep copy (copy ctor / operator=) through the boxed alternative. ---
    printf("RecChoice — deep copy through boxed alt\n");
    {
        RecChoice enc;
        enc.set_present(RecChoice::PR::c);
        enc.c().set_present(RecChoice::PR::a);
        enc.c().a() = Integer{123};

        RecChoice copy_ctor = enc; // copy ctor
        check("copy-ctor alt c",       copy_ctor.present() == RecChoice::PR::c);
        check("copy-ctor inner alt a", copy_ctor.present() == RecChoice::PR::c &&
                                       copy_ctor.c().present() == RecChoice::PR::a);
        check("copy-ctor inner value", copy_ctor.present() == RecChoice::PR::c &&
                                       copy_ctor.c().present() == RecChoice::PR::a &&
                                       (int64_t)copy_ctor.c().a() == 123);

        RecChoice assigned;
        assigned = enc; // copy assignment
        check("copy-assign alt c",       assigned.present() == RecChoice::PR::c);
        check("copy-assign inner value", assigned.present() == RecChoice::PR::c &&
                                         assigned.c().present() == RecChoice::PR::a &&
                                         (int64_t)assigned.c().a() == 123);

        // Independence: mutating the copy must not affect the original.
        copy_ctor.c().a() = Integer{999};
        check("copy independent of original",
              (int64_t)enc.c().a() == 123 && (int64_t)copy_ctor.c().a() == 999);
    }

    // --- Decode nesting limit: a forged deeply nested input is rejected
    // with an error in every codec instead of overflowing the stack. ---
    printf("\nRecChoice — decode nesting limit (kMaxDecodeDepth = %d)\n", kMaxDecodeDepth);
    for (int levels : {kMaxDecodeDepth - 2, 100000}) {
        bool within = levels < kMaxDecodeDepth;
        char label[128];
        auto expect = [&](const char* codec, bool ok) {
            std::snprintf(label, sizeof(label), "%s decode of %d levels %s", codec, levels,
                          within ? "succeeds" : "is an error");
            check(label, ok == within);
        };
        { RecChoice d; auto b = deep_ber(levels); expect("BER", ber_dec(b, RecChoice::asn_DEF, &d)); }
        { RecChoice d; expect("XER", xer_dec(deep_xer(levels), RecChoice::asn_DEF, &d)); }
        { RecChoice d; expect("JER", jer_dec(deep_jer(levels), RecChoice::asn_DEF, &d)); }
        { RecChoice d; auto b = deep_per(levels); expect("PER", per_dec(b, RecChoice::asn_DEF, &d)); }
    }

    printf("\n%s  %d failure(s)\n", failures ? "\033[31mFAIL\033[0m" : "\033[32mPASS\033[0m", failures);
    return failures ? 1 : 0;
}
