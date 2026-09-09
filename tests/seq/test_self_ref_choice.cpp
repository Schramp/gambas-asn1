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

    printf("\n%s  %d failure(s)\n", failures ? "\033[31mFAIL\033[0m" : "\033[32mPASS\033[0m", failures);
    return failures ? 1 : 0;
}
