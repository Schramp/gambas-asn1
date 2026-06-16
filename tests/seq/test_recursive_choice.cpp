// BER/XER round-trip tests for indirect recursive CHOICE (Expr / ExprSeq).
// Expr ::= CHOICE { num INTEGER, compound ExprSeq }
// ExprSeq ::= SEQUENCE { left Expr OPTIONAL, right Expr OPTIONAL }
// The cycle is broken via unique_ptr on the OPTIONAL ExprSeq members.
#include <cstdio>
#include <vector>
#include <string>
#include <sstream>
#include <span>
#include <memory>
#include <asn1cpp/asn1cpp.hpp>
#include "Expr.hpp"
#include "ExprSeq.hpp"

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

// Helper: make a leaf Expr (num alternative)
static Expr make_num(int64_t v) {
    Expr e;
    e.set_present(Expr::PR::num);
    e.num() = Integer{v};
    return e;
}

// Helper: make a compound Expr with optional left/right leaves
static Expr make_compound(int64_t lv, int64_t rv) {
    Expr e;
    e.set_present(Expr::PR::compound);
    e.compound().left  = std::make_unique<Expr>(make_num(lv));
    e.compound().right = std::make_unique<Expr>(make_num(rv));
    return e;
}

int main() {
    // --- Leaf node: Expr = num(42) ---
    printf("Expr — leaf (num)\n");
    {
        Expr enc = make_num(42);

        auto bytes = ber_enc(Expr::asn_DEF, &enc);
        check("Expr leaf BER encode non-empty", !bytes.empty());

        Expr dec{};
        check("Expr leaf BER decode ok", ber_dec(bytes, Expr::asn_DEF, &dec));
        check("Expr leaf alt num",       dec.present() == Expr::PR::num);
        check("Expr leaf value",         dec.present() == Expr::PR::num &&
                                         (int64_t)dec.num() == 42);

        auto bytes2 = ber_enc(Expr::asn_DEF, &dec);
        check("Expr leaf BER idempotent", bytes == bytes2);
    }

    // --- XER leaf ---
    printf("Expr — XER leaf (num)\n");
    {
        Expr enc = make_num(7);

        std::string xer = xer_enc(Expr::asn_DEF, &enc);
        check("Expr leaf XER encode non-empty", !xer.empty());

        Expr dec{};
        check("Expr leaf XER decode ok",  xer_dec(xer, Expr::asn_DEF, &dec));
        check("Expr leaf XER alt num",    dec.present() == Expr::PR::num);
        check("Expr leaf XER value",      dec.present() == Expr::PR::num &&
                                          (int64_t)dec.num() == 7);
    }

    // --- Depth-1 compound: compound { left=num(1), right=num(2) } ---
    printf("Expr — compound depth 1\n");
    {
        Expr enc = make_compound(1, 2);

        auto bytes = ber_enc(Expr::asn_DEF, &enc);
        check("Expr compound BER encode non-empty", !bytes.empty());

        Expr dec{};
        check("Expr compound BER decode ok",     ber_dec(bytes, Expr::asn_DEF, &dec));
        check("Expr compound alt",               dec.present() == Expr::PR::compound);
        check("Expr compound left present",      !!dec.compound().left);
        check("Expr compound left alt num",      dec.compound().left &&
                                                 dec.compound().left->present() == Expr::PR::num);
        check("Expr compound left value",        dec.compound().left &&
                                                 (int64_t)dec.compound().left->num() == 1);
        check("Expr compound right present",     !!dec.compound().right);
        check("Expr compound right value",       dec.compound().right &&
                                                 (int64_t)dec.compound().right->num() == 2);

        auto bytes2 = ber_enc(Expr::asn_DEF, &dec);
        check("Expr compound BER idempotent",    bytes == bytes2);
    }

    // --- XER compound ---
    printf("Expr — XER compound depth 1\n");
    {
        Expr enc = make_compound(3, 4);

        std::string xer = xer_enc(Expr::asn_DEF, &enc);
        check("Expr compound XER encode non-empty", !xer.empty());

        Expr dec{};
        check("Expr compound XER decode ok",     xer_dec(xer, Expr::asn_DEF, &dec));
        check("Expr compound XER alt",           dec.present() == Expr::PR::compound);
        check("Expr compound XER left present",  !!dec.compound().left);
        check("Expr compound XER left value",    dec.compound().left &&
                                                 (int64_t)dec.compound().left->num() == 3);
        check("Expr compound XER right present", !!dec.compound().right);
        check("Expr compound XER right value",   dec.compound().right &&
                                                 (int64_t)dec.compound().right->num() == 4);
    }

    // --- Depth-2 compound: compound { left=compound{left=num(1),right=num(2)}, right=num(3) } ---
    printf("Expr — compound depth 2\n");
    {
        Expr enc;
        enc.set_present(Expr::PR::compound);
        enc.compound().left  = std::make_unique<Expr>(make_compound(1, 2));
        enc.compound().right = std::make_unique<Expr>(make_num(3));

        auto bytes = ber_enc(Expr::asn_DEF, &enc);
        check("Expr depth-2 BER encode non-empty", !bytes.empty());

        Expr dec{};
        check("Expr depth-2 BER decode ok",          ber_dec(bytes, Expr::asn_DEF, &dec));
        check("Expr depth-2 alt compound",           dec.present() == Expr::PR::compound);
        check("Expr depth-2 left present",           !!dec.compound().left);
        check("Expr depth-2 left alt compound",      dec.compound().left &&
                                                     dec.compound().left->present() == Expr::PR::compound);
        check("Expr depth-2 left.left present",      dec.compound().left &&
                                                     !!dec.compound().left->compound().left);
        check("Expr depth-2 left.left value",        dec.compound().left &&
                                                     dec.compound().left->compound().left &&
                                                     (int64_t)dec.compound().left->compound().left->num() == 1);
        check("Expr depth-2 left.right present",     dec.compound().left &&
                                                     !!dec.compound().left->compound().right);
        check("Expr depth-2 left.right value",       dec.compound().left &&
                                                     dec.compound().left->compound().right &&
                                                     (int64_t)dec.compound().left->compound().right->num() == 2);
        check("Expr depth-2 right alt num",          dec.compound().right &&
                                                     dec.compound().right->present() == Expr::PR::num);
        check("Expr depth-2 right value",            dec.compound().right &&
                                                     (int64_t)dec.compound().right->num() == 3);

        auto bytes2 = ber_enc(Expr::asn_DEF, &dec);
        check("Expr depth-2 BER idempotent",         bytes == bytes2);
    }

    // --- Empty compound: both left and right absent ---
    printf("Expr — empty compound\n");
    {
        Expr enc;
        enc.set_present(Expr::PR::compound);
        // leave left and right as nullptr

        auto bytes = ber_enc(Expr::asn_DEF, &enc);
        check("Expr empty compound BER encode non-empty", !bytes.empty());

        Expr dec{};
        check("Expr empty compound BER decode ok",  ber_dec(bytes, Expr::asn_DEF, &dec));
        check("Expr empty compound alt",            dec.present() == Expr::PR::compound);
        check("Expr empty compound left absent",    !dec.compound().left);
        check("Expr empty compound right absent",   !dec.compound().right);
    }

    printf("\n%s  %d failure(s)\n", failures ? "\033[31mFAIL\033[0m" : "\033[32mPASS\033[0m", failures);
    return failures ? 1 : 0;
}
