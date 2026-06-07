// Deep-copy tests for SEQUENCE-with-optionals and CHOICE types.
// Uses existing schemas: seq_opt_test.asn1 (Rec5) and choice_test.asn1 (Alt4, HasAlt4).
#include <cstdio>
#include <vector>
#include <span>
#include <asn1cpp/asn1cpp.hpp>
#include <asn1cpp/codec/DeepCopy.hpp>
#include "Rec5.hpp"
#include "Alt4.hpp"
#include "HasAlt4.hpp"

using namespace asn1;
static int failures = 0;

static void check(const char* name, bool cond) {
    if (cond) printf("  \033[32mPASS\033[0m  %s\n", name);
    else     { printf("  \033[31mFAIL\033[0m  %s\n", name); ++failures; }
}

static std::vector<uint8_t> ber_enc(const Rec5& v) {
    std::vector<uint8_t> buf; BerWriter w{buf};
    BerEncodeStream s{w}; BerCodec::instance().encode(s, Rec5::asn_DEF, &v); return buf;
}
static std::vector<uint8_t> ber_enc(const HasAlt4& v) {
    std::vector<uint8_t> buf; BerWriter w{buf};
    BerEncodeStream s{w}; BerCodec::instance().encode(s, HasAlt4::asn_DEF, &v); return buf;
}

int main() {
    printf("=== deep_copy: SEQUENCE with optionals ===\n");
    {
        // Build a source with both optionals set.
        Rec5 src{};
        src.id.set(42);
        src.note = std::make_unique<MyStr>(); src.note->str() = "hello";
        src.flag.set(true);
        src.extra = std::make_unique<MyByte>(); src.extra->set(7);

        // Copy-construct.
        Rec5 copy1(src);
        check("copy-ctor: id",    static_cast<int64_t>(copy1.id)   == 42);
        check("copy-ctor: note",  copy1.note && copy1.note->str()   == "hello");
        check("copy-ctor: flag",  static_cast<bool>(copy1.flag)     == true);
        check("copy-ctor: extra", copy1.extra && static_cast<int64_t>(*copy1.extra) == 7);
        check("copy-ctor: independent note",
              copy1.note.get() != src.note.get());
        check("copy-ctor: BER match", ber_enc(src) == ber_enc(copy1));

        // Mutate copy — source must be unaffected.
        copy1.note->str() = "world";
        check("copy-ctor: mutation isolated", src.note->str() == "hello");

        // Copy-assign into a live object that has optionals present.
        Rec5 copy2{};
        copy2.id.set(99);
        copy2.note = std::make_unique<MyStr>(); copy2.note->str() = "old";
        copy2 = src;
        check("copy-assign: id",    static_cast<int64_t>(copy2.id)   == 42);
        check("copy-assign: note",  copy2.note && copy2.note->str()   == "hello");
        check("copy-assign: flag",  static_cast<bool>(copy2.flag)     == true);
        check("copy-assign: BER match", ber_enc(src) == ber_enc(copy2));

        // Source with note absent.
        Rec5 sparse{};
        sparse.id.set(1);
        sparse.flag.set(false);
        Rec5 copy3(sparse);
        check("copy-ctor sparse: note absent", !copy3.note);
        check("copy-ctor sparse: extra absent", !copy3.extra);

        // Assign sparse over copy that had note set.
        copy2 = sparse;
        check("copy-assign clears note", !copy2.note);
        check("copy-assign clears extra", !copy2.extra);
    }

    printf("\n=== deep_copy: CHOICE ===\n");
    {
        // Build a CHOICE set to the 'str' arm.
        Alt4 src{};
        src.set_present(Alt4::PR::str);
        src.str().str() = "test";

        // Copy-construct.
        Alt4 copy1(src);
        check("choice copy-ctor: present", copy1.present() == Alt4::PR::str);
        check("choice copy-ctor: value",   copy1.str().str() == "test");
        check("choice copy-ctor: independent",
              &copy1.str() != &src.str());

        // Mutate — source unaffected.
        copy1.str().str() = "mutated";
        check("choice copy-ctor: mutation isolated", src.str().str() == "test");

        // Copy-assign to a CHOICE with a different active arm.
        Alt4 copy2{};
        copy2.set_present(Alt4::PR::num); copy2.num().set(77);
        copy2 = src;
        check("choice copy-assign: present", copy2.present() == Alt4::PR::str);
        check("choice copy-assign: value",   copy2.str().str() == "test");

        // Copy NOTHING.
        Alt4 nothing{};
        Alt4 copy3(nothing);
        check("choice copy-ctor NOTHING: present", copy3.present() == Alt4::PR::NOTHING);

        // Assign NOTHING over an armed CHOICE.
        copy2 = nothing;
        check("choice copy-assign NOTHING: present", copy2.present() == Alt4::PR::NOTHING);
    }

    printf("\n=== deep_copy: SEQUENCE containing CHOICE ===\n");
    {
        HasAlt4 src{};
        src.val.set_present(Alt4::PR::flag); src.val.flag().set(true);

        HasAlt4 copy1(src);
        check("nested copy-ctor: present", copy1.val.present() == Alt4::PR::flag);
        check("nested copy-ctor: BER match", ber_enc(src) == ber_enc(copy1));

        // direct deep_copy free function
        HasAlt4 copy2{};
        deep_copy(HasAlt4::asn_DEF, &copy2, &src);
        check("deep_copy free fn: present", copy2.val.present() == Alt4::PR::flag);
        check("deep_copy free fn: BER match", ber_enc(src) == ber_enc(copy2));
    }

    printf("\n%s (%d failures)\n", failures ? "FAIL" : "PASS", failures);
    return failures ? 1 : 0;
}
