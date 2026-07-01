// Unit tests for Asn1Optional<T> — layout, invariants, no-conflict with present()
#include <cstddef>
#include <cstdio>
#include <cstdlib>
#include <asn1cpp/Asn1Optional.hpp>
#include <asn1cpp/types/Integer.hpp>
#include <asn1cpp/types/Strings.hpp>

using namespace asn1;

static int failures = 0;

static void check(const char* name, bool cond, const char* detail = "") {
    if (cond) {
        printf("  \033[32mPASS\033[0m  %s\n", name);
    } else {
        printf("  \033[31mFAIL\033[0m  %s%s%s\n", name, *detail ? ": " : "", detail);
        ++failures;
    }
}

// ── Asn1OptionalBase at offset 0 ────────────────────────────────────────────

template<typename T>
static void test_layout(const char* tname) {
    Asn1Optional<T> opt;

    // Asn1OptionalBase is first base — same address as derived
    auto* base = static_cast<Asn1OptionalBase*>(&opt);
    check(tname,
          reinterpret_cast<void*>(base) == reinterpret_cast<void*>(&opt),
          "Asn1OptionalBase not at offset 0");
}

// ── value_ptr points to T sub-object ────────────────────────────────────────

template<typename T>
static void test_value_ptr(const char* tname) {
    Asn1Optional<T> opt;
    auto* expected = static_cast<Asn1Object*>(static_cast<T*>(&opt));
    char buf[128];
    snprintf(buf, sizeof(buf), "value_ptr=%p expected=%p",
             static_cast<void*>(opt.value_ptr),
             static_cast<void*>(expected));
    check(tname, opt.value_ptr == expected, buf);
}

// ── desc == &T::asn_DEF ─────────────────────────────────────────────────────

template<typename T>
static void test_desc(const char* tname) {
    Asn1Optional<T> opt;
    check(tname, opt.desc == &T::asn_DEF, "desc mismatch");
}

// ── found == false after default construction ────────────────────────────────

template<typename T>
static void test_default_found(const char* tname) {
    Asn1Optional<T> opt;
    check(tname, !opt.found, "found should be false after construction");
}

// ── static_cast<T&> accessible ──────────────────────────────────────────────

static void test_cast_integer() {
    Asn1Optional<Integer> opt;
    static_cast<Integer&>(opt) = Integer{42};
    check("cast_integer", static_cast<Integer&>(opt) == Integer{42});
}

static void test_cast_string() {
    Asn1Optional<VisibleString> opt;
    static_cast<VisibleString&>(opt) = VisibleString{"hello"};
    check("cast_string", static_cast<VisibleString&>(opt) == VisibleString{"hello"});
}

// ── set found via base pointer — simulates projection engine ─────────────────

template<typename T>
static void test_engine_set(const char* tname) {
    Asn1Optional<T> opt;
    Asn1OptionalBase* base = &opt;   // engine holds Asn1OptionalBase*
    base->found = true;
    check(tname, opt.found, "found not visible after setting through base*");
    base->found = false;
    check(tname, !opt.found, "found not cleared through base*");
}

int main() {
    printf("=== Asn1Optional layout ===\n");
    test_layout<Integer>     ("layout_integer");
    test_layout<VisibleString>("layout_visible_string");

    printf("=== value_ptr ===\n");
    test_value_ptr<Integer>     ("value_ptr_integer");
    test_value_ptr<VisibleString>("value_ptr_visible_string");

    printf("=== desc ===\n");
    test_desc<Integer>     ("desc_integer");
    test_desc<VisibleString>("desc_visible_string");

    printf("=== default found=false ===\n");
    test_default_found<Integer>     ("default_found_integer");
    test_default_found<VisibleString>("default_found_visible_string");

    printf("=== cast access ===\n");
    test_cast_integer();
    test_cast_string();

    printf("=== engine set via base* ===\n");
    test_engine_set<Integer>     ("engine_set_integer");
    test_engine_set<VisibleString>("engine_set_visible_string");

    printf("\n%s — %d failure(s)\n", failures ? "FAIL" : "PASS", failures);
    return failures ? EXIT_FAILURE : EXIT_SUCCESS;
}
