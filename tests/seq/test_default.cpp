// BER round-trip tests for DEFAULT values: suppress on encode, fill on decode.
#include <cstdio>
#include <vector>
#include <span>
#include <memory>
#include <asn1cpp/asn1cpp.hpp>
#include "Primitive.hpp"
#include "Config.hpp"
#include "Mixed.hpp"

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

// ── Primitive: INTEGER / BOOLEAN / ENUMERATED DEFAULT ──────────────────────

static void test_primitive_all_default() {
    printf("Primitive — all at default values\n");

    // Encode with all members at their default values — body must be empty (30 00).
    Primitive enc{};
    auto setdef = [](Primitive& p) {
        BerReader r{std::span<const uint8_t>{}};
        BerDecodeStream s{r};
        // Use set_default path: encode empty sequence, decode to trigger set_default fill.
        std::vector<uint8_t> empty{0x30, 0x00};
        BerReader r2{empty}; BerDecodeStream s2{r2};
        BerCodec::instance().decode(s2, Primitive::asn_DEF, &p);
    };
    setdef(enc);

    auto bytes = ber_enc(Primitive::asn_DEF, &enc);
    check("Primitive all-default suppressed (30 00)",
          bytes == std::vector<uint8_t>{0x30, 0x00});

    // Decode empty sequence — set_default must fill all three members.
    std::vector<uint8_t> empty{0x30, 0x00};
    Primitive dec{};
    check("Primitive decode empty ok", ber_dec(empty, Primitive::asn_DEF, &dec));
    check("Primitive default count==0",  dec.count  && (int64_t)*dec.count  == 0);
    check("Primitive default active==F", dec.active && *dec.active == Boolean{false});
    check("Primitive default level==med",dec.level  && dec.level->present() == Level::medium);
}

static void test_primitive_non_default() {
    printf("Primitive — non-default values\n");

    Primitive enc{};
    enc.count  = std::make_unique<Integer>(Integer{5});
    enc.active = std::make_unique<Boolean>(Boolean{true});
    enc.level  = std::make_unique<Level>(Level::high);

    auto bytes = ber_enc(Primitive::asn_DEF, &enc);
    check("Primitive non-default encodes non-empty", bytes.size() > 2);

    Primitive dec{};
    check("Primitive non-default decode ok",    ber_dec(bytes, Primitive::asn_DEF, &dec));
    check("Primitive non-default count==5",     dec.count  && (int64_t)*dec.count  == 5);
    check("Primitive non-default active==T",    dec.active && *dec.active == Boolean{true});
    check("Primitive non-default level==high",  dec.level  && dec.level->present() == Level::high);
}

static void test_primitive_partial_default() {
    printf("Primitive — mixed: count changed, rest at default\n");

    // count=7, active=false (default), level=medium (default) → only count on wire
    Primitive enc{};
    enc.count  = std::make_unique<Integer>(Integer{7});
    enc.active = std::make_unique<Boolean>(Boolean{false});   // == DEFAULT
    enc.level  = std::make_unique<Level>(Level::medium);      // == DEFAULT

    auto bytes = ber_enc(Primitive::asn_DEF, &enc);
    // Only count ([0] INTEGER 7) on wire: 30 05 80 01 07 (count only, no active/level)
    // Verify: shorter than full encoding but non-empty
    check("Primitive partial: non-empty",        bytes.size() > 2);

    Primitive dec{};
    check("Primitive partial decode ok",         ber_dec(bytes, Primitive::asn_DEF, &dec));
    check("Primitive partial count==7",          dec.count  && (int64_t)*dec.count  == 7);
    // active and level absent on wire → filled with defaults on decode
    check("Primitive partial active==F (default)", dec.active && *dec.active == Boolean{false});
    check("Primitive partial level==med (default)",dec.level  && dec.level->present() == Level::medium);

    // Re-encode decoded value: must match original (idempotent)
    auto bytes2 = ber_enc(Primitive::asn_DEF, &dec);
    check("Primitive partial BER idempotent",    bytes == bytes2);
}

// ── Config: non-zero / non-false defaults ──────────────────────────────────

static void test_config_all_default() {
    printf("Config — all at default (30, 3, TRUE)\n");

    std::vector<uint8_t> empty{0x30, 0x00};
    Config dec{};
    check("Config decode empty ok",          ber_dec(empty, Config::asn_DEF, &dec));
    check("Config default timeout==30",      dec.timeout && (int64_t)*dec.timeout == 30);
    check("Config default retries==3",       dec.retries && (int64_t)*dec.retries == 3);
    check("Config default loud==T",          dec.loud    && *dec.loud == Boolean{true});

    // Re-encode all-default → empty body
    auto bytes = ber_enc(Config::asn_DEF, &dec);
    check("Config all-default suppressed (30 00)",
          bytes == std::vector<uint8_t>{0x30, 0x00});
}

static void test_config_non_default() {
    printf("Config — non-default values\n");

    Config enc{};
    enc.timeout = std::make_unique<Integer>(Integer{60});
    enc.retries = std::make_unique<Integer>(Integer{5});
    enc.loud    = std::make_unique<Boolean>(Boolean{false});

    auto bytes = ber_enc(Config::asn_DEF, &enc);
    check("Config non-default non-empty", bytes.size() > 2);

    Config dec{};
    check("Config non-default decode ok",       ber_dec(bytes, Config::asn_DEF, &dec));
    check("Config non-default timeout==60",     dec.timeout && (int64_t)*dec.timeout == 60);
    check("Config non-default retries==5",      dec.retries && (int64_t)*dec.retries == 5);
    check("Config non-default loud==F",         dec.loud    && *dec.loud == Boolean{false});

    auto bytes2 = ber_enc(Config::asn_DEF, &dec);
    check("Config BER idempotent",              bytes == bytes2);
}

// ── Mixed: required + DEFAULT + OPTIONAL ───────────────────────────────────

static void test_mixed_required_only() {
    printf("Mixed — required id only, code at default, extra absent\n");

    Mixed enc{};
    enc.id   = Integer{42};
    enc.code = std::make_unique<Integer>(Integer{200});   // == DEFAULT
    // extra absent

    auto bytes = ber_enc(Mixed::asn_DEF, &enc);
    check("Mixed req-only non-empty",   bytes.size() > 2);

    Mixed dec{};
    check("Mixed req-only decode ok",   ber_dec(bytes, Mixed::asn_DEF, &dec));
    check("Mixed req-only id==42",      (int64_t)dec.id == 42);
    // code absent on wire → filled with default
    check("Mixed req-only code==200",   dec.code  && (int64_t)*dec.code == 200);
    check("Mixed req-only extra absent",!dec.extra);
}

static void test_mixed_all_present() {
    printf("Mixed — all members present, non-default\n");

    Mixed enc{};
    enc.id    = Integer{1};
    enc.code  = std::make_unique<Integer>(Integer{404});
    enc.extra = std::make_unique<Integer>(Integer{99});

    auto bytes = ber_enc(Mixed::asn_DEF, &enc);
    check("Mixed full non-empty",       bytes.size() > 2);

    Mixed dec{};
    check("Mixed full decode ok",       ber_dec(bytes, Mixed::asn_DEF, &dec));
    check("Mixed full id==1",           (int64_t)dec.id == 1);
    check("Mixed full code==404",       dec.code  && (int64_t)*dec.code == 404);
    check("Mixed full extra==99",       dec.extra && (int64_t)*dec.extra == 99);

    auto bytes2 = ber_enc(Mixed::asn_DEF, &dec);
    check("Mixed full BER idempotent",  bytes == bytes2);
}

int main() {
    test_primitive_all_default();
    test_primitive_non_default();
    test_primitive_partial_default();
    test_config_all_default();
    test_config_non_default();
    test_mixed_required_only();
    test_mixed_all_present();

    printf("\n%s  %d failure(s)\n", failures ? "\033[31mFAIL\033[0m" : "\033[32mPASS\033[0m", failures);
    return failures ? 1 : 0;
}
