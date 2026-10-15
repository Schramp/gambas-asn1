// Wide INTEGER ranges in PER (per_int64_bounds_test.asn1). Every record is
// followed by micro (0..999999) = 2 in 20 bits.
//
//   - U64Rec.seconds INTEGER (0..2^64−1) and S64Rec.value INTEGER
//     (−2^63..2^63−1): 2^64 values, value − lb in 64 bits (X.691 §11.5.6).
//   - S33Rec.value INTEGER (−2^32..2^32−1): 2^33 values, 33 bits.
//   - UncRec.value INTEGER: unconstrained whole number, length octet plus
//     minimal two's complement (X.691 §11.8, §12.2.6).
//   - A negative BER value for U64Rec has no unsigned storage and fails
//     the decode; an S33Rec value outside its range decodes and records a
//     constraint violation.
//
// S64Rec, S33Rec and UncRec bytes are asn1c's UPER output. asn1c cannot
// encode U64Rec (upper bound above INT64_MAX, Schramp/asn1c#12); its bytes
// equal asn1c's S64Rec bytes for value − 2^63, the same 64-bit field.
#include <cstdio>
#include <cstdint>
#include <span>
#include <vector>
#include <asn1cpp/asn1cpp.hpp>
#include <asn1cpp/codec/PerCodec.hpp>
#include <asn1cpp/codec/ValidateCounter.hpp>
#include "U64Rec.hpp"
#include "S64Rec.hpp"
#include "S33Rec.hpp"
#include "UncRec.hpp"

using namespace asn1;

static int failures = 0;

static void check(const char* label, bool cond) {
    if (cond) printf("  \033[32mPASS\033[0m  %s\n", label);
    else      { printf("  \033[31mFAIL\033[0m  %s\n", label); ++failures; }
}

template <typename T>
static std::vector<uint8_t> per_enc(const T& v) {
    std::vector<uint8_t> buf;
    PerEncodeStream s{buf};
    IEncodeStream& es = s;
    PerCodec::instance().encode(es, T::asn_DEF, &v);
    s.flush();
    return buf;
}

template <typename T>
static bool per_dec(std::span<const uint8_t> bytes, T& out) {
    PerDecodeStream s{bytes};
    return PerCodec::instance().decode(s, T::asn_DEF, &out).has_value();
}

template <typename T>
static bool ber_dec(std::span<const uint8_t> bytes, T& out) {
    BerReader r{bytes};
    BerDecodeStream s{r};
    return BerCodec::instance().decode(s, T::asn_DEF, &out).has_value();
}

/// Encode {field = value, micro = 2}, compare with `expected`, decode it back.
template <typename T, typename F, typename V>
static void check_rec(const char* label, F T::*field, V value, std::vector<uint8_t> expected) {
    T v{};
    v.*field = value;
    v.micro = 2;
    char l[160];
    snprintf(l, sizeof l, "%s encodes", label);
    check(l, per_enc(v) == expected);
    T back{};
    snprintf(l, sizeof l, "%s decodes", label);
    check(l, per_dec(expected, back) && (back.*field).value() == value && back.micro.value() == 2);
}

/// BER {value, micro = 2} with `content` as the value's INTEGER contents.
static std::vector<uint8_t> ber_rec(std::vector<uint8_t> content) {
    std::vector<uint8_t> out = {0x30, static_cast<uint8_t>(content.size() + 5), 0x80,
                                static_cast<uint8_t>(content.size())};
    out.insert(out.end(), content.begin(), content.end());
    out.insert(out.end(), {0x81, 0x01, 0x02});
    return out;
}

int main() {
    check_rec("U64Rec 1",      &U64Rec::seconds, 1ULL,                    {0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x01, 0x00,0x00,0x20});
    check_rec("U64Rec 2^32",   &U64Rec::seconds, 4294967296ULL,           {0x00,0x00,0x00,0x01,0x00,0x00,0x00,0x00, 0x00,0x00,0x20});
    check_rec("U64Rec 2^32+1", &U64Rec::seconds, 4294967297ULL,           {0x00,0x00,0x00,0x01,0x00,0x00,0x00,0x01, 0x00,0x00,0x20});
    check_rec("U64Rec 2^64-2", &U64Rec::seconds, 18446744073709551614ULL, {0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xfe, 0x00,0x00,0x20});
    check_rec("U64Rec 2^64-1", &U64Rec::seconds, 18446744073709551615ULL, {0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff, 0x00,0x00,0x20});

    check_rec("S64Rec -2^63",  &S64Rec::value, INT64_MIN,                 {0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00, 0x00,0x00,0x20});
    check_rec("S64Rec -2",     &S64Rec::value, int64_t{-2},               {0x7f,0xff,0xff,0xff,0xff,0xff,0xff,0xfe, 0x00,0x00,0x20});
    check_rec("S64Rec -1",     &S64Rec::value, int64_t{-1},               {0x7f,0xff,0xff,0xff,0xff,0xff,0xff,0xff, 0x00,0x00,0x20});
    check_rec("S64Rec 0",      &S64Rec::value, int64_t{0},                {0x80,0x00,0x00,0x00,0x00,0x00,0x00,0x00, 0x00,0x00,0x20});
    check_rec("S64Rec 2^32",   &S64Rec::value, int64_t{4294967296},       {0x80,0x00,0x00,0x01,0x00,0x00,0x00,0x00, 0x00,0x00,0x20});
    check_rec("S64Rec 2^32+1", &S64Rec::value, int64_t{4294967297},       {0x80,0x00,0x00,0x01,0x00,0x00,0x00,0x01, 0x00,0x00,0x20});
    check_rec("S64Rec 2^63-1", &S64Rec::value, INT64_MAX,                 {0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff, 0x00,0x00,0x20});

    check_rec("S33Rec -2^32",  &S33Rec::value, int64_t{-4294967296},      {0x00,0x00,0x00,0x00,0x00,0x00,0x10});
    check_rec("S33Rec -2",     &S33Rec::value, int64_t{-2},               {0x7f,0xff,0xff,0xff,0x00,0x00,0x10});
    check_rec("S33Rec -1",     &S33Rec::value, int64_t{-1},               {0x7f,0xff,0xff,0xff,0x80,0x00,0x10});
    check_rec("S33Rec 0",      &S33Rec::value, int64_t{0},                {0x80,0x00,0x00,0x00,0x00,0x00,0x10});
    check_rec("S33Rec 2^32-1", &S33Rec::value, int64_t{4294967295},       {0xff,0xff,0xff,0xff,0x80,0x00,0x10});

    check_rec("UncRec -(2^32+4)", &UncRec::value, int64_t{-4294967300},   {0x05,0xfe,0xff,0xff,0xff,0xfc, 0x00,0x00,0x20});
    check_rec("UncRec -2",     &UncRec::value, int64_t{-2},               {0x01,0xfe, 0x00,0x00,0x20});
    check_rec("UncRec -1",     &UncRec::value, int64_t{-1},               {0x01,0xff, 0x00,0x00,0x20});
    check_rec("UncRec 2^32",   &UncRec::value, int64_t{4294967296},       {0x05,0x01,0x00,0x00,0x00,0x00, 0x00,0x00,0x20});
    check_rec("UncRec 2^32+1", &UncRec::value, int64_t{4294967297},       {0x05,0x01,0x00,0x00,0x00,0x01, 0x00,0x00,0x20});
    check_rec("UncRec -2^63",  &UncRec::value, INT64_MIN,                 {0x08,0x80,0x00,0x00,0x00,0x00,0x00,0x00,0x00, 0x00,0x00,0x20});
    check_rec("UncRec 2^63-1", &UncRec::value, INT64_MAX,                 {0x08,0x7f,0xff,0xff,0xff,0xff,0xff,0xff,0xff, 0x00,0x00,0x20});

    U64Rec u64{};
    check("U64Rec -1 in BER is rejected", !ber_dec(ber_rec({0xff}), u64));
    check("U64Rec -2 in BER is rejected", !ber_dec(ber_rec({0xfe}), u64));
    auto violates = [](std::vector<uint8_t> content) {
        S33Rec s33{};
        reset_validate_fail_count();
        return ber_dec(ber_rec(std::move(content)), s33) && validate_fail_count() > 0;
    };
    check("S33Rec -(2^32+4) in BER records a violation", violates({0xfe,0xff,0xff,0xff,0xfc}));
    check("S33Rec 2^32 in BER records a violation",      violates({0x01,0x00,0x00,0x00,0x00}));
    check("S33Rec -2^32 in BER records no violation",    !violates({0xff,0x00,0x00,0x00,0x00}));

    printf("\n%s (%d failure%s)\n", failures ? "FAILED" : "PASSED", failures, failures == 1 ? "" : "s");
    return failures ? 1 : 0;
}
