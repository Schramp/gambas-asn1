// BIT STRING with a NamedBitList in PER (per_named_bits_test.asn1). Trailing
// 0 bits are removed and the value is padded with 0 bits up to the SIZE lower
// bound (X.691 §15.2, §15.3); `plain` has no NamedBitList and keeps its length.
// Expected bytes are asn1c's UPER output for the same values. Decoding gives
// back the value in that transmitted form.
#include <cstdio>
#include <cstdint>
#include <span>
#include <string>
#include <vector>
#include <asn1cpp/asn1cpp.hpp>
#include <asn1cpp/codec/PerCodec.hpp>
#include <asn1cpp/codec/ValidateCounter.hpp>
#include "NamedBitsRec.hpp"

using namespace asn1;

static int failures = 0;

static void check(const std::string& label, bool cond) {
    if (cond) printf("  \033[32mPASS\033[0m  %s\n", label.c_str());
    else      { printf("  \033[31mFAIL\033[0m  %s\n", label.c_str()); ++failures; }
}

/// BitString from a string of '0'/'1' characters, first character = bit 0.
static BitString bits(const std::string& s) {
    std::vector<uint8_t> b((s.size() + 7) / 8, 0);
    for (std::size_t i = 0; i < s.size(); ++i)
        if (s[i] == '1') b[i / 8] |= static_cast<uint8_t>(0x80 >> (i % 8));
    return BitString{std::move(b), static_cast<uint8_t>((8 - s.size() % 8) % 8)};
}

/// The transmitted form of a NamedBitList value: trailing 0 bits removed,
/// then 0 bits added up to `lb`.
static BitString sent(std::string s, std::size_t lb) {
    while (!s.empty() && s.back() == '0') s.pop_back();
    if (s.size() < lb) s.append(lb - s.size(), '0');
    return bits(s);
}

static std::vector<uint8_t> per_enc(const NamedBitsRec& v) {
    std::vector<uint8_t> buf;
    PerEncodeStream s{buf};
    IEncodeStream& es = s;
    PerCodec::instance().encode(es, NamedBitsRec::asn_DEF, &v);
    s.flush();
    return buf;
}

/// Encode {flags, sized, fixed, ext, named, alias, typed, plain}, compare with
/// asn1c's bytes, decode and compare with the transmitted form of each member.
static void check_rec(const char* label, const std::vector<std::string>& v,
                      const std::vector<uint8_t>& expected) {
    NamedBitsRec r{};
    r.flags = bits(v[0]); r.sized = bits(v[1]); r.fixed = bits(v[2]); r.ext = bits(v[3]);
    r.named = bits(v[4]); r.alias = bits(v[5]); r.typed = bits(v[6]); r.plain = bits(v[7]);
    reset_validate_fail_count();
    check(std::string(label) + " encodes", per_enc(r) == expected);
    check(std::string(label) + " satisfies its constraints", validate_fail_count() == 0);

    NamedBitsRec back{};
    PerDecodeStream ds{std::span<const uint8_t>(expected)};
    bool ok = PerCodec::instance().decode(ds, NamedBitsRec::asn_DEF, &back).has_value();
    check(std::string(label) + " decodes",
          ok && back.flags == sent(v[0], 0) && back.sized == sent(v[1], 2)
             && back.fixed == sent(v[2], 8) && back.ext == sent(v[3], 2)
             && back.named == sent(v[4], 0) && back.alias == sent(v[5], 0)
             && back.typed == sent(v[6], 2) && back.plain == bits(v[7]));
}

int main() {
    check_rec("'01000000'B",
              {"01000000", "01000000", "01000000", "01000000", "01000000", "01000000", "01000000", "01000000"},
              {0x02, 0x42, 0x80, 0x08, 0x12, 0x04, 0x84, 0x21, 0x00});
    check_rec("all zero",
              {"00000000", "00000000", "00000000", "00000000", "00000000", "00000000", "00000000", "00000000"},
              {0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x08, 0x00});
    check_rec("'1'B",
              {"1", "1", "10000000", "1", "1", "1", "1", "1"},
              {0x01, 0x8a, 0x00, 0x20, 0x18, 0x0c, 0x40, 0x30});
    check_rec("'1'B, fixed padded to SIZE (8)",
              {"1", "1", "1", "1", "1", "1", "1", "1"},
              {0x01, 0x8a, 0x00, 0x20, 0x18, 0x0c, 0x40, 0x30});
    check_rec("'0110100000'B",
              {"0110100000", "0110100000", "01101000", "0110100000", "0110100000", "0110100000", "0110100000", "0110100000"},
              {0x05, 0x6b, 0x6b, 0x41, 0xb4, 0x15, 0xa0, 0xad, 0x6d, 0x0a, 0x68, 0x00});
    check_rec("'101'B, ext outside its root",
              {"101", "101", "10100001", "101000001", "101", "101", "101", "101"},
              {0x03, 0xa6, 0xd0, 0xc2, 0x68, 0x20, 0x74, 0x0e, 0x9a, 0x07, 0x40});

    printf("\n%s (%d failure%s)\n", failures ? "FAILED" : "PASSED", failures, failures == 1 ? "" : "s");
    return failures ? 1 : 0;
}
