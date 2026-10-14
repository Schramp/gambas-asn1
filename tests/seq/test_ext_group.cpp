// SEQUENCE extension addition group [[ ]] (X.691 §18.9;
// per_ext_group_test.asn1): the group is one extension addition, encoded
// as a sequence of its components (own bitmap for g2, the only component
// declared OPTIONAL inside it) in one open type; "before" and "after" are
// plain additions. Expected bytes are asn1c's UPER output for each value.
#include <cstdio>
#include <memory>
#include <span>
#include <vector>
#include <asn1cpp/asn1cpp.hpp>
#include <asn1cpp/codec/PerCodec.hpp>
#include "Rec.hpp"

using namespace asn1;

static int failures = 0;

static void check(const char* label, bool cond) {
    if (cond) printf("  \033[32mPASS\033[0m  %s\n", label);
    else      { printf("  \033[31mFAIL\033[0m  %s\n", label); ++failures; }
}

static std::vector<uint8_t> per_enc(const Rec& v) {
    std::vector<uint8_t> buf;
    PerEncodeStream s{buf};
    IEncodeStream& es = s;
    PerCodec::instance().encode(es, Rec::asn_DEF, &v);
    s.flush();
    return buf;
}

static bool per_dec(const std::vector<uint8_t>& bytes, Rec& out) {
    PerDecodeStream s{std::span<const uint8_t>{bytes}};
    IDecodeStream& ds = s;
    return PerCodec::instance().decode(ds, Rec::asn_DEF, &out).has_value();
}

struct Case {
    const char* label;
    std::vector<uint8_t> bytes;
    int before, g1, g2, after;   // -1 = absent
};

static Rec make(const Case& c) {
    Rec r{};
    r.id = Integer{39};
    if (c.before >= 0) r.before = std::make_unique<Boolean>(c.before != 0);
    if (c.g1 >= 0)     r.g1 = std::make_unique<Integer>(c.g1);
    if (c.g2 >= 0)     r.g2 = std::make_unique<Boolean>(c.g2 != 0);
    if (c.after >= 0)  r.after = std::make_unique<Integer>(c.after);
    return r;
}

static bool matches(const Rec& r, const Case& c) {
    auto opt_int = [](const std::unique_ptr<Integer>& p) { return p ? static_cast<int>(p->value()) : -1; };
    auto opt_bool = [](const std::unique_ptr<Boolean>& p) { return p ? (p->value() ? 1 : 0) : -1; };
    return r.id.value() == 39 && opt_bool(r.before) == c.before && opt_int(r.g1) == c.g1 &&
           opt_bool(r.g2) == c.g2 && opt_int(r.after) == c.after;
}

int main() {
    const Case cases[] = {
        {"no extensions",                   {0x13, 0x80},                                             -1, -1, -1, -1},
        {"before, group {g1}, after",       {0x93, 0x82, 0xe0, 0x30, 0x00, 0x27, 0x00, 0x30, 0x00},     1,  7, -1,  2},
        {"group {g1, g2} only",             {0x93, 0x82, 0x40, 0x37, 0x80},                           -1,  7,  1, -1},
        {"after only",                      {0x93, 0x82, 0x20, 0x28, 0x00},                           -1, -1, -1,  1},
    };
    for (const auto& c : cases) {
        char label[128];
        std::snprintf(label, sizeof label, "encode: %s", c.label);
        check(label, per_enc(make(c)) == c.bytes);
        Rec back{};
        std::snprintf(label, sizeof label, "decode: %s", c.label);
        check(label, per_dec(c.bytes, back) && matches(back, c));
    }
    printf("\n%s (%d failure%s)\n", failures ? "FAILED" : "PASSED", failures, failures == 1 ? "" : "s");
    return failures ? 1 : 0;
}
