// PER SEQUENCE OF/SET OF elements encoded in zero bits
// (zero_width_items_test.asn1): a list counting more than kMaxZeroWidthItems
// items is refused once an element takes no input, so a few octets of
// length determinant (X.691 §11.9.3.8) cannot allocate millions of
// elements. Lists of elements that take input, and many short lists, are
// not limited.
//
// Vectors are UPER. asn1c (constr_SET_OF_uper.c) agrees on every Nulls,
// Fives and Flags row; it also refuses the Rows rows, since its SET OF
// decoder reports zero bits consumed for a nested list whatever it read.
#include <cstdio>
#include <string>
#include <vector>
#include <asn1cpp/asn1cpp.hpp>
#include <asn1cpp/codec/DecodeDepth.hpp>
#include <asn1cpp/codec/PerCodec.hpp>
#include "Fives.hpp"
#include "Flags.hpp"
#include "Nulls.hpp"
#include "Rows.hpp"

using namespace asn1;

static int failures = 0;

static void check(const std::string& label, bool cond) {
    if (cond) printf("  \033[32mPASS\033[0m  %s\n", label.c_str());
    else      { printf("  \033[31mFAIL\033[0m  %s\n", label.c_str()); ++failures; }
}

static std::vector<uint8_t> unhex(const std::string& h) {
    std::vector<uint8_t> out;
    for (std::size_t i = 0; i + 1 < h.size(); i += 2) out.push_back(static_cast<uint8_t>(std::stoi(h.substr(i, 2), nullptr, 16)));
    return out;
}

static std::string repeat(const std::string& s, int n) {
    std::string out;
    for (int i = 0; i < n; ++i) out += s;
    return out;
}

template <class T>
static void accepts(const char* label, const TypeDescriptor& def, const std::string& h, std::size_t count) {
    auto buf = unhex(h);
    T v;
    PerDecodeStream d{buf};
    auto r = PerCodec::instance().decode(d, def, &v);
    check(std::string(label) + " decodes to " + std::to_string(count) + " items", r.has_value() && v.count() == count);
}

template <class T>
static void refuses(const char* label, const TypeDescriptor& def, const std::string& h) {
    auto buf = unhex(h);
    T v;
    PerDecodeStream d{buf};
    auto r = PerCodec::instance().decode(d, def, &v);
    check(std::string(label) + " is refused as zero-width items",
          !r.has_value() && r.error().message.find("items encoded in zero bits") != std::string::npos);
}

int main() {
    printf("=== PER zero-width SEQUENCE OF items (limit %zu) ===\n", kMaxZeroWidthItems);
    accepts<Nulls>("Nulls, 200 NULLs", asn_DEF_Nulls, "80c8", 200);
    refuses<Nulls>("Nulls, 201 NULLs", asn_DEF_Nulls, "80c9");
    refuses<Nulls>("Nulls, 100 fragments of 64K NULLs", asn_DEF_Nulls, repeat("c4", 100) + "00");
    accepts<Fives>("Fives, 200 single-value INTEGERs", asn_DEF_Fives, "00c8", 200);
    refuses<Fives>("Fives, 60000 single-value INTEGERs", asn_DEF_Fives, "ea60");
    accepts<Flags>("Flags, 1000 one-bit BOOLEANs", asn_DEF_Flags, "83e8" + repeat("ff", 125), 1000);
    accepts<Rows>("Rows, 300 lists of 200 NULLs", asn_DEF_Rows, "812c" + repeat("80c8", 300), 300);
    accepts<Rows>("Rows, 201 empty lists", asn_DEF_Rows, "80c9" + repeat("00", 201), 201);

    printf("\n%s (%d failure%s)\n", failures ? "FAILED" : "OK", failures, failures == 1 ? "" : "s");
    return failures ? 1 : 0;
}
