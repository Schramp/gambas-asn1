// BER / XER / PER round-trip tests for plain SEQUENCE (no tagging, no OPTIONAL).
// Schema: tests/asn1/simple_seq.asn1
// TypeDescriptors are constructed manually; cross-validated against asn1c.
#include <cstdio>
#include <cstdlib>
#include <vector>
#include <span>
#include <sstream>
#include <string>
#include <asn1cpp/asn1cpp.hpp>
#include <asn1cpp/codec/PerCodec.hpp>
#include <asn1cpp/codec/PerConstraints.hpp>

using namespace asn1;

static int failures = 0;

static void check(const char* name, bool cond, const char* detail = "") {
    if (cond) printf("  \033[32mPASS\033[0m  %s\n", name);
    else {
        printf("  \033[31mFAIL\033[0m  %s%s%s\n", name, *detail ? ": " : "", detail);
        ++failures;
    }
}

// ---- Inline TypeDescriptors matching what the generator emits ---------------

struct Point { Integer x{}; Integer y{}; };

static const MemberDescriptor Point_mbr[] = {
    { "x", Tag::universal(2, false), false, false, offsetof(Point, x), &asn_DEF_Integer },
    { "y", Tag::universal(2, false), false, false, offsetof(Point, y), &asn_DEF_Integer },
};
static const SequenceSpec Point_spc = { Point_mbr, 2, -1, 0, 0, nullptr };
static const TypeDescriptor Point_def = {
    "Point", Tag::universal(16, true),
    nullptr, &Point_spc, nullptr, nullptr
};

// ---- BER helpers -----------------------------------------------------------

static std::vector<uint8_t> ber_encode(const Point& p) {
    std::vector<uint8_t> buf;
    BerWriter w{buf};
    BerEncodeStream s{w};
    BerCodec::instance().encode(s, Point_def, &p);
    return buf;
}

static bool ber_decode(std::span<const uint8_t> bytes, Point& out) {
    BerReader r{bytes};
    BerDecodeStream s{r};
    return BerCodec::instance().decode(s, Point_def, &out).has_value();
}

// ---- XER helpers -----------------------------------------------------------

static std::string xer_encode(const Point& p) {
    std::ostringstream oss;
    XerEncodeStream s{oss};
    XerCodec::instance().encode(s, Point_def, &p);
    return oss.str();
}

static bool xer_decode(const std::string& xml, Point& out) {
    XerDecodeStream s{xml};
    return XerCodec::instance().decode(s, Point_def, &out).has_value();
}

// ---- PER helpers -----------------------------------------------------------

static std::vector<uint8_t> per_encode(const Point& p) {
    std::vector<uint8_t> buf;
    PerEncodeStream s{buf};
    PerCodec::instance().encode(s, Point_def, &p);
    s.flush();
    return buf;
}

static bool per_decode(std::span<const uint8_t> bytes, Point& out) {
    PerDecodeStream s{bytes};
    return PerCodec::instance().decode(s, Point_def, &out).has_value();
}

// ---- Tests -----------------------------------------------------------------

static bool ber_roundtrip(int64_t x, int64_t y) {
    Point p{Integer{x}, Integer{y}};
    auto enc = ber_encode(p);
    Point got{};
    if (!ber_decode(enc, got)) return false;
    return got.x.value() == x && got.y.value() == y;
}

static bool xer_roundtrip(int64_t x, int64_t y) {
    Point p{Integer{x}, Integer{y}};
    auto xml = xer_encode(p);
    Point got{};
    if (!xer_decode(xml, got)) return false;
    return got.x.value() == x && got.y.value() == y;
}

static bool per_roundtrip(int64_t x, int64_t y) {
    Point p{Integer{x}, Integer{y}};
    auto enc = per_encode(p);
    Point got{};
    if (!per_decode(enc, got)) return false;
    return got.x.value() == x && got.y.value() == y;
}

// Expected BER bytes cross-validated against asn1c
static bool ber_encodes_as(int64_t x, int64_t y, std::initializer_list<uint8_t> exp) {
    Point p{Integer{x}, Integer{y}};
    auto got = ber_encode(p);
    return got == std::vector<uint8_t>(exp);
}

// Expected PER bytes cross-validated against asn1c
static bool per_encodes_as(int64_t x, int64_t y, std::initializer_list<uint8_t> exp) {
    Point p{Integer{x}, Integer{y}};
    auto got = per_encode(p);
    return got == std::vector<uint8_t>(exp);
}

int main() {
    printf("\n── SEQUENCE BER — Point{x,y} ────────────────────────────────────\n");

    check("Point{3,4} BER encodes as 30 06 02 01 03 02 01 04",
          ber_encodes_as(3, 4, {0x30,0x06,0x02,0x01,0x03,0x02,0x01,0x04}));
    check("Point{0,0} BER encodes as 30 06 02 01 00 02 01 00",
          ber_encodes_as(0, 0, {0x30,0x06,0x02,0x01,0x00,0x02,0x01,0x00}));
    check("Point{100,-7} BER encodes as 30 06 02 01 64 02 01 f9",
          ber_encodes_as(100, -7, {0x30,0x06,0x02,0x01,0x64,0x02,0x01,0xf9}));

    check("Point{3,4} BER round-trip",    ber_roundtrip(3, 4));
    check("Point{0,0} BER round-trip",    ber_roundtrip(0, 0));
    check("Point{-1,1000} BER round-trip", ber_roundtrip(-1, 1000));

    printf("\n── SEQUENCE XER — Point{x,y} ────────────────────────────────────\n");

    check("Point{3,4} XER round-trip",    xer_roundtrip(3, 4));
    check("Point{0,0} XER round-trip",    xer_roundtrip(0, 0));
    check("Point{100,-7} XER round-trip", xer_roundtrip(100, -7));

    // XER encode sanity: check that element names appear correctly
    {
        auto xml = xer_encode(Point{Integer{5}, Integer{6}});
        bool has_point = xml.find("<Point>") != std::string::npos;
        bool has_x     = xml.find("<x>5</x>") != std::string::npos;
        bool has_y     = xml.find("<y>6</y>") != std::string::npos;
        check("Point{5,6} XER contains <Point>", has_point);
        check("Point{5,6} XER contains <x>5</x>", has_x);
        check("Point{5,6} XER contains <y>6</y>", has_y);
    }

    printf("\n── SEQUENCE PER — Point{x,y} (unconstrained INTEGERs) ───────────\n");

    check("Point{3,4} PER encodes as 01 03 01 04",
          per_encodes_as(3, 4, {0x01,0x03,0x01,0x04}));
    check("Point{0,0} PER encodes as 01 00 01 00",
          per_encodes_as(0, 0, {0x01,0x00,0x01,0x00}));
    check("Point{100,-7} PER encodes as 01 64 01 f9",
          per_encodes_as(100, -7, {0x01,0x64,0x01,0xf9}));

    check("Point{3,4} PER round-trip",    per_roundtrip(3, 4));
    check("Point{0,0} PER round-trip",    per_roundtrip(0, 0));
    check("Point{100,-7} PER round-trip", per_roundtrip(100, -7));

    printf("\n");
    if (failures) { printf("  %d test(s) FAILED\n", failures); return 1; }
    printf("  All tests passed.\n");
    return 0;
}
