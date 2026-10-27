// PER encode of a length outside a non-extensible SIZE constraint
// (per_size_violation_test.asn1, X.691 §10.9.4.1): OCTET STRING, BIT STRING
// and SEQUENCE OF have no encoding for such a count, so the encode fails.
#include <cstdio>
#include <vector>
#include <asn1cpp/asn1cpp.hpp>
#include <asn1cpp/codec/PerCodec.hpp>
#include "Probe.hpp"

using namespace asn1;

static int failures = 0;

static void check(const char* label, bool cond) {
    if (cond) printf("  \033[32mPASS\033[0m  %s\n", label);
    else      { printf("  \033[31mFAIL\033[0m  %s\n", label); ++failures; }
}

static Probe valid() {
    Probe p;
    const uint8_t s[] = {1, 2};
    p.s.set(s, sizeof s);
    p.b.set(std::vector<uint8_t>{0xA5});
    p.l.push_back(ProbeLElem{1});
    p.l.push_back(ProbeLElem{2});
    p.tail = Integer{99};
    return p;
}

static bool encode_fails(const Probe& p) {
    std::vector<uint8_t> buf;
    PerEncodeStream s{buf};
    PerCodec::instance().encode(s, Probe::asn_DEF, &p);
    return s.encode_failed();
}

int main() {
    printf("=== PER: length outside a non-extensible SIZE ===\n");
    {
        Probe p = valid();
        std::vector<uint8_t> buf;
        PerEncodeStream s{buf};
        PerCodec::instance().encode(s, Probe::asn_DEF, &p);
        s.flush();
        Probe back;
        PerDecodeStream d{buf};
        check("in-range value encodes and round-trips",
              !s.encode_failed() && PerCodec::instance().decode(d, Probe::asn_DEF, &back).has_value() &&
              back.s.size() == 2 && back.l.size() == 2 && back.tail.value() == 99);
    }
    {
        Probe p = valid();
        std::vector<uint8_t> v(15, 0x78);
        p.s.set(v.data(), v.size());
        check("OCTET STRING (SIZE(1..4)) with 15 octets fails", encode_fails(p));
        p.s.set(v.data(), 0);
        check("OCTET STRING (SIZE(1..4)) with 0 octets fails", encode_fails(p));
    }
    {
        Probe p = valid();
        p.b.set(std::vector<uint8_t>{0xA5, 0x5A});
        check("BIT STRING (SIZE(8..12)) with 16 bits fails", encode_fails(p));
    }
    {
        Probe p = valid();
        p.l.push_back(ProbeLElem{3});
        p.l.push_back(ProbeLElem{4});
        check("SEQUENCE (SIZE(2..3)) OF with 4 elements fails", encode_fails(p));
        Probe q = valid();
        q.l.resize(1);
        check("SEQUENCE (SIZE(2..3)) OF with 1 element fails", encode_fails(q));
    }

    printf("\n%s (%d failure%s)\n", failures ? "FAILED" : "OK", failures, failures == 1 ? "" : "s");
    return failures ? 1 : 0;
}
