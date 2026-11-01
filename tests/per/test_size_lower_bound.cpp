// SIZE(lb..MAX) lower bounds and the 64K edge of the PER length determinant
// (size_lower_bound_test.asn1).
//
// validate() must reject a value shorter than lb (X.680 §51.5) and
// RandomFiller must never produce one. On the wire, a length whose SIZE has
// no upper bound, or one of 64K or more, is n itself (X.691 §11.9.4.2);
// below 64K it is the constrained whole number n - lb (§11.9.4.1).
//
// Vectors: asn1c `converter-example -ixer -ouper`, cross-checked
// byte-for-byte with Erlang/OTP asn1 `-buper`. The large-length rows record
// asn1c's output as total size plus the offsets and values of the length
// octets; the content octets in between are all 0xAB.
#include <cstdio>
#include <random>
#include <string>
#include <vector>
#include <asn1cpp/asn1cpp.hpp>
#include <asn1cpp/Validate.hpp>
#include <asn1cpp/codec/PerCodec.hpp>
#include <asn1cpp/codec/RandomFiller.hpp>
#include "Probe.hpp"
#include "Ub65535.hpp"
#include "Ub65536.hpp"
#include "Lb10Ub70k.hpp"
#include "Lb10Max.hpp"

using namespace asn1;

static int failures = 0;

static void check(const std::string& label, bool cond) {
    if (cond) printf("  \033[32mPASS\033[0m  %s\n", label.c_str());
    else      { printf("  \033[31mFAIL\033[0m  %s\n", label.c_str()); ++failures; }
}

static std::string hex(const std::vector<uint8_t>& v) {
    std::string s;
    char b[3];
    for (auto x : v) { snprintf(b, sizeof b, "%02x", x); s += b; }
    return s;
}

static std::vector<uint8_t> per_encode(const TypeDescriptor& def, const Asn1Object* obj) {
    std::vector<uint8_t> buf;
    PerEncodeStream s{buf};
    PerCodec::instance().encode(s, def, obj);
    s.flush();
    return buf;
}

static Probe make_probe(int os_len, const char* ia5, int bit_count, int ints) {
    Probe p;
    std::vector<uint8_t> os(os_len);
    for (int i = 0; i < os_len; ++i) os[i] = static_cast<uint8_t>(i + 1);
    p.os.set(os);
    p.ia5 = Ia5{ia5};
    // 1010 0101 1...: the bit pattern of the vectors below.
    std::vector<uint8_t> bits((bit_count + 7) / 8, 0);
    bits[0] = 0xA5;
    if (bit_count > 8) bits[1] = 0x80;
    p.bits.set(bits, static_cast<uint8_t>((8 - bit_count % 8) % 8));
    const int64_t vals[] = {1, 2, 7};
    for (int i = 0; i < ints; ++i) p.ints.push_back(Integer{vals[i]});
    return p;
}

static void probe_vector(const char* label, const Probe& p, const char* want) {
    auto buf = per_encode(Probe::asn_DEF, &p);
    check(std::string(label) + " encodes to " + want, hex(buf) == want);
    Probe back;
    PerDecodeStream d{buf};
    check(std::string(label) + " round-trips",
          PerCodec::instance().decode(d, Probe::asn_DEF, &back).has_value() && back == p);
}

static void length_vector(const TypeDescriptor& def, const char* type, int n, const std::string& want) {
    OctetString v;
    v.set(std::vector<uint8_t>(n, 0xAB));
    auto buf = per_encode(def, &v);
    check(std::string(type) + " n=" + std::to_string(n) + " encodes to asn1c bytes", hex(buf) == want);
}

struct Header { std::size_t offset; uint8_t value; };

static void long_vector(const TypeDescriptor& def, const char* type, int n, std::size_t total,
                        std::vector<Header> headers) {
    OctetString v;
    v.set(std::vector<uint8_t>(n, 0xAB));
    auto buf = per_encode(def, &v);
    bool ok = buf.size() == total;
    std::size_t hi = 0;
    for (std::size_t i = 0; ok && i < buf.size(); ++i) {
        if (hi < headers.size() && headers[hi].offset == i) ok = buf[i] == headers[hi++].value;
        else ok = buf[i] == 0xAB;
    }
    check(std::string(type) + " n=" + std::to_string(n) + " matches asn1c layout", ok && hi == headers.size());
    OctetString back;
    PerDecodeStream d{buf};
    check(std::string(type) + " n=" + std::to_string(n) + " round-trips",
          PerCodec::instance().decode(d, def, &back).has_value() && back == v);
}

int main() {
    printf("=== validate(): SIZE(lb..MAX) lower bound ===\n");
    {
        Probe ok = make_probe(4, "abc", 8, 2);
        const auto& m = Probe::asn_DEF.sequence_spec->members;
        auto member_valid = [&](int i, const Asn1Object* field) {
            return validate(*m[i].type_descriptor, field) == 0;
        };
        check("OCTET STRING (SIZE(4..MAX)) with 4 octets is valid", member_valid(0, &ok.os));
        check("IA5String (SIZE(3..MAX)) with 3 chars is valid",     member_valid(1, &ok.ia5));
        check("BIT STRING (SIZE(8..MAX)) with 8 bits is valid",     member_valid(2, &ok.bits));
        check("SEQUENCE (SIZE(2..MAX)) OF with 2 elements is valid", member_valid(3, &ok.ints));

        Probe shortp = make_probe(3, "ab", 7, 1);
        check("OCTET STRING (SIZE(4..MAX)) with 3 octets is rejected", !member_valid(0, &shortp.os));
        check("IA5String (SIZE(3..MAX)) with 2 chars is rejected",     !member_valid(1, &shortp.ia5));
        check("BIT STRING (SIZE(8..MAX)) with 7 bits is rejected",     !member_valid(2, &shortp.bits));
        check("SEQUENCE (SIZE(2..MAX)) OF with 1 element is rejected", !member_valid(3, &shortp.ints));
    }

    printf("=== RandomFiller honours SIZE(lb..MAX) ===\n");
    {
        std::mt19937 rng{42};
        FillConfig cfg;
        RandomFiller filler{rng, cfg};
        int bad = 0;
        for (int i = 0; i < 500; ++i) {
            Probe p;
            filler.fill(&p, Probe::asn_DEF);
            if (p.os.size() < 4 || p.ia5.str().size() < 3 || p.bits.bit_count() < 8 || p.ints.size() < 2)
                ++bad;
        }
        check("500 filled Probe values all reach their lower bounds", bad == 0);
    }

    printf("=== UPER: SIZE(lb..MAX) uses the unconstrained length ===\n");
    probe_vector("Probe{4 octets, \"abc\", 8 bits, 2 ints}", make_probe(4, "abc", 8, 2),
                 "040102030403c38b1845281140");
    probe_vector("Probe{5 octets, \"abcd\", 9 bits, 3 ints}", make_probe(5, "abcd", 9, 3),
                 "05010203040504c38b1e409a58195c");

    printf("=== UPER: 64K edge of the length determinant ===\n");
    auto abs = [](int n) { std::string s; for (int i = 0; i < n; ++i) s += "ab"; return s; };
    length_vector(asn_DEF_Ub65535, "Ub65535 SIZE(0..65535)",    10,  "000a" + abs(10));
    length_vector(asn_DEF_Ub65535, "Ub65535 SIZE(0..65535)",    200, "00c8" + abs(200));
    length_vector(asn_DEF_Ub65536, "Ub65536 SIZE(0..65536)",    10,  "0a" + abs(10));
    length_vector(asn_DEF_Ub65536, "Ub65536 SIZE(0..65536)",    200, "80c8" + abs(200));
    length_vector(asn_DEF_Lb10Ub70k, "Lb10Ub70k SIZE(10..70000)", 10,  "0a" + abs(10));
    length_vector(asn_DEF_Lb10Ub70k, "Lb10Ub70k SIZE(10..70000)", 200, "80c8" + abs(200));
    length_vector(asn_DEF_Lb10Max, "Lb10Max SIZE(10..MAX)",     10,  "0a" + abs(10));
    length_vector(asn_DEF_Lb10Max, "Lb10Max SIZE(10..MAX)",     200, "80c8" + abs(200));

    long_vector(asn_DEF_Ub65535, "Ub65535 SIZE(0..65535)", 65535, 65537,
                {{0, 0xff}, {1, 0xff}});
    long_vector(asn_DEF_Ub65536, "Ub65536 SIZE(0..65536)", 65535, 65538,
                {{0, 0xc3}, {49153, 0xbf}, {49154, 0xff}});
    long_vector(asn_DEF_Lb10Max, "Lb10Max SIZE(10..MAX)", 16384, 16386,
                {{0, 0xc1}, {16385, 0x00}});
    long_vector(asn_DEF_Lb10Ub70k, "Lb10Ub70k SIZE(10..70000)", 65536, 65538,
                {{0, 0xc4}, {65537, 0x00}});

    printf("\n%s (%d failure(s))\n", failures ? "FAILED" : "OK", failures);
    return failures ? 1 : 0;
}
