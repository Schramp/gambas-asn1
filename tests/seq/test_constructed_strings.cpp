// Constructed-form strings in BER (X.690 §8.6.4, §8.7.3, §8.23.6; CER §9.2).
//
// tests/vectors/constructed_strings_test.vectors holds, per row, a BER
// encoding with constructed strings (asn1c's CER, or a worked example from
// X.690) and asn1c's DER of the same value. Decoding the BER must give the
// value the DER gives, and re-encoding either must give the DER.
// Malformed segment structures below must fail to decode.
#include <cstdio>
#include <fstream>
#include <functional>
#include <map>
#include <sstream>
#include <string>
#include <vector>
#include <asn1cpp/asn1cpp.hpp>
#include <asn1cpp/codec/BerProjection.hpp>
#include "Bits.hpp"
#include "Name.hpp"
#include "Plain.hpp"
#include "Tagged.hpp"
#include "Opt.hpp"
#include "OptSet.hpp"
#include "Lab.hpp"
#include "LabChoice.hpp"
#include "Outer.hpp"
#include "Wrapped.hpp"

using namespace asn1;

static int failures = 0;

static void check(const std::string& label, bool cond) {
    if (cond) printf("  \033[32mPASS\033[0m  %s\n", label.c_str());
    else     { printf("  \033[31mFAIL\033[0m  %s\n", label.c_str()); ++failures; }
}

static std::vector<uint8_t> unhex(const std::string& h) {
    std::vector<uint8_t> out;
    for (std::size_t i = 0; i + 1 < h.size(); i += 2)
        out.push_back(static_cast<uint8_t>(std::stoi(h.substr(i, 2), nullptr, 16)));
    return out;
}

static std::string hex(const std::vector<uint8_t>& b) {
    static const char* d = "0123456789ABCDEF";
    std::string s;
    for (uint8_t c : b) { s += d[c >> 4]; s += d[c & 15]; }
    return s;
}

struct Outcome {
    bool ok;
    std::string error;
    std::vector<uint8_t> der;
};

template <typename T>
static Outcome roundtrip(const std::vector<uint8_t>& ber) {
    T v{};
    BerReader r{ber};
    BerDecodeStream ds{r};
    auto res = BerCodec::instance().decode(ds, T::asn_DEF, &v);
    if (!res) return {false, res.error().message, {}};
    if (!r.at_end()) return {false, "trailing octets", {}};
    std::vector<uint8_t> out;
    BerWriter w{out};
    BerEncodeStream es{w};
    BerCodec::instance().encode(es, T::asn_DEF, &v);
    return {true, {}, out};
}

static const std::map<std::string, std::function<Outcome(const std::vector<uint8_t>&)>> TYPES = {
    {"Tagged", roundtrip<Tagged>},
    {"Plain", roundtrip<Plain>},
    {"Bits", roundtrip<Bits>},
    {"Name", roundtrip<Name>},
    {"Wrapped", roundtrip<Wrapped>},
    {"Opt", roundtrip<Opt>},
    {"OptSet", roundtrip<OptSet>},
    {"Lab", roundtrip<Lab>},
    {"LabChoice", roundtrip<LabChoice>},
};

static void vectors(const char* path) {
    std::ifstream f(path);
    std::string line;
    int rows = 0;
    while (std::getline(f, line)) {
        if (line.empty() || line[0] == '#') continue;
        std::istringstream in(line);
        std::string type, source, ber, der;
        std::getline(in, type, '\t');
        std::getline(in, source, '\t');
        std::getline(in, ber, '\t');
        std::getline(in, der, '\t');
        ++rows;
        std::string label = type + " (" + source + ", row " + std::to_string(rows) + ")";
        auto& rt = TYPES.at(type);
        auto from_ber = rt(unhex(ber));
        check(label + ": BER decodes" + (from_ber.ok ? "" : ": " + from_ber.error), from_ber.ok);
        check(label + ": BER re-encodes to asn1c's DER", hex(from_ber.der) == der);
        auto from_der = rt(unhex(der));
        check(label + ": DER re-encodes to itself", from_der.ok && hex(from_der.der) == der);
    }
    check("vector rows read", rows == 6);
}

static void accepted(const std::string& label, const std::string& type,
                     const std::string& ber, const std::string& der) {
    auto o = TYPES.at(type)(unhex(ber));
    check(label + (o.ok ? "" : ": " + o.error), o.ok && hex(o.der) == der);
}

static void refused(const std::string& label, const std::string& type,
                    const std::vector<uint8_t>& ber, const std::string& error) {
    auto o = TYPES.at(type)(ber);
    check(label + ": " + (o.ok ? "decoded" : o.error), !o.ok && o.error.find(error) != std::string::npos);
}

/// The contained value is decoded from the joined segments, not from the
/// segment TLVs.
static void contained() {
    auto ber = unhex("300DA00B04021A0504054A6F6E6573");
    Wrapped v{};
    BerReader r{ber};
    BerDecodeStream ds{r};
    bool ok = BerCodec::instance().decode(ds, Wrapped::asn_DEF, &v).has_value();
    check("CONTAINING value decoded from the joined segments",
          ok && v.c.status() == ContainedStatus::Decoded && v.c.value() && v.c.value()->str() == "Jones");
}

/// BerProjection over constructed leaves (IMPLICIT tagging only): an
/// IMPLICIT-tagged SEQUENCE leaf re-encodes to the same contents shape and
/// commits; an EXPLICIT-tagged leaf is outside the projection model.
static void projection() {
    // Outer { p { o '01'H, b ''B, s "ab" }, x "cd" }
    auto frame = unhex("3012A00A80010181010082026162A10416026364");
    BerProjection proj{Outer::asn_DEF};
    auto hp = proj.add_path("p");
    auto hx = proj.add_path("x");
    proj.finalize();
    BerProjectionResult res{proj};
    Asn1Optional<Tagged> p;
    res.bind(hp, p);
    res.apply(std::span<uint8_t>(frame));
    check("projection: IMPLICIT SEQUENCE leaf found",
          p.found && static_cast<Tagged&>(p).s.str() == "ab");
    static_cast<Tagged&>(p).s.str() = "zz";
    check("projection: IMPLICIT SEQUENCE leaf commits", res.commit(hp));
    check("projection: committed frame",
          hex(frame) == "3012A00A8001018101008202" "7A7A" "A10416026364");

    Asn1Optional<Ia5String> x;
    res.load(hx, x);
    check("projection: EXPLICIT-tagged leaf not found", !x.found);
}

int main(int argc, char** argv) {
    if (argc != 2) { fprintf(stderr, "usage: %s constructed_strings_test.vectors\n", argv[0]); return 2; }
    vectors(argv[1]);

    accepted("empty constructed VisibleString", "Name", "3A00", "1A00");
    accepted("empty constructed indefinite VisibleString", "Name", "3A800000", "1A00");
    accepted("empty constructed BIT STRING", "Bits", "2300", "030100");
    accepted("nested constructed segment", "Name", "3A0B240504034A6F6E04026573", "1A054A6F6E6573");
    accepted("nested indefinite segment", "Name", "3A80248004034A6F6E0000040265730000", "1A054A6F6E6573");
    accepted("segments at several nesting levels", "Name",
             "3A80248004014124800401420000040143000024060401440401450401460000", "1A06414243444546");
    accepted("CONTAINING value split across segments", "Wrapped",
             "300DA00B04021A0504054A6F6E6573", "300980071A054A6F6E6573");
    accepted("BIT STRING, unused bits in the last segment", "Bits", "230803020080030205E0", "03030580E0");
    accepted("constructed OPTIONAL and extension members", "Opt",
             "3080A08004024A6F04016E0000A2070402ABCD0401EF0000", "300A80034A6F6E8203ABCDEF");
    accepted("constructed OPTIONAL character string", "Opt", "3080A10504034A6F6E0000", "300581034A6F6E");
    accepted("SET members out of order, one constructed", "OptSet",
             "310AA1050403414243800141", "31088001418103414243");
    accepted("IMPLICIT tag on EXPLICIT-tagged types", "Lab",
             "301EA8050C03616263A30F170D3234303130313132303030305AA60404020102", "301EA8050C03616263A30F170D3234303130313132303030305AA60404020102");
    accepted("IMPLICIT tag on an EXPLICIT-tagged type, inner value segmented", "Lab",
             "3022A8050C03616263A30F170D3234303130313132303030305AA6082406040101040102", "301EA8050C03616263A30F170D3234303130313132303030305AA60404020102");
    accepted("CHOICE alternative: IMPLICIT tag on an EXPLICIT-tagged type", "LabChoice",
             "A8050C03616263", "A8050C03616263");

    refused("character string segment with its own tag", "Name", unhex("3A051A034A6F6E"),
            "segment of a constructed string is not an OCTET STRING");
    refused("BIT STRING segment with an OCTET STRING tag", "Bits", unhex("2304040200FF"),
            "segment of a constructed BIT STRING is not a BIT STRING");
    refused("end-of-contents in a definite constructed string", "Name", unhex("3A0404000000"),
            "segment of a constructed string is not an OCTET STRING");
    refused("unused bits before the last BIT STRING segment", "Bits", unhex("230803020180030200FF"),
            "BIT STRING segment other than the last has unused bits");
    refused("BIT STRING segment without its unused-bits octet", "Bits", unhex("23020300"),
            "BIT STRING segment is empty");
    refused("BIT STRING segment with unused bits and no octets", "Bits", unhex("2303030103"),
            "BIT STRING segment has 3 unused bits in 0 octets");
    refused("IMPLICIT member segment with the member's tag", "Tagged", unhex("300DA00680044A6F6E658101008200"),
            "segment of a constructed string is not an OCTET STRING");

    contained();
    projection();

    // asn1c's limit: 29 nested segments inside the string decode, 30 do not.
    auto nested = [](int n) {
        std::vector<uint8_t> v{0x3A, 0x80};
        for (int i = 0; i < n; ++i) { v.push_back(0x24); v.push_back(0x80); }
        v.insert(v.end(), {0x04, 0x01, 0x41});
        for (int i = 0; i <= n; ++i) { v.push_back(0); v.push_back(0); }
        return v;
    };
    accepted("segments nested 29 deep", "Name", hex(nested(29)), "1A0141");
    refused("segments nested 30 deep", "Name", nested(30), "constructed string segments nest deeper than 30 levels");
    refused("segments nested 300 deep", "Name", nested(300), "constructed string segments nest deeper than 30 levels");

    printf("%s\n", failures ? "FAILED" : "all passed");
    return failures ? 1 : 0;
}
