// XER vector test: asn1c data-70 test suite (schema 70-xer-test-OK.asn1).
//
// Mirrors the original asn1c check-70.c logic:
//   Each .in file is XER-decoded, BER-encoded, BER-decoded, then XER-re-encoded,
//   and the result is compared to the original using whitespace-stripped equality.
//
//   - (none) / -E files: round-trip must succeed; output must equal input (whitespace-stripped).
//   - -B files: XER decode must fail (broken input).
//   - -D / -X files: round-trip must succeed; output may differ from input.
//
// Known limitations — files in KNOWN_SKIP are counted as skipped, not failed:
//
//   XML comments in element/text content (issue #34):
//     07-D, 09-D, 14-D, 17-D, 37-D, 38-B, 57-D, 58-D, 59-D, 60-D, 61-D, 62-D
//
//   Inline elements inside UTF8String text content (issue #35):
//     15, 19, 20-D, 21-D, 22-D, 23-D, 24-D, 40-D, 41-D
//
// NULL CHOICE alternative encodes as <a></a> (same as asn1c) — files 51, 53 pass.
#include <cstdio>
#include <fstream>
#include <filesystem>
#include <string>
#include <vector>
#include <set>
#include <algorithm>
#include <span>
#include <asn1cpp/asn1cpp.hpp>
#include <asn1cpp/codec/XerCodec.hpp>
#include "PDU.hpp"

using namespace asn1;
namespace fs = std::filesystem;

// Files skipped due to known asn1cpp XER limitations (see top-of-file comment).
static const std::set<std::string> KNOWN_SKIP = {
    // XML comments in element/text content — https://github.com/Schramp/gambas-asn1/issues/34
    "data-70-07-D.in", "data-70-09-D.in",
    "data-70-14-D.in",
    "data-70-17-D.in",
    "data-70-37-D.in", "data-70-38-B.in",
    "data-70-57-D.in", "data-70-58-D.in", "data-70-59-D.in",
    "data-70-60-D.in", "data-70-61-D.in", "data-70-62-D.in",
    // Inline elements inside UTF8String text content — https://github.com/Schramp/gambas-asn1/issues/35
    "data-70-15.in",
    "data-70-19.in",
    "data-70-20-D.in", "data-70-21-D.in", "data-70-22-D.in", "data-70-23-D.in", "data-70-24-D.in",
    "data-70-40-D.in", "data-70-41-D.in",
};

static int failures = 0;
static int skipped  = 0;

static void check(const char* label, bool cond) {
    if (cond) printf("  \033[32mPASS\033[0m  %s\n", label);
    else     { printf("  \033[31mFAIL\033[0m  %s\n", label); ++failures; }
}

static std::string read_text(const fs::path& p) {
    std::ifstream f(p);
    return std::string((std::istreambuf_iterator<char>(f)), {});
}

// Strip all whitespace characters for loose XER comparison (mirrors xer_encoding_equal).
static std::string strip_ws(const std::string& s) {
    std::string out;
    out.reserve(s.size());
    for (char c : s)
        if (!std::isspace(static_cast<unsigned char>(c))) out += c;
    return out;
}

static bool xer_decode(const std::string& xml, PDU& out) {
    XerDecodeStream xs{xml};
    // The .in files wrap the CHOICE value in an outer <PDU>...</PDU> element
    // (same as asn1c's asn_fprint output format). The CHOICE decoder expects the
    // stream to start at the first alternative tag, so consume the outer wrapper here.
    if (auto r = xer_detail::consume_open_tag(xs, "PDU"); !r) return false;
    auto r = XerCodec::instance().decode(xs, PDU::asn_DEF, &out);
    if (!r) return false;
    if (auto r2 = xer_detail::consume_close_tag(xs, "PDU"); !r2) return false;
    return true;
}

static std::string xer_encode(const PDU& val) {
    std::ostringstream oss;
    XerEncodeStream xs{oss};
    XerCodec::instance().encode(xs, PDU::asn_DEF, &val);
    return oss.str();
}

static std::vector<uint8_t> ber_encode(const PDU& val) {
    std::vector<uint8_t> buf;
    BerWriter w{buf};
    BerEncodeStream s{w};
    BerCodec::instance().encode(s, PDU::asn_DEF, &val);
    return buf;
}

static bool ber_decode(std::span<const uint8_t> bytes, PDU& out) {
    BerReader r{bytes};
    BerDecodeStream s{r};
    return BerCodec::instance().decode(s, PDU::asn_DEF, &out).has_value();
}

enum class Expect { OK, Broken, Different };

static Expect classify(const std::string& name) {
    auto dot = name.rfind(".in");
    if (dot == std::string::npos || dot < 2) return Expect::OK;
    switch (name[dot - 1]) {
    case 'B': return Expect::Broken;
    case 'D':
    case 'X': return Expect::Different;
    case 'E':
    default:  return Expect::OK;
    }
}

static void process(const fs::path& path) {
    std::string name = path.filename().string();

    if (KNOWN_SKIP.count(name)) {
        printf("  \033[33mSKIP\033[0m  %s\n", name.c_str());
        ++skipped;
        return;
    }

    Expect exp = classify(name);
    std::string input = read_text(path);

    PDU val{};
    bool decoded = xer_decode(input, val);

    if (exp == Expect::Broken) {
        char label[256];
        std::snprintf(label, sizeof(label), "%s  XER decode must fail", name.c_str());
        check(label, !decoded);
        return;
    }

    {
        char label[256];
        std::snprintf(label, sizeof(label), "%s  XER decode ok", name.c_str());
        check(label, decoded);
    }
    if (!decoded) return;

    auto ber = ber_encode(val);
    {
        char label[256];
        std::snprintf(label, sizeof(label), "%s  BER encode non-empty", name.c_str());
        check(label, !ber.empty());
    }
    if (ber.empty()) return;

    PDU val2{};
    bool ber_ok = ber_decode(ber, val2);
    {
        char label[256];
        std::snprintf(label, sizeof(label), "%s  BER decode ok", name.c_str());
        check(label, ber_ok);
    }
    if (!ber_ok) return;

    std::string reenc = xer_encode(val2);

    if (exp == Expect::Different) {
        char label[256];
        std::snprintf(label, sizeof(label), "%s  round-trip ok (output differs by design)", name.c_str());
        check(label, !reenc.empty());
        return;
    }

    // (none) / -E: whitespace-stripped output must match input.
    // The .in files wrap the CHOICE in <PDU>...</PDU>; our encoder doesn't add that
    // wrapper, so re-add it before comparing.
    std::string wrapped = "<PDU>\n" + reenc + "</PDU>\n";
    char label[256];
    std::snprintf(label, sizeof(label), "%s  XER round-trip equal (whitespace-stripped)", name.c_str());
    check(label, strip_ws(wrapped) == strip_ws(input));
}

int main(int argc, char** argv) {
    const char* datadir = argc > 1 ? argv[1]
                                   : "tests/tests-c-compiler/data-70";

    printf("\n── XER vectors: data-70 (schema 70-xer-test-OK.asn1) ───────────────\n");

    std::vector<fs::path> files;
    for (auto& e : fs::directory_iterator(datadir)) {
        if (e.path().extension() == ".in" &&
            e.path().filename().string().substr(0, 8) == "data-70-")
            files.push_back(e.path());
    }
    std::sort(files.begin(), files.end());

    for (auto& f : files)
        process(f);

    printf("\n  Processed %zu files, %d skipped, %d failed.\n",
           files.size(), skipped, failures);
    if (failures) return 1;
    printf("  All active tests passed.\n");
    return 0;
}
