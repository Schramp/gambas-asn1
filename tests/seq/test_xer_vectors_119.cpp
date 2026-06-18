// XER→UPER→XER vector test: asn1c data-119 suite (schema 119-per-strings-OK.asn1).
//
// Mirrors asn1c check-119.c logic:
//   Each .in file is XER-decoded, UPER-encoded, UPER-decoded, then XER-re-encoded,
//   and the result is compared to the original using whitespace-stripped equality.
//
//   - (none) files: round-trip must succeed; output must equal input (whitespace-stripped).
//   - -P files: PER-incompatible input (alphabet/size constraint violation);
//               PerCodec must reject them (encode returns failed=true).
#include <cstdio>
#include <fstream>
#include <filesystem>
#include <string>
#include <vector>
#include <set>
#include <algorithm>
#include <span>
#include <sstream>
#include <asn1cpp/asn1cpp.hpp>
#include <asn1cpp/codec/XerCodec.hpp>
#include <asn1cpp/codec/PerCodec.hpp>
#include "PDU.hpp"

using namespace asn1;
namespace fs = std::filesystem;

// -P files: PER-incompatible by design (alphabet or SIZE constraint violation).
// PerCodec must reject them — encode returns failed=true.
static const std::set<std::string> KNOWN_P = {
    "data-119-04-P.in",
    "data-119-06-P.in",
    "data-119-07-P.in",
    "data-119-10-P.in",
    "data-119-11-P.in",
    "data-119-12-P.in",
    "data-119-13-P.in",
    "data-119-14-P.in",
    "data-119-20-P.in",
    "data-119-21-P.in",
    "data-119-22-P.in",
    "data-119-23-P.in",
    "data-119-24-P.in",
    "data-119-25-P.in",
};

static int failures = 0;

static void check(const char* label, bool cond) {
    if (cond) printf("  \033[32mPASS\033[0m  %s\n", label);
    else     { printf("  \033[31mFAIL\033[0m  %s\n", label); ++failures; }
}

static std::string read_text(const fs::path& p) {
    std::ifstream f(p);
    return std::string((std::istreambuf_iterator<char>(f)), {});
}

static std::string strip_ws(const std::string& s) {
    std::string out;
    out.reserve(s.size());
    for (char c : s)
        if (!std::isspace(static_cast<unsigned char>(c))) out += c;
    return out;
}

static bool xer_decode(const std::string& xml, PDU& out) {
    XerDecodeStream xs{xml};
    // SEQUENCE decoder reads its own outer <PDU> and </PDU> tags.
    auto r = XerCodec::instance().decode(xs, PDU::asn_DEF, &out);
    return r.has_value();
}

static std::string xer_encode(const PDU& val) {
    std::ostringstream oss;
    XerEncodeStream xs{oss};
    XerCodec::instance().encode(xs, PDU::asn_DEF, &val);
    return oss.str();
}

struct PerEncodeResult { std::vector<uint8_t> buf; bool failed; };

static PerEncodeResult per_encode(const PDU& val) {
    std::vector<uint8_t> buf;
    PerEncodeStream s{buf};
    PerCodec::instance().encode(s, PDU::asn_DEF, &val);
    bool failed = s.encode_failed();
    if (!failed) s.flush();
    return {std::move(buf), failed};
}

static bool per_decode(std::span<const uint8_t> bytes, PDU& out) {
    PerDecodeStream s{bytes};
    return PerCodec::instance().decode(s, PDU::asn_DEF, &out).has_value();
}

static void process(const fs::path& path) {
    std::string name = path.filename().string();
    bool is_p = KNOWN_P.count(name) > 0;

    std::string input = read_text(path);

    PDU val{};
    bool decoded = xer_decode(input, val);
    {
        char label[256];
        std::snprintf(label, sizeof(label), "%s  XER decode ok", name.c_str());
        check(label, decoded);
    }
    if (!decoded) return;

    auto [per, per_failed] = per_encode(val);
    if (is_p) {
        char label[256];
        std::snprintf(label, sizeof(label), "%s  UPER encode rejected (constraint violation)", name.c_str());
        check(label, per_failed);
        return;
    }

    {
        char label[256];
        std::snprintf(label, sizeof(label), "%s  UPER encode non-empty", name.c_str());
        check(label, !per.empty() && !per_failed);
    }
    if (per.empty() || per_failed) return;

    PDU val2{};
    bool per_ok = per_decode(per, val2);
    {
        char label[256];
        std::snprintf(label, sizeof(label), "%s  UPER decode ok", name.c_str());
        check(label, per_ok);
    }
    if (!per_ok) return;

    // xer_encode (SEQUENCE) already includes the outer <PDU>...</PDU> wrapper.
    std::string reenc = xer_encode(val2);
    {
        char label[256];
        std::snprintf(label, sizeof(label), "%s  XER round-trip equal (whitespace-stripped)", name.c_str());
        check(label, strip_ws(reenc) == strip_ws(input));
    }
}

int main(int argc, char** argv) {
    const char* datadir = argc > 1 ? argv[1]
                                   : "tests/tests-c-compiler/data-119";

    printf("\n── XER→UPER→XER vectors: data-119 (schema 119-per-strings-OK.asn1) ──\n");

    std::vector<fs::path> files;
    for (auto& e : fs::directory_iterator(datadir)) {
        if (e.path().extension() == ".in" &&
            e.path().filename().string().substr(0, 9) == "data-119-")
            files.push_back(e.path());
    }
    std::sort(files.begin(), files.end());

    for (auto& f : files)
        process(f);

    printf("\n  Processed %zu files (%zu -P constraint checks), %d failed.\n",
           files.size(), KNOWN_P.size(), failures);
    if (failures) return 1;
    printf("  All tests passed.\n");
    return 0;
}
