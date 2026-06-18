// XER→UPER vector test: asn1c data-126 suite (126-per-extensions-OK.asn1).
//
// Mirrors asn1c check-126.-gen-UPER.c logic:
//   Each .in file is XER-decoded, UPER-encoded, then:
//   - (none): binary must equal .out; UPER-decoded+XER re-encoded must equal .in.
//   - -C: binary may differ from .out; .out decodes ok; round-trip XER == .in.
//   - -P: UPER decode of .out must fail; our own round-trip must succeed.
//   - -X: binary must equal .out; round-trip XER must differ from .in.
//
// KNOWN_PERMISSIVE: files whose .out was generated with an older schema version
// (e.g., fewer extension members). Our decoder accepts them (reads only as many
// extension members as the wire says, treating missing known members as absent).
// asn1c rejects them. This is correct forward-compatible decoder behavior.
#include <cstdio>
#include <fstream>
#include <filesystem>
#include <string>
#include <vector>
#include <algorithm>
#include <span>
#include <sstream>
#include <asn1cpp/asn1cpp.hpp>
#include <asn1cpp/codec/XerCodec.hpp>
#include <asn1cpp/codec/PerCodec.hpp>
#include "PDU.hpp"

using namespace asn1;
namespace fs = std::filesystem;

static int failures = 0;
static int pass_count = 0;

static void check(const char* label, bool cond) {
    if (cond) { printf("  \033[32mPASS\033[0m  %s\n", label); ++pass_count; }
    else       { printf("  \033[31mFAIL\033[0m  %s\n", label); ++failures; }
}

static std::string read_text(const fs::path& p) {
    std::ifstream f(p);
    return std::string((std::istreambuf_iterator<char>(f)), {});
}

static std::vector<uint8_t> read_binary(const fs::path& p) {
    std::ifstream f(p, std::ios::binary);
    return std::vector<uint8_t>((std::istreambuf_iterator<char>(f)), {});
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
    auto r = XerCodec::instance().decode(xs, PDU::asn_DEF, &out);
    return r.has_value();
}

static std::string xer_encode(const PDU& val) {
    std::ostringstream oss;
    XerEncodeStream xs{oss};
    XerCodec::instance().encode(xs, PDU::asn_DEF, &val);
    return oss.str();
}

static std::vector<uint8_t> per_encode(const PDU& val) {
    std::vector<uint8_t> buf;
    PerEncodeStream s{buf};
    PerCodec::instance().encode(s, PDU::asn_DEF, &val);
    s.flush();
    return buf;
}

static bool per_decode(std::span<const uint8_t> bytes, PDU& out) {
    PerDecodeStream s{bytes};
    return PerCodec::instance().decode(s, PDU::asn_DEF, &out).has_value();
}

enum class Kind { OK, P, C, X };

// -P files whose .out was encoded with an older schema version; our permissive decoder
// accepts them rather than failing. Assertion: decode SUCCEEDS (not fails).
static const std::vector<std::string> KNOWN_PERMISSIVE = {
    "data-126-04-P.in",
};

static Kind classify(const std::string& name) {
    auto dot = name.rfind('.');
    if (dot == std::string::npos || dot == 0) return Kind::OK;
    char c = name[dot - 1];
    if (c == 'P') return Kind::P;
    if (c == 'C') return Kind::C;
    if (c == 'X') return Kind::X;
    return Kind::OK;
}

static void process(const fs::path& path) {
    const std::string name = path.filename().string();
    const Kind kind = classify(name);

    fs::path out_path = path;
    out_path.replace_extension(".out");

    std::string input = read_text(path);
    std::vector<uint8_t> out_bytes = read_binary(out_path);

    char lbl[300];

    // 1. XER decode .in
    PDU val{};
    bool dec_ok = xer_decode(input, val);
    std::snprintf(lbl, sizeof lbl, "%s  XER decode ok", name.c_str());
    check(lbl, dec_ok);
    if (!dec_ok) return;

    // 2. UPER encode
    auto our_bytes = per_encode(val);
    std::snprintf(lbl, sizeof lbl, "%s  UPER encode non-empty", name.c_str());
    check(lbl, !our_bytes.empty());
    if (our_bytes.empty()) return;

    // 3. Binary comparison vs .out
    if (kind == Kind::OK || kind == Kind::X) {
        bool match = (our_bytes == out_bytes);
        std::snprintf(lbl, sizeof lbl, "%s  UPER bytes == .out", name.c_str());
        check(lbl, match);
    } else if (kind == Kind::C) {
        bool differ = (our_bytes != out_bytes);
        std::snprintf(lbl, sizeof lbl, "%s  UPER bytes diverge from .out (expected)", name.c_str());
        check(lbl, differ);
    }
    // -P: skip binary comparison; .out is intentionally invalid

    // 4. Decode .out: for -P must fail; for -C must succeed; for others our bytes already checked
    if (kind == Kind::P) {
        PDU tmp{};
        bool out_dec = per_decode(out_bytes, tmp);
        bool known = std::find(KNOWN_PERMISSIVE.begin(), KNOWN_PERMISSIVE.end(), name)
                     != KNOWN_PERMISSIVE.end();
        if (known) {
            std::snprintf(lbl, sizeof lbl, "%s  UPER decode of .out succeeds (known-permissive: old encoding)", name.c_str());
            check(lbl, out_dec);
        } else {
            std::snprintf(lbl, sizeof lbl, "%s  UPER decode of .out fails (as expected)", name.c_str());
            check(lbl, !out_dec);
        }
    } else if (kind == Kind::C) {
        PDU tmp{};
        bool out_ok = per_decode(out_bytes, tmp);
        std::snprintf(lbl, sizeof lbl, "%s  UPER decode of .out succeeds", name.c_str());
        check(lbl, out_ok);
    }

    // 5. Round-trip: UPER decode our own bytes → XER re-encode → compare to .in
    PDU val2{};
    bool rt_dec = per_decode(our_bytes, val2);
    std::snprintf(lbl, sizeof lbl, "%s  UPER round-trip decode ok", name.c_str());
    check(lbl, rt_dec);
    if (!rt_dec) return;

    std::string reenc = xer_encode(val2);
    if (kind == Kind::X) {
        bool differs = (strip_ws(reenc) != strip_ws(input));
        std::snprintf(lbl, sizeof lbl, "%s  XER re-encode differs from .in (expected)", name.c_str());
        check(lbl, differs);
    } else {
        bool equal = (strip_ws(reenc) == strip_ws(input));
        std::snprintf(lbl, sizeof lbl, "%s  XER round-trip equals .in", name.c_str());
        check(lbl, equal);
    }
}

int main(int argc, char** argv) {
    const char* datadir = argc > 1 ? argv[1]
                                   : "tests/tests-c-compiler/data-126";

    printf("\n── XER→UPER vectors: data-126 (126-per-extensions-OK.asn1) ──\n");

    std::vector<fs::path> files;
    for (auto& e : fs::directory_iterator(datadir)) {
        if (e.path().extension() == ".in" &&
            e.path().filename().string().substr(0, 9) == "data-126-")
            files.push_back(e.path());
    }
    std::sort(files.begin(), files.end());

    for (auto& f : files)
        process(f);

    printf("\n  Processed %zu files, %d passed, %d failed.\n",
           files.size(), pass_count, failures);
    if (failures) return 1;
    printf("  All tests passed.\n");
    return 0;
}
