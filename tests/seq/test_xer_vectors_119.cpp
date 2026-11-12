// XER→UPER→XER vector test: asn1c data-119 suite (schema 119-per-strings-OK.asn1).
//
// Mirrors asn1c check-119.c logic:
//   Each .in file is XER-decoded, UPER-encoded, UPER-decoded, then XER-re-encoded,
//   and the result is compared to the original using whitespace-stripped equality.
//
//   - (none) files: round-trip must succeed; output must equal input (whitespace-stripped).
//   - -P files: PER-incompatible input (alphabet/size constraint violation);
//               PerCodec must reject them (encode returns failed=true).
//
// The suite ships no UPER for its inputs, so the round trip alone cannot
// tell a wrong encoding shared by encoder and decoder from a right one.
// tests/vectors/per_strings_119.vectors holds asn1c's UPER for every non -P
// input; the encoding must equal it, and decoding it must give the input.
#include <cctype>
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

// -P files (asn1c's naming): PER-incompatible by design (alphabet or SIZE
// constraint violation). PerCodec must reject them — encode returns failed=true.
static bool is_p_file(const std::string& name) {
    return name.size() >= 5 && name.compare(name.size() - 5, 5, "-P.in") == 0;
}

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
    bool is_p = is_p_file(name);

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

static std::vector<uint8_t> from_hex(const std::string& hex) {
    std::vector<uint8_t> out;
    for (std::size_t i = 0; i + 1 < hex.size(); i += 2)
        out.push_back(static_cast<uint8_t>(std::stoi(hex.substr(i, 2), nullptr, 16)));
    return out;
}

// asn1c's UPER for each non -P input (tests/vectors/per_strings_119.vectors,
// made by make_ber_vectors.py): our encoding must equal it byte for byte,
// and decoding it must give the input value back.
static std::size_t check_vectors(const char* path) {
    std::ifstream f(path);
    check("per_strings_119.vectors readable", f.good());
    std::string line;
    std::size_t n = 0;
    while (std::getline(f, line)) {
        if (line.empty() || line[0] == '#') continue;
        std::vector<std::string> col;
        std::size_t start = 0;
        for (std::size_t tab; (tab = line.find('\t', start)) != std::string::npos; start = tab + 1)
            col.push_back(line.substr(start, tab - start));
        col.push_back(line.substr(start));
        ++n;
        char label[256];
        std::snprintf(label, sizeof label, "vector %zu  has asn1c UPER", n);
        check(label, col.size() == 6 && col[5] != "-");
        if (col.size() != 6 || col[5] == "-") continue;
        const std::vector<uint8_t> asn1c = from_hex(col[5]);

        PDU val{};
        std::snprintf(label, sizeof label, "vector %zu  XER decode ok", n);
        check(label, xer_decode(col[1], val));
        auto [per, per_failed] = per_encode(val);
        std::snprintf(label, sizeof label, "vector %zu  UPER encode == asn1c (%zu octets)", n, asn1c.size());
        check(label, !per_failed && per == asn1c);

        PDU back{};
        bool ok = per_decode(asn1c, back);
        std::snprintf(label, sizeof label, "vector %zu  asn1c UPER decodes to the input", n);
        check(label, ok && strip_ws(xer_encode(back)) == strip_ws(col[1]));
    }
    return n;
}

int main(int argc, char** argv) {
    const char* datadir = argc > 1 ? argv[1]
                                   : "tests/tests-c-compiler/data-119";
    const char* vectors = argc > 2 ? argv[2]
                                   : "tests/vectors/per_strings_119.vectors";

    printf("\n── XER→UPER→XER vectors: data-119 (schema 119-per-strings-OK.asn1) ──\n");

    std::vector<fs::path> files;
    for (auto& e : fs::directory_iterator(datadir)) {
        if (e.path().extension() == ".in" &&
            e.path().filename().string().substr(0, 9) == "data-119-")
            files.push_back(e.path());
    }
    std::sort(files.begin(), files.end());

    std::size_t p_files = 0;
    for (auto& f : files) {
        process(f);
        if (is_p_file(f.filename().string())) ++p_files;
    }

    printf("\n── asn1c UPER vectors (%s) ──\n", vectors);
    std::size_t rows = check_vectors(vectors);
    char label[160];
    std::snprintf(label, sizeof label, "one vector per non -P input (%zu vectors, %zu inputs)",
                  rows, files.size() - p_files);
    check(label, rows == files.size() - p_files);

    printf("\n  Processed %zu files (%zu -P constraint checks), %zu asn1c vectors, %d failed.\n",
           files.size(), p_files, rows, failures);
    if (failures) return 1;
    printf("  All tests passed.\n");
    return 0;
}
