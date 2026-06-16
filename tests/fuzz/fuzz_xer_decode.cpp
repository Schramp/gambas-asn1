// XER decode fuzz harness and corpus-replay driver.
//
// Schema: 70-xer-test-OK.asn1 — PDU is a CHOICE covering Sequence (recursive),
// Set (RELATIVE-OID + OCTET STRING), ExtensibleSequence, SetOfNULL/REAL/Enums,
// and many other types.  Feeding arbitrary bytes into the XER decoder exercises
// XML parsing, entity unescaping, element dispatch, and type conversion.
//
// Two build modes:
//   fuzz_xer_corpus_replay — standalone; reads .in files from argv.
//   fuzz_xer_decode        — libfuzzer target (FUZZ_DRIVER defined, -fsanitize=fuzzer).
//
// Both must not crash on any input.

#include <cstdint>
#include <cstdio>
#include <cstdlib>
#include <filesystem>
#include <fstream>
#include <string>
#include <asn1cpp/asn1cpp.hpp>
#include "PDU.hpp"

using namespace asn1;
namespace fs = std::filesystem;

static void decode_one(const uint8_t* data, std::size_t size) {
    std::string xml(reinterpret_cast<const char*>(data), size);
    PDU obj{};
    XerDecodeStream s{xml};
    (void)XerCodec::instance().decode(s, PDU::asn_DEF, &obj);
}

extern "C" int LLVMFuzzerTestOneInput(const uint8_t* data, std::size_t size) {
    decode_one(data, size);
    return 0;
}

#ifndef FUZZ_DRIVER
int main(int argc, char* argv[]) {
    if (argc < 2) {
        std::fprintf(stderr, "Usage: %s <corpus-dir-or-file>...\n", argv[0]);
        return 1;
    }
    std::size_t total = 0;
    std::size_t open_errors = 0;

    auto process_file = [&](const fs::path& fp) {
        std::ifstream f(fp, std::ios::binary);
        if (!f) { ++open_errors; return; }
        std::string content((std::istreambuf_iterator<char>(f)), {});
        decode_one(reinterpret_cast<const uint8_t*>(content.data()), content.size());
        ++total;
    };

    for (int i = 1; i < argc; ++i) {
        fs::path p{argv[i]};
        if (fs::is_directory(p)) {
            for (const auto& entry : fs::directory_iterator(p)) {
                auto ext = entry.path().extension().string();
                if (ext == ".in" || ext == ".xer" || ext == ".xml")
                    process_file(entry.path());
            }
        } else {
            process_file(p);
        }
    }

    std::printf("Decoded %zu XER file(s) without crash", total);
    if (open_errors)
        std::printf(" (%zu file(s) failed to open)", open_errors);
    std::printf("\n");
    return open_errors ? 1 : 0;
}
#endif // FUZZ_DRIVER
