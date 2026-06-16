// BER decode fuzz harness and corpus-replay driver.
//
// Schema: 62-any-OK.asn1 — T is a CHOICE covering SEQUENCE (with ANY),
// tagged SEQUENCE, SET, and tagged CHOICE.  Feeding arbitrary bytes into
// the T decoder exercises CHOICE dispatch, SEQUENCE/SET decode, optional
// members, EXPLICIT/IMPLICIT tags, ANY raw-byte storage, and indefinite-length
// handling.
//
// Two build modes:
//   fuzz_ber_corpus_replay — standalone; iterates .ber files from argv.
//   fuzz_ber_decode        — libfuzzer target (FUZZ_DRIVER defined, -fsanitize=fuzzer).
//
// Both must not crash on any input.  Decode failure is expected for malformed
// inputs and is fine; what must never happen is SIGABRT / SIGSEGV / assertion.

#include <cstdint>
#include <cstdio>
#include <cstdlib>
#include <filesystem>
#include <fstream>
#include <span>
#include <vector>
#include <asn1cpp/asn1cpp.hpp>
#include "T.hpp"

using namespace asn1;
namespace fs = std::filesystem;

// Feed `size` bytes at `data` into the BER decoder as type T.
// Returns silently regardless of decode outcome — crash = bug.
static void decode_one(const uint8_t* data, std::size_t size) {
    T obj{};
    BerReader r{std::span<const uint8_t>{data, size}};
    BerDecodeStream s{r};
    (void)BerCodec::instance().decode(s, T::asn_DEF, &obj);
}

// libfuzzer entry point — must be `extern "C"` and return 0.
extern "C" int LLVMFuzzerTestOneInput(const uint8_t* data, std::size_t size) {
    decode_one(data, size);
    return 0;
}

#ifndef FUZZ_DRIVER
// Standalone corpus-replay mode: not built with a fuzzer driver.
// Reads every .ber file from each directory (or individual file) in argv.
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
        std::vector<uint8_t> data((std::istreambuf_iterator<char>(f)), {});
        decode_one(data.data(), data.size());
        ++total;
    };

    for (int i = 1; i < argc; ++i) {
        fs::path p{argv[i]};
        if (fs::is_directory(p)) {
            for (const auto& entry : fs::directory_iterator(p))
                if (entry.path().extension() == ".ber")
                    process_file(entry.path());
        } else {
            process_file(p);
        }
    }

    std::printf("Decoded %zu BER file(s) without crash", total);
    if (open_errors)
        std::printf(" (%zu file(s) failed to open)", open_errors);
    std::printf("\n");
    return open_errors ? 1 : 0;
}
#endif // FUZZ_DRIVER
