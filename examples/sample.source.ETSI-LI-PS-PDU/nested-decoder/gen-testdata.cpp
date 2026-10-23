/*
 * gen-testdata.cpp
 *
 * Writes the nested-decoder regression input: a stream of BER-encoded
 * PS-PDU records made by RandomFiller with a fixed seed, so the test data
 * contains no captured traffic. Records over kMaxRecord octets are drawn
 * again, keeping the file small. Every third record carries an
 * EncryptionContainer with encryptionType `none`, whose encryptedPayload
 * holds a random EncryptedPayload plus zero padding (container_fields.json),
 * so the decoder's inner pass has work to do.
 *
 * The output is committed (pdu-00000001.etsi) rather than regenerated in
 * CI: the values std::uniform_*_distribution produces are
 * implementation-defined across standard libraries.
 *
 * Usage: gen-testdata <out.etsi> [count] [seed]
 */

#include <cstdio>
#include <cstdlib>
#include <random>
#include <vector>

#include <asn1cpp/asn1cpp.hpp>
#include <asn1cpp/codec/RandomFiller.hpp>

#include "EncryptionContainer.hpp"
#include "PS_PDU.hpp"

static constexpr std::size_t kMaxRecord = 2048;

/// One random PS-PDU, BER-encoded into rec; with encrypted, its payload is
/// an EncryptionContainer of encryptionType `none`.
static bool make_record(asn1::RandomFiller& filler, bool encrypted, std::vector<uint8_t>& rec)
{
    PS_PDU pdu{};
    if (!filler.fill(&pdu, PS_PDU::asn_DEF, 0, true)) return false;
    if (encrypted) {
        pdu.payload.set_present(Payload::PR::encryptionContainer);
        auto& ec = pdu.payload.encryptionContainer();
        if (!filler.fill(&ec, EncryptionContainer::asn_DEF, 1, true)) return false;
        ec.encryptionType = EncryptionType::none;
    }
    rec.clear();
    asn1::BerWriter w(rec);
    asn1::BerEncodeStream s{w};
    asn1::BerCodec::instance().encode(s, PS_PDU::asn_DEF, &pdu);
    return !w.encode_failed();
}

int main(int argc, char* argv[])
{
    if (argc < 2) {
        std::fprintf(stderr, "Usage: %s <out.etsi> [count] [seed]\n", argv[0]);
        return 1;
    }
    int count = argc > 2 ? std::atoi(argv[2]) : 12;
    unsigned seed = argc > 3 ? static_cast<unsigned>(std::atoi(argv[3])) : 42;

    std::mt19937 rng(seed);
    asn1::FillConfig cfg;
    // Small records: the expected output is reviewed as text.
    cfg.max_depth = 4;
    cfg.max_seq_of = 1;
    cfg.max_str_len = 8;
    asn1::RandomFiller filler(rng, cfg);

    std::vector<uint8_t> out;
    for (int i = 0; i < count; ++i) {
        std::vector<uint8_t> rec;
        do {
            if (!make_record(filler, i % 3 == 0, rec)) {
                std::fprintf(stderr, "record %d: random fill or BER encode failed\n", i + 1);
                return 1;
            }
        } while (rec.size() > kMaxRecord);
        out.insert(out.end(), rec.begin(), rec.end());
    }

    std::FILE* f = std::fopen(argv[1], "wb");
    if (!f) { std::perror(argv[1]); return 1; }
    std::fwrite(out.data(), 1, out.size(), f);
    std::fclose(f);
    std::fprintf(stderr, "Wrote %d PS-PDU records (%zu bytes) to %s\n", count, out.size(), argv[1]);
    return 0;
}
