/*
 * nested-decoder.cpp
 *
 * C++ port of etsi-li-ps-pdu-nested.c using asn1cpp-generated types.
 *
 * Reads a stream of BER-encoded PS-PDU records from a file.
 * For each PDU whose payload is an EncryptionContainer, the
 * encryptedPayload OCTET STRING is itself a BER-encoded EncryptedPayload
 * wrapped in a zero-padded block.  strip_and_decode() strips trailing zeros
 * and BER-decodes the inner EncryptedPayload as a second, independent step.
 */

#include <cstdio>
#include <cstdlib>
#include <iostream>
#include <vector>
#include <span>

#include <asn1cpp/asn1cpp.hpp>
#include <asn1cpp/codec/XerCodec.hpp>

#include "PS_PDU.hpp"
#include "EncryptedPayload.hpp"

using asn1::BerReader;
using asn1::BerCodec;
using asn1::BerDecodeStream;
using asn1::XerCodec;
using asn1::XerEncodeStream;

static void xer_print(const asn1::TypeDescriptor& def, const asn1::Asn1Object* val)
{
    XerEncodeStream s(std::cout);
    XerCodec::instance().encode(s, def, val);
}

static bool strip_and_decode(const asn1::OctetString& blob)
{
    auto data = blob.bytes();

    if (data.empty()) {
        std::fprintf(stderr, "  inner: empty blob\n");
        return false;
    }

    // Decode from full buffer; BerReader advances exactly to end of the TLV.
    BerReader reader{data};
    EncryptedPayload ep{};
    {
        BerDecodeStream s{reader};
        auto ok = BerCodec::instance().decode(s, asn_DEF_EncryptedPayload, &ep);
        if (!ok) {
            std::fprintf(stderr, "  inner: BER decode failed: %s\n",
                         ok.error().message.c_str());
            return false;
        }
    }

    // Verify the tail (if any) is all-zero block-alignment padding.
    std::size_t consumed = reader.pos();
    for (std::size_t i = consumed; i < data.size(); ++i) {
        if (data[i] != 0) {
            std::fprintf(stderr, "  inner: non-zero byte 0x%02x at offset %zu after %zu-byte payload\n",
                         data[i], i, consumed);
            break;
        }
    }

    xer_print(asn_DEF_EncryptedPayload, &ep);
    return true;
}

int main(int argc, char* argv[])
{
    if (argc < 2) {
        std::fprintf(stderr, "Usage: %s <file.etsi>\n", argv[0]);
        return 1;
    }

    std::FILE* f = std::fopen(argv[1], "rb");
    if (!f) { std::perror(argv[1]); return 1; }

    std::fseek(f, 0, SEEK_END);
    long fsize = std::ftell(f);
    std::fseek(f, 0, SEEK_SET);

    std::vector<uint8_t> buf(static_cast<std::size_t>(fsize));
    if (static_cast<long>(std::fread(buf.data(), 1, buf.size(), f)) != fsize) {
        std::perror("fread"); std::fclose(f); return 1;
    }
    std::fclose(f);

    std::size_t offset = 0;
    int pdu_num = 0;
    int inner_decoded = 0;

    while (offset < buf.size()) {
        BerReader reader{std::span<const uint8_t>{buf.data() + offset, buf.size() - offset}};
        PS_PDU pdu{};
        {
            BerDecodeStream s{reader};
            auto ok = BerCodec::instance().decode(s, asn_DEF_PS_PDU, &pdu);
            if (!ok) {
                std::fprintf(stderr, "Outer BER decode failed at offset %zu (PDU #%d): %s\n",
                             offset, pdu_num + 1, ok.error().message.c_str());
                break;
            }
        }
        offset += reader.pos();
        ++pdu_num;
        std::printf("=== PS-PDU #%d ===\n", pdu_num);
        xer_print(asn_DEF_PS_PDU, &pdu);

        if (pdu.payload.present() == Payload::PR::encryptionContainer) {
            const auto& ec = pdu.payload.encryptionContainer();
            auto data = ec.encryptedPayload.bytes();
            std::size_t raw = data.size();
            std::size_t stripped = raw;
            while (stripped > 0 && data[stripped - 1] == 0)
                --stripped;
            std::printf("--- EncryptedPayload (%zu bytes, %zu zero-padded) ---\n",
                        stripped, raw - stripped);
            if (strip_and_decode(ec.encryptedPayload))
                ++inner_decoded;
        }
    }

    std::fprintf(stderr, "Decoded %d outer PS-PDUs, %d with inner EncryptedPayload\n",
                 pdu_num, inner_decoded);
    return 0;
}
