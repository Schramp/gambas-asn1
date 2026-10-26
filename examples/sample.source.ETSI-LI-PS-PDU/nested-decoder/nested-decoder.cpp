/*
 * nested-decoder.cpp
 *
 * C++ port of etsi-li-ps-pdu-nested.c using asn1cpp-generated types.
 *
 * Reads a stream of BER-encoded PS-PDU records from a file and prints each
 * as XER. The library is generated with container_fields.json, so the outer
 * decode already decodes EncryptionContainer.encryptedPayload (encryptionType
 * `none`) as an EncryptedPayload with the zero_padding decoder.
 *
 * --xer-form hex (default) prints encryptedPayload as hex, then the inner
 * EncryptedPayload as a separate document after a "--- EncryptedPayload ---"
 * header: the same output as the asn1c nested decoder.
 * --xer-form inline / inline_raw prints the inner value inside the PS-PDU
 * (inline_raw adds the raw hex as a comment) and no separate document.
 *
 * Usage: nested-decoder [--xer-form hex|inline|inline_raw] <file.etsi>
 */

#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <iostream>
#include <vector>
#include <span>

#include <asn1cpp/asn1cpp.hpp>
#include <asn1cpp/codec/ContainedDecoders.hpp>
#include <asn1cpp/codec/XerCodec.hpp>

#include "PS_PDU.hpp"
#include "EncryptedPayload.hpp"

using asn1::BerReader;
using asn1::BerCodec;
using asn1::BerDecodeStream;
using asn1::ContainedOptions;
using asn1::ContainedStatus;
using asn1::ContainedText;
using asn1::XerCodec;
using asn1::XerEncodeStream;

static void xer_print(const asn1::TypeDescriptor& def, const asn1::Asn1Object* val,
                      const ContainedOptions& opts)
{
    XerEncodeStream s(std::cout);
    s.set_contained(&opts);
    XerCodec::instance().encode(s, def, val);
}

static const char* status_name(ContainedStatus st)
{
    switch (st) {
    case ContainedStatus::NotDecoded: return "not decoded";
    case ContainedStatus::Decoded:    return "decoded";
    case ContainedStatus::Skipped:    return "skipped";
    case ContainedStatus::Failed:     return "failed";
    }
    return "?";
}

/// Report an undecoded payload, or a decoder warning (non-zero padding), on stderr.
static void report_inner(const asn1::Containing<EncryptedPayload>& ep)
{
    if (ep.status() != ContainedStatus::Decoded)
        std::fprintf(stderr, "  inner: %s: %s\n", status_name(ep.status()), ep.error().c_str());
    else if (!ep.error().empty())
        std::fprintf(stderr, "  inner: %s\n", ep.error().c_str());
}

static bool parse_form(const char* s, ContainedText& form)
{
    if (!std::strcmp(s, "hex"))        { form = ContainedText::Hex;       return true; }
    if (!std::strcmp(s, "inline"))     { form = ContainedText::Inline;    return true; }
    if (!std::strcmp(s, "inline_raw")) { form = ContainedText::InlineRaw; return true; }
    return false;
}

int main(int argc, char* argv[])
{
    ContainedText form = ContainedText::Hex;
    const char* path = nullptr;
    for (int i = 1; i < argc; ++i) {
        if (!std::strcmp(argv[i], "--xer-form") && i + 1 < argc) {
            if (!parse_form(argv[++i], form)) {
                std::fprintf(stderr, "--xer-form: expected hex, inline or inline_raw, got '%s'\n", argv[i]);
                return 1;
            }
        } else if (!path && argv[i][0] != '-') {
            path = argv[i];
        } else {
            path = nullptr;
            break;
        }
    }
    if (!path) {
        std::fprintf(stderr, "Usage: %s [--xer-form hex|inline|inline_raw] <file.etsi>\n", argv[0]);
        return 1;
    }

    ContainedOptions opts;
    opts.xer = form;

    std::FILE* f = std::fopen(path, "rb");
    if (!f) { std::perror(path); return 1; }

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
            auto ok = BerCodec::instance().decode(s, PS_PDU::asn_DEF, &pdu);
            if (!ok) {
                std::fprintf(stderr, "Outer BER decode failed at offset %zu (PDU #%d): %s\n",
                             offset, pdu_num + 1, ok.error().message.c_str());
                break;
            }
        }
        offset += reader.pos();
        ++pdu_num;
        std::printf("=== PS-PDU #%d ===\n", pdu_num);
        xer_print(PS_PDU::asn_DEF, &pdu, opts);

        if (pdu.payload.present() != Payload::PR::encryptionContainer)
            continue;
        const auto& ep = pdu.payload.encryptionContainer().encryptedPayload;
        if (form == ContainedText::Hex) {
            auto data = ep.bytes();
            std::size_t stripped = data.size();
            while (stripped > 0 && data[stripped - 1] == 0)
                --stripped;
            std::printf("--- EncryptedPayload (%zu bytes, %zu zero-padded) ---\n",
                        stripped, data.size() - stripped);
        }
        report_inner(ep);
        if (!ep.has_value())
            continue;
        ++inner_decoded;
        if (form == ContainedText::Hex)
            xer_print(EncryptedPayload::asn_DEF, ep.value(), opts);
    }

    std::fprintf(stderr, "Decoded %d outer PS-PDUs, %d with inner EncryptedPayload\n",
                 pdu_num, inner_decoded);
    return 0;
}
