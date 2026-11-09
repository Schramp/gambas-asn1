// ber-to-per — decode raw BER stream, re-encode each record to UPER, emit
// length-prefixed PER records to stdout.
//
// PER is not self-delimiting the way BER's TLV framing is (X.691 has no
// per-record boundary marker), so each output record is framed as a
// 4-byte big-endian byte count followed by that many PER bytes — the
// same framing per-to-ber (this directory) expects on its own input.
// The BER input is read one record at a time through asn1::BerFrameReader.
//
// Usage: ber-to-per --type TYPE [FILE]
//   --type TYPE     type name (required; --type list to show available)
//   FILE            input file (default: stdin)

#include "type_registry.hpp"

#include <asn1cpp/codec/BerFrames.hpp>

#include <asn1cpp/codec/PerCodec.hpp>
#include <cstdint>
#include <cstring>
#include <fstream>
#include <iostream>
#include <sstream>
#include <vector>

static void write_u32be(std::ostream& out, uint32_t v) {
    char buf[4] = {char((v >> 24) & 0xFF), char((v >> 16) & 0xFF),
                   char((v >> 8) & 0xFF), char(v & 0xFF)};
    out.write(buf, 4);
}

int main(int argc, char** argv) {
    std::string type_name;
    std::string input_file;

    for (int i = 1; i < argc; ++i) {
        if (std::strcmp(argv[i], "--type") == 0 && i+1 < argc)
            type_name = argv[++i];
        else if (argv[i][0] != '-')
            input_file = argv[i];
        else { std::cerr << "Unknown option: " << argv[i] << "\n"; return 1; }
    }

    if (type_name.empty() || type_name == "list") {
        std::cerr << "Available types:\n";
        randgen::list_types();
        return type_name.empty() ? 1 : 0;
    }

    const randgen::TypeEntry* entry = randgen::find_type(type_name);
    if (!entry) {
        std::cerr << "Unknown type: " << type_name << "\nAvailable:\n";
        randgen::list_types();
        return 1;
    }

    std::ifstream fin;
    if (!input_file.empty()) {
        fin.open(input_file, std::ios::binary);
        if (!fin) { std::cerr << "Cannot open: " << input_file << "\n"; return 1; }
    }
    asn1::IstreamInput in{input_file.empty() ? std::cin : static_cast<std::istream&>(fin)};
    asn1::BerFrameReader frames{in};

    int n = 0, errors = 0;

    for (;;) {
        auto frame = frames.next();
        if (!frame) {
            std::cerr << "BER framing failed record #" << n
                      << " at offset " << frame.error().offset
                      << ": " << frame.error().message << "\n";
            ++errors;
            break;
        }
        if (!*frame) break;
        const std::uint64_t offset = (**frame).offset;
        auto obj = entry->make();
        asn1::Asn1Object* p = obj.get();
        auto ok = asn1::decode_frame(**frame, *entry->def, p);
        if (!ok) {
            std::cerr << "BER decode failed record #" << n
                      << " at offset " << offset
                      << ": " << ok.error().message << "\n";
            ++errors;
            break;
        }

        std::vector<uint8_t> per_buf;
        asn1::PerEncodeStream ps{per_buf};
        asn1::IEncodeStream& es = ps;
        asn1::PerCodec::instance().encode(es, *entry->def, p);
        if (ps.encode_failed()) {
            std::cerr << "PER encode failed record #" << n << " at offset " << offset << "\n";
            ++errors;
            continue;
        }
        ps.flush();

        write_u32be(std::cout, static_cast<uint32_t>(per_buf.size()));
        std::cout.write(reinterpret_cast<const char*>(per_buf.data()), per_buf.size());
        ++n;
    }

    std::cerr << n << " records processed, " << errors << " errors\n";
    return errors ? 1 : 0;
}
