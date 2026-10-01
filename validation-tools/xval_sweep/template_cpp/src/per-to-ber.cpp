// per-to-ber — read length-prefixed UPER records (same framing
// ber-to-per, this directory, produces) and re-encode each to BER,
// writing the concatenated (self-delimiting) BER TLVs to stdout.
//
// Usage: per-to-ber --type TYPE [FILE]
//   --type TYPE     type name (required; --type list to show available)
//   FILE            input file (default: stdin)

#include "type_registry.hpp"

#include <asn1cpp/codec/PerCodec.hpp>
#include <cstdint>
#include <cstring>
#include <fstream>
#include <iostream>
#include <vector>

static std::vector<uint8_t> slurp(std::istream& in) {
    return {std::istreambuf_iterator<char>(in), {}};
}

static uint32_t read_u32be(const uint8_t* p) {
    return (uint32_t(p[0]) << 24) | (uint32_t(p[1]) << 16) | (uint32_t(p[2]) << 8) | uint32_t(p[3]);
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
    auto data = slurp(input_file.empty() ? std::cin : static_cast<std::istream&>(fin));

    int n = 0, errors = 0;
    std::size_t offset = 0;

    while (offset < data.size()) {
        if (offset + 4 > data.size()) {
            std::cerr << "Truncated length prefix at offset " << offset << "\n";
            ++errors;
            break;
        }
        uint32_t len = read_u32be(data.data() + offset);
        offset += 4;
        if (offset + len > data.size()) {
            std::cerr << "Truncated PER record at offset " << offset << "\n";
            ++errors;
            break;
        }

        auto obj = entry->make();
        asn1::Asn1Object* p = obj.get();

        asn1::PerDecodeStream ds{std::span<const uint8_t>(data.data() + offset, len)};
        asn1::IDecodeStream& is = ds;
        auto ok = asn1::PerCodec::instance().decode(is, *entry->def, p);
        offset += len;
        if (!ok) {
            std::cerr << "PER decode failed record #" << n << ": "
                      << ok.error().message << "\n";
            ++errors;
            break;
        }

        std::vector<uint8_t> ber_buf;
        asn1::BerWriter bw{ber_buf};
        asn1::BerEncodeStream es{bw};
        asn1::BerCodec::instance().encode(es, *entry->def, p);
        std::cout.write(reinterpret_cast<const char*>(ber_buf.data()), ber_buf.size());
        ++n;
    }

    std::cerr << n << " records processed, " << errors << " errors\n";
    return errors ? 1 : 0;
}
