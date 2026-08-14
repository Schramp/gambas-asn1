// ber-to-xer — decode raw BER stream and emit XER to stdout.
//
// Input: raw concatenated BER TLVs (same format as .etsi files and randgen output).
//
// Usage: ber-to-xer --type TYPE [FILE]
//   --type TYPE     type name (required; --type list to show available)
//   FILE            input file (default: stdin)

#include "type_registry.hpp"

#include <cstring>
#include <fstream>
#include <iostream>
#include <vector>

static std::vector<uint8_t> slurp(std::istream& in) {
    return {std::istreambuf_iterator<char>(in), {}};
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
        auto obj = entry->make();   // shared_ptr<Asn1Object>
        asn1::Asn1Object* p = obj.get();

        asn1::BerReader r{std::span<const uint8_t>(data.data() + offset,
                                                    data.size() - offset)};
        asn1::BerDecodeStream ds{r};
        auto ok = asn1::BerCodec::instance().decode(ds, *entry->def, p);

        if (!ok) {
            std::cerr << "BER decode failed record #" << n
                      << " at offset " << offset
                      << ": " << ok.error().message << "\n";
            ++errors;
            break;
        }

        std::size_t consumed = r.pos();
        if (consumed == 0) {
            std::cerr << "Zero bytes consumed at offset " << offset << "\n";
            break;
        }
        offset += consumed;

        asn1::XerEncodeStream xs{std::cout};
        asn1::XerCodec::instance().encode(xs, *entry->def, p);
        std::cout << "\n";
        ++n;
    }   // obj destructs here — ~T() via shared_ptr control block

    std::cerr << n << " records processed, " << errors << " errors\n";
    return errors ? 1 : 0;
}
