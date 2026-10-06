// jer-to-ber — decode JER records and emit raw BER stream.
//
// Input: JER records, one compact JSON object per line (format output by
// ber-to-jer). Unlike XER's tag-balancing line-splitter, JER needs no
// multi-line record detection — each non-blank line is already one
// complete, self-delimiting JSON value.
// Output: raw concatenated BER TLVs.
//
// Usage: jer-to-ber --type TYPE [FILE]
//   --type TYPE    type name (required; --type list to show available)
//   FILE           input file (default: stdin)

#include "type_registry.hpp"

#include <cstring>
#include <fstream>
#include <iostream>
#include <sstream>
#include <vector>

static std::vector<std::string> split_jer_records(std::istream& in) {
    std::vector<std::string> records;
    for (std::string line; std::getline(in, line); ) {
        if (!line.empty())
            records.push_back(std::move(line));
    }
    return records;
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
        fin.open(input_file);
        if (!fin) { std::cerr << "Cannot open: " << input_file << "\n"; return 1; }
    }
    auto records = split_jer_records(input_file.empty() ? std::cin : static_cast<std::istream&>(fin));

    int n = 0, errors = 0;
    for (const auto& rec : records) {
        auto obj = entry->make();
        asn1::Asn1Object* p = obj.get();

        asn1::JerDecodeStream ds{rec};
        auto ok = asn1::JerCodec::instance().decode(ds, *entry->def, p);
        if (!ok) {
            std::cerr << "JER decode failed record #" << n
                      << ": " << ok.error().message << "\n";
            ++errors;
            continue;
        }

        std::vector<uint8_t> buf;
        asn1::BerWriter w{buf};
        asn1::BerEncodeStream es{w};
        asn1::BerCodec::instance().encode(es, *entry->def, p);

        std::cout.write(reinterpret_cast<const char*>(buf.data()),
                        static_cast<std::streamsize>(buf.size()));
        ++n;
    }   // obj destructs here — ~T() via shared_ptr control block

    std::cerr << n << " records processed, " << errors << " errors\n";
    return errors ? 1 : 0;
}
