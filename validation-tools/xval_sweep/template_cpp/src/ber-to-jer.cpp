// ber-to-jer — decode raw BER stream and emit JER to stdout.
//
// Input: raw concatenated BER TLVs (same format as .etsi files and randgen output),
// read one record at a time through asn1::BerFrameReader.
// Output: one compact JSON object per line (JerCodec's own convention —
// unlike XER, JER has no indentation to produce, so no record-splitting
// heuristic is needed on the decode side: each line is already one record).
//
// Usage: ber-to-jer --type TYPE [FILE]
//   --type TYPE     type name (required; --type list to show available)
//   FILE            input file (default: stdin)

#include "type_registry.hpp"

#include <asn1cpp/codec/BerFrames.hpp>

#include <cstring>
#include <fstream>
#include <iostream>
#include <sstream>
#include <vector>

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
        auto obj = entry->make();   // shared_ptr<Asn1Object>
        asn1::Asn1Object* p = obj.get();
        auto ok = asn1::decode_frame(**frame, *entry->def, p);
        if (!ok) {
            std::cerr << "BER decode failed record #" << n
                      << " at offset " << offset
                      << ": " << ok.error().message << "\n";
            ++errors;
            break;
        }

        // Buffered, so a record that fails to encode leaves no partial output.
        std::ostringstream text;
        asn1::JerEncodeStream js{text};
        asn1::JerCodec::instance().encode(js, *entry->def, p);
        if (js.encode_failed()) {
            std::cerr << "JER encode failed record #" << n << " at offset " << offset << "\n";
            ++errors;
            continue;
        }
        std::cout << text.str() << "\n";
        ++n;
    }   // obj destructs here — ~T() via shared_ptr control block

    std::cerr << n << " records processed, " << errors << " errors\n";
    return errors ? 1 : 0;
}
