// randgen — write raw BER-encoded records to a file.
//
// Output: raw concatenated BER TLVs (same format as .etsi capture files).
// Type selected at runtime; available types registered by etsi_types.cpp.
//
// Usage: randgen --type TYPE [options]
//   --type    TYPE     type name (required; --type list to show available)
//   --count   N        number of records (default: 100)
//   --seed    S        RNG seed (default: random_device)
//   --output  FILE     output BER file (default: stdout)
//   --xer     FILE     also write XER output alongside BER (optional)
//   --depth   D        max recursion depth (default: 25)
//   --max-seq M        max SEQUENCE OF elements (default: 30)
//   --invalid-percent P  per-primitive percent chance of producing an
//                        out-of-constraint value (default: 0; 0.1 = 0.1 %)
//   --corrupt-percent P  per-TLV-header percent chance of byte-level BER
//                        corruption applied AFTER encoding (default: 0).
//   --corrupt-mode SPEC  bitmask of mutation kinds (default: all).
//                        SPEC is one or more names joined with '+' or ',',
//                        e.g. flip-pc+tag-jump, or a numeric mask 0xNN / N.
//                        Names: flip-pc rotate-class tag-bump tag-jump
//                               len-bit-flip len-indef len-overstate
//                               len-understate (all = OR of every name)

#include "type_registry.hpp"
#include <asn1cpp/codec/BerCorruptor.hpp>

#include <cstdlib>
#include <cstring>
#include <fstream>
#include <iostream>
#include <random>
#include <string>

int main(int argc, char** argv) {
    int    count   = 100;
    int    depth   = 25;
    int    max_seq = 30;
    double invalid_percent = 0.0;
    double corrupt_percent = 0.0;
    asn1::CorruptMask corrupt_mask = asn1::CORRUPT_ALL;
    uint64_t seed = std::random_device{}();
    std::string output_file;
    std::string xer_file;
    std::string type_name;

    for (int i = 1; i < argc; ++i) {
        if      (std::strcmp(argv[i], "--type")    == 0 && i+1 < argc) type_name   = argv[++i];
        else if (std::strcmp(argv[i], "--count")   == 0 && i+1 < argc) count       = std::atoi(argv[++i]);
        else if (std::strcmp(argv[i], "--seed")    == 0 && i+1 < argc) seed        = (uint64_t)std::atoll(argv[++i]);
        else if (std::strcmp(argv[i], "--output")  == 0 && i+1 < argc) output_file = argv[++i];
        else if (std::strcmp(argv[i], "--xer")     == 0 && i+1 < argc) xer_file    = argv[++i];
        else if (std::strcmp(argv[i], "--depth")   == 0 && i+1 < argc) depth       = std::atoi(argv[++i]);
        else if (std::strcmp(argv[i], "--max-seq") == 0 && i+1 < argc) max_seq     = std::atoi(argv[++i]);
        else if (std::strcmp(argv[i], "--invalid-percent") == 0 && i+1 < argc)
            invalid_percent = std::atof(argv[++i]);
        else if (std::strcmp(argv[i], "--corrupt-percent") == 0 && i+1 < argc)
            corrupt_percent = std::atof(argv[++i]);
        else if (std::strcmp(argv[i], "--corrupt-mode") == 0 && i+1 < argc) {
            const char* spec = argv[++i];
            if (!asn1::parse_corrupt_mask(spec, corrupt_mask)) {
                std::cerr << "Bad --corrupt-mode: " << spec << "\n"
                          << "Valid tokens: all flip-pc rotate-class tag-bump tag-jump\n"
                          << "              len-bit-flip len-indef len-overstate len-understate\n"
                          << "Combine with '+' or ',' (e.g. flip-pc+tag-jump),\n"
                          << "or pass a hex/decimal mask (e.g. 0x21).\n";
                return 1;
            }
        }
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

    std::mt19937 rng{static_cast<uint32_t>(seed)};
    asn1::FillConfig cfg;
    cfg.max_depth        = depth;
    cfg.max_seq_of       = max_seq;
    cfg.invalid_percent  = invalid_percent;
    asn1::RandomFiller filler{rng, cfg};

    std::ofstream fout;
    if (!output_file.empty()) {
        fout.open(output_file, std::ios::binary);
        if (!fout) { std::cerr << "Cannot open: " << output_file << "\n"; return 1; }
    }
    std::ostream& out = output_file.empty() ? std::cout : fout;

    std::ofstream xout;
    if (!xer_file.empty()) {
        xout.open(xer_file);
        if (!xout) { std::cerr << "Cannot open: " << xer_file << "\n"; return 1; }
    }

    std::cerr << "type=" << type_name << " seed=" << seed
              << " count=" << count << " depth=" << depth
              << " max_seq=" << max_seq
              << " invalid_percent=" << invalid_percent
              << " corrupt_percent=" << corrupt_percent << "\n";

    for (int i = 0; i < count; ++i) {
        auto obj = entry->make();
        asn1::Asn1Object* p = obj.get();

        filler.fill(p, *entry->def);

        std::vector<uint8_t> buf;
        asn1::BerWriter w{buf};
        asn1::BerEncodeStream es{w};
        asn1::BerCodec::instance().encode(es, *entry->def, p);

        if (corrupt_percent > 0.0)
            asn1::corrupt_ber(buf, corrupt_percent, rng, corrupt_mask);

        out.write(reinterpret_cast<const char*>(buf.data()),
                  static_cast<std::streamsize>(buf.size()));

        if (xout.is_open()) {
            asn1::XerEncodeStream xs{xout};
            asn1::XerCodec::instance().encode(xs, *entry->def, p);
            xout << "\n";
        }
    }   // obj destructs here — ~T() called through shared_ptr control block

    return 0;
}
