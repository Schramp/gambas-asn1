#pragma once
#include <random>
#include "../TypeDescriptor.hpp"

namespace asn1 {

struct FillConfig {
    int    max_depth     = 10;   // recursion depth limit (self-recursive types)
    int    min_seq_of    =  1;   // min elements in SEQUENCE OF / SET OF
    int    max_seq_of    =  8;   // max elements
    int    min_str_len   =  1;   // min OCTET STRING / character string length
    int    max_str_len   = 32;
    double optional_prob = 0.7;  // probability an OPTIONAL member is present
};

// Walks a TypeDescriptor tree and fills a caller-provided, already-default-constructed
// object with random but structurally valid data.  Works through the same void*/offset
// mechanism as BerCodec — no knowledge of the concrete C++ type is required.
//
// Usage:
//   std::mt19937 rng{42};
//   asn1::RandomFiller filler{rng};
//   MyType obj{};                              // default-construct
//   filler.fill(&obj, asn_DEF_MyType);
//   // obj is now ready to encode with any ICodec
class RandomFiller {
public:
    explicit RandomFiller(std::mt19937& rng, FillConfig cfg = {});

    void fill(void* obj, const TypeDescriptor& def, int depth = 0, bool mandatory = false);

private:
    void fill_sequence (void* obj, const SequenceSpec&   spec, int depth);
    void fill_choice   (void* obj, const ChoiceSpec&     spec, int depth);
    void fill_seq_of   (void* obj, const SeqOfSpec&      spec, int depth);
    void fill_enum     (void* obj, const EnumSpec&       spec);
    void fill_primitive(void* obj, const TypeDescriptor& def);

    // helpers
    bool coin(double p);
    int  rand_int(int lo, int hi);   // inclusive
    std::string random_printable(int len);

    std::mt19937& rng_;
    FillConfig    cfg_;
};

} // namespace asn1
