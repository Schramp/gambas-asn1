#pragma once
#include <random>
#include <string>
#include <string_view>
#include "../TypeDescriptor.hpp"
#include "../Asn1Object.hpp"

namespace asn1 {

/// @brief Configuration knobs for \c RandomFiller.
/// All fields have safe defaults; override only the knobs you care about.
struct FillConfig {
    int    max_depth     = 10;   ///< Recursion depth limit (prevents infinite loops in self-recursive types).
    int    min_seq_of    =  1;   ///< Minimum element count for SEQUENCE OF / SET OF.
    int    max_seq_of    =  8;   ///< Maximum element count for SEQUENCE OF / SET OF.
    int    min_str_len   =  1;   ///< Minimum length for OCTET STRING and character strings.
    int    max_str_len   = 32;   ///< Maximum length for OCTET STRING and character strings.
    double optional_prob = 0.7;  ///< Probability (0–1) that an OPTIONAL member is generated.

    /// @brief Per-primitive probability (in PERCENT, e.g. \c 0.1 = 0.1%) that
    /// the generator emits a value intentionally violating a constraint.
    /// Used by xval / fuzz pipelines to verify decoder/validator behaviour on bad input.
    /// Affects: INTEGER range, OCTET/BIT/string SIZE, string alphabet, ENUM map, SEQUENCE OF size.
    /// Default 0 = always in-spec.
    double invalid_percent = 0.0;
};

/// @brief Fills a default-constructed ASN.1 object with random but structurally valid data.
///
/// Walks the \c TypeDescriptor tree in the same way \c BerCodec does — no knowledge
/// of the concrete C++ type is required.  The result is ready to encode with any \c ICodec.
///
/// Usage:
/// @code
/// std::mt19937 rng{42};
/// asn1::RandomFiller filler{rng};
/// MyType obj{};
/// filler.fill(&obj, MyType::asn_DEF);
/// // obj is now ready to encode
/// @endcode
///
/// To generate intentionally invalid values (for fuzz / validator testing) set
/// \c FillConfig::invalid_percent to a small positive number (e.g. \c 5.0 for 5%).
class RandomFiller {
public:
    /// @brief Construct with the given RNG and optional config.
    /// @param rng  Random number generator; must outlive this object.
    /// @param cfg  Fill parameters; defaults are reasonable for structural testing.
    explicit RandomFiller(std::mt19937& rng, FillConfig cfg = {});

    /// @brief Fill \p obj (described by \p def) with random data.
    /// \p obj must be default-constructed before the call.
    /// @param obj       Target object; must not be null.
    /// @param def       TypeDescriptor of \p obj's type.
    /// @param depth     Current recursion depth (callers pass 0).
    /// @param mandatory True when this member must succeed (no optional skip fallback).
    /// @return True on success; false when a constraint could not be satisfied after retries.
    bool fill(Asn1Object* obj, const TypeDescriptor& def, int depth = 0, bool mandatory = false);

private:
    bool fill_sequence (Asn1Object* obj, const SequenceSpec&   spec, int depth);
    bool fill_choice   (Asn1Object* obj, const ChoiceSpec&     spec, int depth);
    bool fill_seq_of   (Asn1Object* obj, const SeqOfSpec&      spec, int depth);
    void fill_enum     (Asn1Object* obj, const EnumSpec&       spec);
    void fill_primitive(Asn1Object* obj, const TypeDescriptor& def);
    // Retry-with-validate wrapper around fill_primitive; falls back to a
    // permuted length scan (0..256) for SIZE-constrained primitives when
    // simple regeneration doesn't produce a valid value.
    bool try_fill_primitive(Asn1Object* obj, const TypeDescriptor& def);

    // helpers
    bool coin(double p);
    int  rand_int(int lo, int hi);   // inclusive
    std::string random_printable(int len);
    std::string random_from_alphabet(std::string_view alpha, int len);

    std::mt19937& rng_;
    FillConfig    cfg_;
};

} // namespace asn1
