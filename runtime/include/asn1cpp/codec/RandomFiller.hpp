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

    /// @brief When true, REAL values are generated with at most 6 digits
    /// after the decimal point (assembled via snprintf("%.*f") + strtod,
    /// not bit-twiddled) instead of the full double range. A double that
    /// is exactly a short decimal has no formatting ambiguity left: every
    /// `%.15G`-family formatter (asn1cpp's own JerCodec, asn1c's JER
    /// encoder, which does not always agree with asn1cpp's own choice of
    /// digit count for an arbitrary double — see gambas-asn1 xval_sweep's
    /// JER leg) converges on the same minimal text. Exists specifically
    /// so JER cross-validation can be byte-exact-gated instead of
    /// informational-only when the caller opts in. Default false — not
    /// the general-purpose knob; other callers (BER/XER/PER fuzzing) want
    /// the full double range.
    bool jer_safe_real = false;

    /// @brief Probability (0-1, not percent) that a generated REAL value
    /// is one of the five "magic" special values (NaN, +Inf, -Inf, -0.0,
    /// +0.0 -- chosen uniformly among them) instead of a value from the
    /// ordinary uniform range. `std::uniform_real_distribution` over
    /// [-1e6, 1e6] has essentially zero chance of ever landing on one of
    /// these by chance (NaN/Inf aren't in its range at all; exact -0.0/
    /// +0.0 is a single point out of 2^64), so without this knob the
    /// special-value encode/decode paths (X.697 §23.2's Table 2 strings,
    /// X.693's SpecialRealValue element, PER's own special-value bit
    /// patterns) are effectively never exercised by randomized testing.
    /// Default ~1/40 — frequent enough that a handful of records already
    /// covers all five cases, not so frequent that it swamps ordinary
    /// REAL coverage.
    double magic_real_prob = 1.0 / 40.0;

    /// @brief When true (default, matches magic_real_prob's own doc),
    /// the magic-value set includes -0.0. When false, -0.0 is excluded
    /// -- leaving NaN/+Inf/-Inf/+0.0, all four of which round-trip
    /// bit-exactly through every codec this runtime has (BER, PER, basic
    /// XER, JER). -0.0 is the one exception: basic XER has no
    /// minus-zero distinction (X.693 §17.9 -- confirmed against the
    /// standard text directly, 2026-10-07), so it legitimately loses its
    /// sign crossing BER->XER, even though BER itself (X.690 §8.5.3/
    /// 8.5.9) and JER/PER both carry it exactly. Set false when
    /// generating a fixture that must survive a naive byte-for-byte
    /// cross-codec round-trip check without a tolerant comparator (see
    /// tests/seq/test_random_roundtrip.cpp's own idempotent-after-first-
    /// hop handling for the alternative, more rigorous approach).
    bool include_xer_unsafe_magic = true;
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
    // Wide-char string content for UniversalString (X.680: UCS-4, 4 raw
    // bytes/char) and BmpString (UCS-2, 2 raw bytes/char) — unlike every
    // other string kind, AsnStringBase::str() for these holds fixed-width
    // big-endian code units, not one byte per character. `unit_bytes` is 4
    // or 2; returns `len` code units (`len * unit_bytes` bytes total),
    // each a valid Unicode scalar value in the type's own representable
    // range (excludes the UTF-16 surrogate range for both, and clamps to
    // the Basic Multilingual Plane for BmpString, which is defined over
    // BMP code points only — X.680 §41).
    std::string random_wide_chars(int unit_bytes, int len);

    std::mt19937& rng_;
    FillConfig    cfg_;
};

} // namespace asn1
