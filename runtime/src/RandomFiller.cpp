#include <asn1cpp/codec/RandomFiller.hpp>
#include <asn1cpp/codec/Alphabets.hpp>
#include <asn1cpp/Validate.hpp>
#include <algorithm>
#include <limits>
#include <vector>
#include <asn1cpp/types/Integer.hpp>
#include <asn1cpp/types/Boolean.hpp>
#include <asn1cpp/types/OctetString.hpp>
#include <asn1cpp/types/BitString.hpp>
#include <asn1cpp/types/Real.hpp>
#include <asn1cpp/types/Oid.hpp>
#include <asn1cpp/types/Time.hpp>
#include <asn1cpp/types/Strings.hpp>
#include <asn1cpp/codec/BerWriter.hpp>

namespace asn1 {

RandomFiller::RandomFiller(std::mt19937& rng, FillConfig cfg)
    : rng_(rng), cfg_(cfg) {}

// ---------------------------------------------------------------------------
// helpers
// ---------------------------------------------------------------------------

bool RandomFiller::coin(double p) {
    return std::bernoulli_distribution{p}(rng_);
}

int RandomFiller::rand_int(int lo, int hi) {
    return std::uniform_int_distribution<int>{lo, hi}(rng_);
}

// Resolve effective [lo, hi] sampling range for a SIZE-constrained primitive.
// Reads bounds straight from Constraints when SIZE_CONSTRAINED is set; caps
// at 65536 so absurd schema-level bounds (e.g. SIZE(0..2^32-1)) don't drive
// gigabyte allocations. Falls back to caller-supplied defaults otherwise.
static std::pair<int,int> size_range(const Constraints& c,
                                     int dflt_lo, int dflt_hi) {
    constexpr int64_t CAP = 65536;
    int lo = dflt_lo, hi = dflt_hi;
    if (c.flags & Constraints::SIZE_CONSTRAINED) {
        int64_t clo = c.size_lower, chi = c.size_upper;
        if (clo >= 0) lo = static_cast<int>(std::min(clo, CAP));
        if (chi >= 0) hi = static_cast<int>(std::min(chi, CAP));
        if (lo > hi)  hi = lo;
    }
    return {lo, hi};
}

std::string RandomFiller::random_printable(int len) {
    return random_from_alphabet(DEFAULT_STRING_ALPHABET, len);
}

std::string RandomFiller::random_from_alphabet(std::string_view alpha, int len) {
    std::uniform_int_distribution<int> pick{0, static_cast<int>(alpha.size()) - 1};
    std::string s;
    s.reserve(len);
    for (int i = 0; i < len; ++i)
        s += alpha[pick(rng_)];
    return s;
}

// ---------------------------------------------------------------------------
// top-level dispatch
// ---------------------------------------------------------------------------

bool RandomFiller::fill(void* obj, const TypeDescriptor& def, int depth, bool mandatory) {
    if (depth > 1000) return false;                       // absolute safety — catches recursive mandatory cycles
    if (!mandatory && depth > cfg_.max_depth) return false; // soft limit — only skips optional paths

    if (def.is_any) {
        // Encode a small random INTEGER as the raw ANY bytes.
        // ANY is stored as OctetString in the runtime.
        std::vector<uint8_t> buf;
        BerWriter w{buf};
        int64_t v = std::uniform_int_distribution<int64_t>{-127, 127}(rng_);
        Integer iv{v};
        BerTraits<Integer>::encode(w, iv);
        static_cast<OctetString*>(obj)->set(std::move(buf));
        return true;
    }
    if (def.enum_spec)     { fill_enum(obj, *def.enum_spec); return true; }
    if (def.sequence_spec) return fill_sequence(obj, *def.sequence_spec, depth);
    if (def.choice_spec)   return fill_choice  (obj, *def.choice_spec,   depth);
    if (def.seq_of_spec)   return fill_seq_of  (obj, *def.seq_of_spec,   depth);
    return try_fill_primitive(obj, def);
}

// Rewrite obj as a fresh random value of exactly `len` units (bytes for
// OctetString, bits for BitString, chars for the string family). Returns
// false for non-resizable primitives. Used by try_fill_primitive's SIZE
// nudge path so we adjust the produced object directly instead of mutating
// constraints to coerce fill_primitive into a target length.
static bool resize_in_place(void* obj, const TypeDescriptor& def,
                            std::size_t len, std::mt19937& rng) {
    if (def.tag.cls != TagClass::Universal) return false;
    auto rand_byte = [&]{
        return static_cast<uint8_t>(std::uniform_int_distribution<int>{0, 255}(rng));
    };
    auto rand_char = [&]{
        static constexpr std::string_view chars =
            "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789 ";
        return chars[std::uniform_int_distribution<int>{
            0, static_cast<int>(chars.size()) - 1}(rng)];
    };

    switch (def.tag.number) {
    case UniversalTag::OctetString: {
        std::vector<uint8_t> v(len);
        for (auto& b : v) b = rand_byte();
        static_cast<OctetString*>(obj)->set(std::move(v));
        return true;
    }
    case UniversalTag::BitString: {
        std::size_t bytes = (len + 7) / 8;
        std::vector<uint8_t> v(bytes);
        for (auto& b : v) b = rand_byte();
        uint8_t unused = bytes > 0
            ? static_cast<uint8_t>(bytes * 8 - len) : 0;
        if (!v.empty() && unused > 0)
            v.back() &= static_cast<uint8_t>(0xFF << unused);
        static_cast<BitString*>(obj)->set(std::move(v), unused);
        return true;
    }
    case UniversalTag::Utf8String:
    case UniversalTag::NumericString:
    case UniversalTag::PrintableString:
    case UniversalTag::T61String:
    case UniversalTag::VideotexString:
    case UniversalTag::Ia5String:
    case UniversalTag::GraphicString:
    case UniversalTag::VisibleString:
    case UniversalTag::GeneralString:
    case UniversalTag::UniversalString:
    case UniversalTag::BmpString:
    case UniversalTag::ObjectDescriptor: {
        std::string s;
        s.reserve(len);
        for (std::size_t i = 0; i < len; ++i) s += rand_char();
        detail::asnstring_assign(obj, s);
        return true;
    }
    default:
        return false;
    }
}

// Sample a primitive from a *widened* version of its constraint envelope so
// the resulting value lands out-of-spec a fair fraction of the time, but
// occasionally still in-spec. Mirrors fill_primitive's structure with each
// per-type sampling range expanded by a constraint-relative margin.
//
// Returns true if widening was applicable (caller skips validation/retry);
// false for primitives without a checkable constraint (caller falls through
// to the strict in-spec path).
static bool fill_primitive_loose(void* obj, const TypeDescriptor& def,
                                 std::mt19937& rng) {
    if (def.tag.cls != TagClass::Universal) return false;
    const auto& c = def.constraints;
    auto rand_byte = [&]{ return static_cast<uint8_t>(
        std::uniform_int_distribution<int>{0, 255}(rng)); };

    switch (def.tag.number) {
    case UniversalTag::Integer: {
        int64_t lo, hi;
        if (c.flags & Constraints::CONSTRAINED) {
            int64_t span = c.upper_bound - c.lower_bound;
            int64_t margin = std::max<int64_t>(2, span / 4 + 5);
            lo = (c.lower_bound > std::numeric_limits<int64_t>::min() + margin)
                     ? c.lower_bound - margin : c.lower_bound;
            hi = (c.upper_bound < std::numeric_limits<int64_t>::max() - margin)
                     ? c.upper_bound + margin : c.upper_bound;
        } else if (c.flags & Constraints::SEMI_CONSTRAINED) {
            lo = (c.lower_bound > std::numeric_limits<int64_t>::min() + 100)
                     ? c.lower_bound - 100 : c.lower_bound;
            hi = lo + 2000;
        } else {
            return false;
        }
        if (lo > hi) std::swap(lo, hi);
        int64_t v = std::uniform_int_distribution<int64_t>{lo, hi}(rng);
        static_cast<Integer*>(obj)->set(v);
        return true;
    }
    case UniversalTag::OctetString: {
        if (!(c.flags & Constraints::SIZE_CONSTRAINED)) return false;
        int64_t span = c.size_upper - c.size_lower;
        int64_t margin = std::max<int64_t>(2, span / 4 + 2);
        int64_t lo = std::max<int64_t>(0, c.size_lower - margin);
        int64_t hi = std::min<int64_t>(256, c.size_upper + margin);
        if (lo > hi) lo = hi;
        int64_t len = std::uniform_int_distribution<int64_t>{lo, hi}(rng);
        std::vector<uint8_t> buf(len);
        for (auto& b : buf) b = rand_byte();
        static_cast<OctetString*>(obj)->set(std::move(buf));
        return true;
    }
    case UniversalTag::BitString: {
        if (!(c.flags & Constraints::SIZE_CONSTRAINED)) return false;
        int64_t span = c.size_upper - c.size_lower;
        int64_t margin = std::max<int64_t>(2, span / 4 + 2);
        int64_t lo = std::max<int64_t>(0, c.size_lower - margin);
        int64_t hi = std::min<int64_t>(256, c.size_upper + margin);
        if (lo > hi) lo = hi;
        int64_t bits = std::uniform_int_distribution<int64_t>{lo, hi}(rng);
        std::size_t bytes = (bits + 7) / 8;
        std::vector<uint8_t> buf(bytes);
        for (auto& b : buf) b = rand_byte();
        uint8_t unused = bytes > 0
            ? static_cast<uint8_t>(bytes * 8 - bits) : 0;
        if (!buf.empty() && unused > 0)
            buf.back() &= static_cast<uint8_t>(0xFF << unused);
        static_cast<BitString*>(obj)->set(std::move(buf), unused);
        return true;
    }
    case UniversalTag::Utf8String:
    case UniversalTag::NumericString:
    case UniversalTag::PrintableString:
    case UniversalTag::T61String:
    case UniversalTag::VideotexString:
    case UniversalTag::Ia5String:
    case UniversalTag::GraphicString:
    case UniversalTag::VisibleString:
    case UniversalTag::GeneralString:
    case UniversalTag::UniversalString:
    case UniversalTag::BmpString:
    case UniversalTag::ObjectDescriptor: {
        bool size_constrained  = (c.flags & Constraints::SIZE_CONSTRAINED) != 0;
        bool alpha_constrained = !c.alphabet.empty();
        if (!size_constrained && !alpha_constrained) return false;

        int lo, hi;
        if (size_constrained) {
            int64_t span = c.size_upper - c.size_lower;
            int64_t margin = std::max<int64_t>(2, span / 4 + 2);
            lo = static_cast<int>(std::max<int64_t>(0, c.size_lower - margin));
            hi = static_cast<int>(std::min<int64_t>(64, c.size_upper + margin));
            if (lo > hi) lo = hi;
        } else {
            lo = 1; hi = 16;
        }
        int len = std::uniform_int_distribution<int>{lo, hi}(rng);

        // Widened character pool: full printable ASCII regardless of FROM /
        // built-in alphabet. Some chars will be in-spec, some not.
        static constexpr std::string_view pool =
            " !\"#$%&'()*+,-./0123456789:;<=>?@"
            "ABCDEFGHIJKLMNOPQRSTUVWXYZ[\\]^_`"
            "abcdefghijklmnopqrstuvwxyz{|}~";
        std::uniform_int_distribution<int> pick{
            0, static_cast<int>(pool.size()) - 1};
        std::string s;
        s.reserve(len);
        for (int i = 0; i < len; ++i) s += pool[pick(rng)];
        detail::asnstring_assign(obj, s);
        return true;
    }
    default:
        return false;
    }
}

bool RandomFiller::try_fill_primitive(void* obj, const TypeDescriptor& def) {
    // Loosened-sampling path: at probability cfg_.invalid_percent / 100 the
    // generator samples from a *widened* range that may overshoot the
    // declared constraint. Some samples land in-spec, some don't — natural
    // distribution rather than always-just-past-the-bound. Validation/retry
    // is skipped so out-of-spec values survive. Unconstrained primitives
    // fall through to the strict in-spec path (no widening possible).
    if (cfg_.invalid_percent > 0.0 && coin(cfg_.invalid_percent / 100.0)) {
        if (fill_primitive_loose(obj, def, rng_))
            return true;
    }

    constexpr int MAX_RETRIES = 16;

    bool is_int = (def.tag.cls == TagClass::Universal &&
                   def.tag.number == UniversalTag::Integer);

    // Integer: distance-tightening loop. Each failure narrows a working
    // descriptor copy's lower/upper bound using validate()'s signed delta:
    //   +delta → value below lower; raise sampling min by delta
    //   -delta → value above upper; lower sampling max by |delta|
    // Working copy converges monotonically toward the valid window.
    if (is_int) {
        // UInteger (uint64_t): validate() returns 0 for SEMI_CONSTRAINED(lo=0),
        // so no retry needed in the common case. For constrained U64, just
        // delegate to fill_primitive directly — practical U64 ranges are large.
        if (def.constraints.int_kind == Constraints::INT_U64) {
            fill_primitive(obj, def);
            return validate(def, obj) == 0;
        }

        TypeDescriptor d = def;
        for (int i = 0; i < MAX_RETRIES; ++i) {
            fill_primitive(obj, d);
            int64_t dist = validate(def, obj);
            if (dist == 0) return true;

            auto& pc = d.constraints;
            int64_t v = static_cast<const Integer*>(obj)->value();
            if (dist > 0) {
                int64_t new_lo = (v <= std::numeric_limits<int64_t>::max() - dist)
                    ? v + dist : std::numeric_limits<int64_t>::max();
                if (!(pc.flags & Constraints::CONSTRAINED) || new_lo > pc.lower_bound)
                    pc.lower_bound = new_lo;
            } else {
                int64_t new_hi = (v >= std::numeric_limits<int64_t>::min() - dist)
                    ? v + dist : std::numeric_limits<int64_t>::min();
                if (!(pc.flags & Constraints::CONSTRAINED) || new_hi < pc.upper_bound)
                    pc.upper_bound = new_hi;
            }
            pc.flags |= Constraints::CONSTRAINED;
            pc.flags &= ~(Constraints::SEMI_CONSTRAINED | Constraints::EXTENSIBLE);
            if (pc.lower_bound > pc.upper_bound) return false;
        }
        return false;
    }

    // Non-integer primitive: one regeneration attempt, then if still invalid
    // resize the produced object directly to a target length derived from
    // validate()'s delta. (current_size + delta) lands exactly on the
    // violated bound; cap at 256 so absurd schema-level bounds like
    // SIZE(0..2^32-1) don't trigger gigabyte allocations.
    fill_primitive(obj, def);
    int64_t dist = validate(def, obj);
    if (dist == 0) return true;

    int64_t target = (dist > 0) ? def.constraints.size_lower
                                : def.constraints.size_upper;
    if (target < 0)   target = 0;
    if (target > 256) target = 256;
    return resize_in_place(obj, def, static_cast<std::size_t>(target), rng_);
}

// ---------------------------------------------------------------------------
// ENUMERATED
// ---------------------------------------------------------------------------

void RandomFiller::fill_enum(void* obj, const EnumSpec& spec) {
    // Pick from root values only (extension values may be rejected by parents
    // expecting non-extensible enums). spec.entries is sorted by value for
    // BER/XER binary search, so its first root_count slots are NOT
    // necessarily roots when any extension value sorts before any root.
    // spec.per_value_order is the definition-order array of root values.
    int n = spec.root_count > 0 ? spec.root_count : spec.count;
    if (n == 0) return;
    int idx = rand_int(0, n - 1);
    long v = (spec.per_value_order && spec.root_count > 0)
                 ? spec.per_value_order[idx]
                 : spec.entries[idx].value;
    *static_cast<long*>(obj) = v;
}

// ---------------------------------------------------------------------------
// SEQUENCE / SET
// ---------------------------------------------------------------------------

bool RandomFiller::fill_sequence(void* obj, const SequenceSpec& spec, int depth) {
    for (int i = 0; i < spec.count; ++i) {
        const MemberDescriptor& mbr = spec.members[i];

        bool is_ext = (spec.ext_at >= 0 && i >= spec.ext_at);

        if (mbr.optional) {
            // Extension members: lower probability and only when depth allows.
            double p = is_ext ? cfg_.optional_prob * 0.3 : cfg_.optional_prob;
            bool present = (depth < cfg_.max_depth) && coin(p);
            mbr.optional_ops.set_present(obj, present);
            if (!present) continue;
        }

        void* mptr = mbr.optional_ops
                       ? mbr.optional_ops.member_ptr(obj, mbr.offset)
                       : static_cast<char*>(obj) + mbr.offset;

        // Mandatory: always fill (bypass soft depth limit), but still increment depth
        // to keep the absolute-limit stack-overflow guard working.
        // Optional: increment depth and apply soft limit.
        bool is_mand = !mbr.optional;
        bool ok = fill(mptr, *mbr.type_descriptor, depth + 1, is_mand);
        if (!ok) {
            // Couldn't satisfy a constraint. Optional members get dropped;
            // mandatory failures bubble up so the caller can retry.
            if (mbr.optional)
                mbr.optional_ops.set_present(obj, false);
            else
                return false;
        }
    }
    return true;
}

// ---------------------------------------------------------------------------
// CHOICE
// ---------------------------------------------------------------------------

bool RandomFiller::fill_choice(void* obj, const ChoiceSpec& spec, int depth) {
    if (spec.count == 0) return false;

    // Stay in root alternatives when near depth limit.
    int limit = (spec.ext_at >= 0 && depth >= cfg_.max_depth - 2)
                    ? spec.ext_at
                    : spec.count;
    if (limit == 0) limit = spec.count;

    int alt_idx = rand_int(0, limit - 1);
    *static_cast<int*>(obj) = alt_idx + 1;   // 1-based discriminant

    const MemberDescriptor& alt = spec.alternatives[alt_idx];

    void* aptr;
    if (alt.optional_ops) {
        alt.optional_ops.set_present(obj, true);
        aptr = alt.optional_ops.member_ptr(obj, alt.offset);
    } else {
        aptr = static_cast<char*>(obj) + alt.offset;
    }

    return fill(aptr, *alt.type_descriptor, depth + 1, true);
}

// ---------------------------------------------------------------------------
// SEQUENCE OF / SET OF
// ---------------------------------------------------------------------------

bool RandomFiller::fill_seq_of(void* obj, const SeqOfSpec& spec, int depth) {
    int lo = cfg_.min_seq_of;
    int hi = cfg_.max_seq_of;

    // Respect SIZE constraints if present. Clamp size_lower/upper like OctetString:
    // ETSI uses ranges like (0..18446744073709551615) which store as signed int64
    // upper = -1, breaking min/max math.
    const auto& sc = spec.size_constraints;
    if (sc.flags & Constraints::SIZE_CONSTRAINED) {
        int64_t clo = sc.size_lower, chi = sc.size_upper;
        if (clo >= 0 && clo <= 65536) lo = std::max(lo, static_cast<int>(clo));
        if (chi >= lo && chi <= 65536) hi = std::min(hi, static_cast<int>(chi));
        if (lo > hi) lo = hi;
    }

    // Exponential backoff: halve effective max every 2 depth levels so that
    // total data stays bounded regardless of max_depth.  Without this, nested
    // SEQUENCE OFs multiply as max_seq^nesting_levels.
    int depth_hi = std::max(cfg_.min_seq_of, cfg_.max_seq_of >> (depth / 2));
    hi = std::min(hi, depth_hi);
    // Re-clamp lo: SIZE_CONSTRAINED may have raised lo above the depth-reduced hi.
    if (lo > hi) lo = hi;

    int n = rand_int(lo, hi);
    spec.resize_fn(obj, static_cast<std::size_t>(n));

    int valid = 0;
    for (int i = 0; i < n; ++i) {
        void* eptr = spec.get_fn(obj, static_cast<std::size_t>(i));
        // Mandatory minimum elements bypass soft limit but still increment depth.
        bool mand = (i < lo);
        if (fill(eptr, *spec.element, depth + 1, mand)) {
            ++valid;
        } else if (mand) {
            // Couldn't satisfy the mandatory minimum; truncate and signal failure.
            spec.resize_fn(obj, static_cast<std::size_t>(valid));
            return false;
        }
        // Optional element failure: stop adding more, keep what we have.
        else { break; }
    }
    spec.resize_fn(obj, static_cast<std::size_t>(valid));
    return true;
}

// ---------------------------------------------------------------------------
// Primitive types — dispatched by universal tag number
// ---------------------------------------------------------------------------

void RandomFiller::fill_primitive(void* obj, const TypeDescriptor& def) {
    namespace UT = UniversalTag;

    // Non-universal tag: underlying C++ type is determined by the base type,
    // not the tag. We don't have that information here, so leave the object
    // zero-initialised (already valid — default-constructed upstream).
    if (def.tag.cls != TagClass::Universal)
        return;

    switch (def.tag.number) {

    case UT::Boolean: {
        static_cast<Boolean*>(obj)->set(coin(0.5));
        break;
    }

    case UT::Integer: {
        const auto& c = def.constraints;
        if (c.int_kind == Constraints::INT_U64) {
            uint64_t lo = c.lower_u64;
            uint64_t hi = c.upper_u64;
            if (c.flags & Constraints::SEMI_CONSTRAINED)
                hi = lo + 1000;  // bounded sample for SEMI_CONSTRAINED
            if (lo > hi) hi = lo;
            uint64_t v = std::uniform_int_distribution<uint64_t>{lo, hi}(rng_);
            static_cast<UInteger*>(obj)->set(v);
            break;
        }
        int64_t lo = -1000, hi = 1000;
        if (c.flags & Constraints::CONSTRAINED) {
            lo = c.lower_bound;
            hi = c.upper_bound;
            if (lo > hi) hi = std::numeric_limits<int64_t>::max();
        } else if (c.flags & Constraints::SEMI_CONSTRAINED) {
            lo = c.lower_bound;
            hi = lo + 1000;
        }
        int64_t v = std::uniform_int_distribution<int64_t>{lo, hi}(rng_);
        static_cast<Integer*>(obj)->set(v);
        break;
    }

    case UT::Real: {
        double v = std::uniform_real_distribution<double>{-1e6, 1e6}(rng_);
        static_cast<Real*>(obj)->set(v);
        break;
    }

    case UT::Null:
        // Nothing to set — Null has no data.
        break;

    case UT::OctetString: {
        auto [lo, hi] = size_range(def.constraints,
                                   cfg_.min_str_len, cfg_.max_str_len);
        int len = rand_int(lo, hi);
        std::vector<uint8_t> b(len);
        for (auto& byte : b)
            byte = static_cast<uint8_t>(rand_int(0, 255));
        static_cast<OctetString*>(obj)->set(std::move(b));
        break;
    }

    case UT::BitString: {
        auto [lo, hi] = size_range(def.constraints,
                                   cfg_.min_str_len, cfg_.max_str_len);
        int bits = rand_int(lo, hi);
        if (bits < 0) bits = 0;
        int byte_count = (bits + 7) / 8;
        uint8_t unused = (byte_count > 0)
            ? static_cast<uint8_t>((byte_count * 8) - bits)
            : 0;
        std::vector<uint8_t> b(byte_count);
        for (auto& byte : b)
            byte = static_cast<uint8_t>(rand_int(0, 255));
        if (!b.empty() && unused > 0)
            b.back() &= static_cast<uint8_t>(0xFF << unused);
        static_cast<BitString*>(obj)->set(std::move(b), unused);
        break;
    }

    case UT::Oid:
    case UT::RelativeOid: {
        // Fixed plausible OID — arbitrary OIDs are hard to generate validly.
        static_cast<Oid*>(obj)->set({1, 3, 6, 1, static_cast<uint32_t>(rand_int(1, 99))});
        break;
    }

    case UT::UtcTime: {
        // Fixed valid UTCTime: YYMMDDHHMMSSZ
        static_cast<UtcTime*>(obj)->set("240101120000Z");
        break;
    }

    case UT::GeneralizedTime: {
        // Fixed valid GeneralizedTime: YYYYMMDDHHMMSSZ
        static_cast<GeneralizedTime*>(obj)->set("20240101120000Z");
        break;
    }

    // All string types share AsnString<N> layout (std::string at offset 0).
    case UT::Utf8String:
    case UT::NumericString:
    case UT::PrintableString:
    case UT::T61String:
    case UT::Ia5String:
    case UT::VisibleString:
    case UT::GeneralString:
    case UT::UniversalString:
    case UT::BmpString:
    case UT::ObjectDescriptor:
    case UT::VideotexString:
    case UT::GraphicString:
    {
        const auto& c = def.constraints;
        auto [lo, hi] = size_range(c, cfg_.min_str_len, cfg_.max_str_len);
        int len = rand_int(lo, hi);
        // Alphabet precedence (single source: Alphabets.hpp):
        //   1. FROM constraint (c.alphabet) — schema-explicit charset.
        //   2. Type built-in (NumericString / PrintableString / Visible /
        //      IA5) via builtin_alphabet(tag).
        //   3. DEFAULT_STRING_ALPHABET — printable subset for unrestricted
        //      types (Utf8 / BMP / General / Graphic / Videotex / ObjDesc).
        std::string_view alpha;
        std::string_view from_view;
        if (!c.alphabet.empty()) {
            from_view = std::string_view(
                reinterpret_cast<const char*>(c.alphabet.data()),
                c.alphabet.size());
            alpha = from_view;
        } else if (auto a = builtin_alphabet(def.tag.number); !a.empty()) {
            alpha = a;
        } else {
            alpha = DEFAULT_STRING_ALPHABET;
        }
        detail::asnstring_assign(obj, random_from_alphabet(alpha, len));
        break;
    }

    default:
        // Unknown/context tag — leave zero-initialised.
        break;
    }
}

} // namespace asn1
