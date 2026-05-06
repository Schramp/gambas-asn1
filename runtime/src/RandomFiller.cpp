#include <asn1cpp/codec/RandomFiller.hpp>
#include <limits>
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

std::string RandomFiller::random_printable(int len) {
    static constexpr std::string_view chars =
        "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789 ";
    std::uniform_int_distribution<int> pick{0, static_cast<int>(chars.size()) - 1};
    std::string s;
    s.reserve(len);
    for (int i = 0; i < len; ++i)
        s += chars[pick(rng_)];
    return s;
}

// ---------------------------------------------------------------------------
// top-level dispatch
// ---------------------------------------------------------------------------

void RandomFiller::fill(void* obj, const TypeDescriptor& def, int depth, bool mandatory) {
    if (depth > 1000) return;                          // absolute safety — catches recursive mandatory cycles
    if (!mandatory && depth > cfg_.max_depth) return;  // soft limit — only skips optional paths

    if (def.is_any) {
        // Encode a small random INTEGER as the raw ANY bytes.
        // ANY is stored as OctetString in the runtime.
        std::vector<uint8_t> buf;
        BerWriter w{buf};
        int64_t v = std::uniform_int_distribution<int64_t>{-127, 127}(rng_);
        Integer iv{v};
        BerTraits<Integer>::encode(w, iv);
        new (obj) OctetString{std::move(buf)};
        return;
    }
    if (def.enum_spec)     { fill_enum(obj, *def.enum_spec); return; }
    if (def.sequence_spec) { fill_sequence(obj, *def.sequence_spec, depth); return; }
    if (def.choice_spec)   { fill_choice  (obj, *def.choice_spec,   depth); return; }
    if (def.seq_of_spec)   { fill_seq_of  (obj, *def.seq_of_spec,   depth); return; }
    fill_primitive(obj, def);
}

// ---------------------------------------------------------------------------
// ENUMERATED
// ---------------------------------------------------------------------------

void RandomFiller::fill_enum(void* obj, const EnumSpec& spec) {
    // Pick from root values only (extension enums may be unknown to asn1c).
    int n = spec.root_count > 0 ? spec.root_count : spec.count;
    if (n == 0) return;
    int idx = rand_int(0, n - 1);
    *static_cast<long*>(obj) = spec.entries[idx].value;
}

// ---------------------------------------------------------------------------
// SEQUENCE / SET
// ---------------------------------------------------------------------------

void RandomFiller::fill_sequence(void* obj, const SequenceSpec& spec, int depth) {
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
        fill(mptr, *mbr.type_descriptor, depth + 1, is_mand);
    }
}

// ---------------------------------------------------------------------------
// CHOICE
// ---------------------------------------------------------------------------

void RandomFiller::fill_choice(void* obj, const ChoiceSpec& spec, int depth) {
    if (spec.count == 0) return;

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

    // The chosen alternative is mandatory — bypass soft limit but still increment depth.
    fill(aptr, *alt.type_descriptor, depth + 1, true);
}

// ---------------------------------------------------------------------------
// SEQUENCE OF / SET OF
// ---------------------------------------------------------------------------

void RandomFiller::fill_seq_of(void* obj, const SeqOfSpec& spec, int depth) {
    int lo = cfg_.min_seq_of;
    int hi = cfg_.max_seq_of;

    // Respect SIZE constraints if present.
    const auto& sc = spec.size_constraints;
    if (sc.flags & PerConstraints::SIZE_CONSTRAINED) {
        lo = std::max(lo, static_cast<int>(sc.size_lower));
        hi = std::min(hi, static_cast<int>(sc.size_upper));
        if (lo > hi) lo = hi;
    }

    // Exponential backoff: halve effective max every 2 depth levels so that
    // total data stays bounded regardless of max_depth.  Without this, nested
    // SEQUENCE OFs multiply as max_seq^nesting_levels.
    int depth_hi = std::max(cfg_.min_seq_of, cfg_.max_seq_of >> (depth / 2));
    hi = std::min(hi, depth_hi);

    int n = rand_int(lo, hi);
    spec.resize_fn(obj, static_cast<std::size_t>(n));

    for (int i = 0; i < n; ++i) {
        void* eptr = spec.get_fn(obj, static_cast<std::size_t>(i));
        // Mandatory minimum elements bypass soft limit but still increment depth.
        bool mand = (i < lo);
        fill(eptr, *spec.element, depth + 1, mand);
    }
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
        new (obj) Boolean{coin(0.5)};
        break;
    }

    case UT::Integer: {
        int64_t lo = -1000, hi = 1000;
        const auto& c = def.per_constraints;
        if (c.flags & PerConstraints::CONSTRAINED) {
            lo = c.lower_bound;
            hi = c.upper_bound;
            // upper_bound overflows int64_t for types like (0..18446744073709551615)
            // (ETSI schemas assume unsigned 64-bit; asn1c treats INTEGER as signed).
            // Clamp to INT64_MAX so the range stays valid and values are in-range.
            if (lo > hi) hi = std::numeric_limits<int64_t>::max();
        } else if (c.flags & PerConstraints::SEMI_CONSTRAINED) {
            lo = c.lower_bound;
            hi = lo + 1000;
        }
        int64_t v = std::uniform_int_distribution<int64_t>{lo, hi}(rng_);
        new (obj) Integer{v};
        break;
    }

    case UT::Real: {
        double v = std::uniform_real_distribution<double>{-1e6, 1e6}(rng_);
        new (obj) Real{v};
        break;
    }

    case UT::Null:
        // Nothing to set — Null has no data.
        break;

    case UT::OctetString: {
        int lo = cfg_.min_str_len, hi = cfg_.max_str_len;
        const auto& c = def.per_constraints;
        if (c.flags & PerConstraints::SIZE_CONSTRAINED) {
            int64_t clo = c.size_lower, chi = c.size_upper;
            if (clo >= 0 && clo <= 65536) lo = static_cast<int>(clo);
            if (chi >= lo && chi <= 65536) hi = static_cast<int>(chi);
            if (lo > hi) hi = lo;
        }
        int len = rand_int(lo, hi);
        std::vector<uint8_t> b(len);
        for (auto& byte : b)
            byte = static_cast<uint8_t>(rand_int(0, 255));
        new (obj) OctetString{std::move(b)};
        break;
    }

    case UT::BitString: {
        int lo = cfg_.min_str_len, hi = cfg_.max_str_len;
        const auto& c = def.per_constraints;
        if (c.flags & PerConstraints::SIZE_CONSTRAINED) {
            int64_t clo = c.size_lower, chi = c.size_upper;
            // Guard against overflow (e.g. SIZE(0..4294967295) stored as int64_t).
            if (clo >= 0 && clo <= 65536) lo = static_cast<int>(clo);
            if (chi >= lo && chi <= 65536) hi = static_cast<int>(chi);
            if (lo > hi) hi = lo;
        }
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
        new (obj) BitString{std::move(b), unused};
        break;
    }

    case UT::Oid:
    case UT::RelativeOid: {
        // Fixed plausible OID — arbitrary OIDs are hard to generate validly.
        new (obj) Oid{{1, 3, 6, 1, static_cast<uint32_t>(rand_int(1, 99))}};
        break;
    }

    case UT::UtcTime: {
        // Fixed valid UTCTime: YYMMDDHHMMSSZ
        new (obj) UtcTime{"240101120000Z"};
        break;
    }

    case UT::GeneralizedTime: {
        // Fixed valid GeneralizedTime: YYYYMMDDHHMMSSZ
        new (obj) GeneralizedTime{"20240101120000Z"};
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
        int lo = cfg_.min_str_len, hi = cfg_.max_str_len;
        const auto& c = def.per_constraints;
        if (c.flags & PerConstraints::SIZE_CONSTRAINED) {
            int64_t clo = c.size_lower, chi = c.size_upper;
            if (clo >= 0 && clo <= 65536) lo = static_cast<int>(clo);
            if (chi >= lo && chi <= 65536) hi = static_cast<int>(chi);
            if (lo > hi) hi = lo;
        }
        // If an alphabet constraint is present, pick chars from it.
        std::string s;
        int len = rand_int(lo, hi);
        if (!c.alphabet.empty()) {
            std::uniform_int_distribution<int> pick{
                0, static_cast<int>(c.alphabet.size()) - 1};
            s.reserve(len);
            for (int i = 0; i < len; ++i)
                s += static_cast<char>(c.alphabet[pick(rng_)]);
        } else {
            s = random_printable(len);
        }
        detail::asnstring_assign(obj, s);
        break;
    }

    default:
        // Unknown/context tag — leave zero-initialised.
        break;
    }
}

} // namespace asn1
