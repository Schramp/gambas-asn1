// BER SEQUENCE and CHOICE encode/decode tests using hand-crafted types
// (the compiler will generate these structs from ASN.1 files;
//  here we write them manually to test the runtime library).

#include <cstdio>
#include <cstdlib>
#include <optional>
#include <variant>
#include <vector>
#include <asn1cpp/asn1cpp.hpp>

using namespace asn1;

static int failures = 0;
static void check(const char* name, bool cond, const char* detail = "") {
    if (cond) printf("  \033[32mPASS\033[0m  %s\n", name);
    else { printf("  \033[31mFAIL\033[0m  %s%s%s\n", name, *detail ? ": " : "", detail); ++failures; }
}

// ============================================================================
// Hand-crafted generated types (simulating compiler output)
// ============================================================================

// MySeq ::= SEQUENCE { a INTEGER, b UTF8String OPTIONAL }
struct MySeq {
    Integer                  a{};
    std::optional<Utf8String> b;
};

template<> struct asn1::BerTraits<MySeq> {
    static Tag tag() { return Tag::universal(UniversalTag::Sequence, true); }

    static void encode(BerWriter& w, const MySeq& v) {
        w.write_constructed(tag(), [&](BerWriter& inner) {
            BerTraits<Integer>::encode(inner, v.a);
            if (v.b) BerTraits<Utf8String>::encode(inner, *v.b);
        });
    }

    static Expected<MySeq, DecodeError> decode(BerReader& r) {
        auto tlv = r.read_tlv();
        if (!tlv) return make_unexpected<MySeq, DecodeError>(tlv.error());
        MySeq result{};
        BerReader inner = r.sub(tlv->value);
        {
            auto v = BerTraits<Integer>::decode(inner);
            if (!v) return make_unexpected<MySeq, DecodeError>(v.error());
            result.a = *v;
        }
        if (!inner.at_end()) {
            auto v = BerTraits<Utf8String>::decode(inner);
            if (v) result.b = *v;
        }
        return result;
    }
};

// MyChoice ::= CHOICE { i INTEGER, s UTF8String }
struct MyChoice {
    enum class PR { NOTHING, i, s } present{PR::NOTHING};
    std::variant<std::monostate, Integer, Utf8String> choice;
};

template<> struct asn1::BerTraits<MyChoice> {
    static Tag tag() { return Tag::universal(UniversalTag::Sequence, true); }

    static void encode(BerWriter& w, const MyChoice& v) {
        std::visit([&](const auto& alt) {
            using T = std::decay_t<decltype(alt)>;
            if constexpr (!std::is_same_v<T, std::monostate>)
                BerTraits<T>::encode(w, alt);
        }, v.choice);
    }

    static Expected<MyChoice, DecodeError> decode(BerReader& r) {
        // Peek at the next tag to determine the alternative
        auto saved_pos = r.pos();
        auto tag_r = r.read_tag();
        if (!tag_r) return make_unexpected<MyChoice, DecodeError>(tag_r.error());
        // Rewind — BerReader is not seekable, so we need a workaround via sub-span peek
        // In practice the generated code uses the outer TLV's value span directly
        (void)saved_pos;
        return make_unexpected<MyChoice, DecodeError>(
            DecodeError("MyChoice::decode: demonstration only — full decode needs peek support"));
    }
};

// SeqOf ::= SEQUENCE OF INTEGER
using SeqOf = std::vector<Integer>;

// ============================================================================
int main() {
    printf("\n── SEQUENCE encode/decode ──────────────────────────────────────\n");

    // MySeq { a = 42, b = absent }
    MySeq s1;
    s1.a = Integer{42};
    auto enc1 = encode<BER>(s1);
    // Expected: 30 03 02 01 2A
    check("MySeq{42, absent} tag=0x30",      enc1[0] == 0x30);
    check("MySeq{42, absent} total length=5", enc1.size() == 5);
    check("MySeq{42, absent} a=0x02 0x01 0x2A",
          enc1[2] == 0x02 && enc1[3] == 0x01 && enc1[4] == 0x2A);

    // Round-trip
    auto dec1 = decode<BER, MySeq>(enc1);
    check("MySeq{42, absent} decode ok",     (bool)dec1);
    check("MySeq{42, absent} a==42",         dec1 && dec1->a.value() == 42);
    check("MySeq{42, absent} b absent",      dec1 && !dec1->b.has_value());

    // MySeq { a = 1, b = "Hi" }
    MySeq s2;
    s2.a = Integer{1};
    s2.b = Utf8String{"Hi"};
    auto enc2 = encode<BER>(s2);
    // 30 07 02 01 01 0C 02 48 69
    check("MySeq{1,'Hi'} tag=0x30",         enc2[0] == 0x30);
    check("MySeq{1,'Hi'} total length=9",    enc2.size() == 9);

    auto dec2 = decode<BER, MySeq>(enc2);
    check("MySeq{1,'Hi'} decode ok",         (bool)dec2);
    check("MySeq{1,'Hi'} a==1",              dec2 && dec2->a.value() == 1);
    check("MySeq{1,'Hi'} b=='Hi'",           dec2 && dec2->b && dec2->b->str() == "Hi");

    printf("\n── CHOICE encode ───────────────────────────────────────────────\n");

    MyChoice c1;
    c1.present = MyChoice::PR::i;
    c1.choice  = Integer{99};
    auto enc3 = encode<BER>(c1);
    // CHOICE encodes only the selected alternative: 02 01 63
    check("MyChoice{INTEGER=99} encoded as INTEGER TLV", enc3[0] == 0x02);
    check("MyChoice{INTEGER=99} value=99",               enc3[2] == 0x63);

    MyChoice c2;
    c2.present = MyChoice::PR::s;
    c2.choice  = Utf8String{"X"};
    auto enc4 = encode<BER>(c2);
    check("MyChoice{UTF8String='X'} encoded as UTF8String TLV", enc4[0] == 0x0C);

    printf("\n── SEQUENCE OF ─────────────────────────────────────────────────\n");

    std::vector<Integer> ints = {Integer{1}, Integer{2}, Integer{3}};
    auto enc5 = encode_sequence_of<BER>(ints);
    // 30 09 02 01 01 02 01 02 02 01 03
    check("SEQUENCE OF 3 INTEGERs tag=0x30",          enc5[0] == 0x30);
    check("SEQUENCE OF 3 INTEGERs total length=11",   enc5.size() == 11);

    auto dec5 = decode_sequence_of<BER, Integer>(enc5);
    check("SEQUENCE OF decoded ok",    (bool)dec5);
    check("SEQUENCE OF count=3",       dec5 && dec5->size() == 3);
    check("SEQUENCE OF [0]=1",         dec5 && (*dec5)[0].value() == 1);
    check("SEQUENCE OF [2]=3",         dec5 && (*dec5)[2].value() == 3);

    // Empty SEQUENCE OF
    std::vector<Integer> empty_ints;
    auto enc6 = encode_sequence_of<BER>(empty_ints);
    check("SEQUENCE OF empty encodes as 30 00", enc6 == std::vector<uint8_t>{0x30, 0x00});

    printf("\n── Nested SEQUENCE ─────────────────────────────────────────────\n");

    // Outer { Inner { a=7, b="Z" } }
    MySeq inner;
    inner.a = Integer{7};
    inner.b = Utf8String{"Z"};
    auto enc_inner = encode<BER>(inner);

    // Wrap in another SEQUENCE manually
    std::vector<uint8_t> outer_buf;
    BerWriter w(outer_buf);
    w.write_constructed(Tag::universal(UniversalTag::Sequence, true), [&](BerWriter& iw) {
        iw.append(enc_inner);
    });
    check("Nested SEQUENCE outer tag=0x30", outer_buf[0] == 0x30);
    check("Nested SEQUENCE inner tag=0x30", outer_buf[2] == 0x30);

    printf("\n");
    if (failures) { printf("  %d test(s) FAILED\n", failures); return 1; }
    printf("  All tests passed.\n");
    return 0;
}
