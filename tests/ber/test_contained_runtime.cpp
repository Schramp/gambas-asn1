// Contained values (X.682 §11): Containing<T> value semantics and the
// built-in contained-value decoders, on an INTEGER inner type.
#include <cstdio>
#include <vector>
#include <asn1cpp/asn1cpp.hpp>

using namespace asn1;

static int failures = 0;
static void check(const char* name, bool cond) {
    printf("  %s  %s\n", cond ? "PASS" : "FAIL", name);
    if (!cond) ++failures;
}

static const ContainedSpec k_spec{&asn_DEF_Integer, &ContainedOpsFor<Integer>::ops,
                                  ContainedEncoding::Ber, true, "plain"};

/// Run the named built-in decoder on \p raw into a fresh Integer.
static ContainedResult run(const char* decoder, std::vector<uint8_t> raw, int64_t* out = nullptr,
                           const ContainedDecoders& reg = ContainedDecoders::defaults()) {
    Integer v;
    ContainedDecodeArgs a{raw, k_spec, v, nullptr, nullptr, ContainedEncoding::Ber, DecodeDepth{}, reg, nullptr};
    auto r = reg.find(decoder)->decode(a);
    if (out) *out = v.value();
    return r;
}

int main() {
    // INTEGER 0x1234 = 02 02 12 34
    int64_t v = 0;
    check("plain decodes exactly one value",
          run("plain", {0x02, 0x02, 0x12, 0x34}, &v).status == ContainedStatus::Decoded && v == 0x1234);
    check("plain rejects trailing octets",
          run("plain", {0x02, 0x02, 0x12, 0x34, 0x00}).status == ContainedStatus::Failed);
    check("plain reports a bad encoding",
          run("plain", {0x02, 0x05, 0x12}).status == ContainedStatus::Failed);

    auto zp = run("zero_padding", {0x02, 0x02, 0x12, 0x34, 0x00, 0x00, 0x00}, &v);
    check("zero_padding accepts a zero tail", zp.status == ContainedStatus::Decoded && zp.message.empty() && v == 0x1234);
    // A value ending in 0x00 must not be cut: 02 02 12 00 is 0x1200.
    zp = run("zero_padding", {0x02, 0x02, 0x12, 0x00, 0x00, 0x00}, &v);
    check("zero_padding keeps a value ending in 0x00", zp.status == ContainedStatus::Decoded && v == 0x1200);
    zp = run("zero_padding", {0x02, 0x02, 0x12, 0x34, 0x00, 0x07}, &v);
    check("zero_padding reports a non-zero tail but keeps the value",
          zp.status == ContainedStatus::Decoded && !zp.message.empty() && v == 0x1234);

    check("pkcs7 strips valid padding",
          run("pkcs7", {0x02, 0x02, 0x12, 0x34, 0x04, 0x04, 0x04, 0x04}, &v).status == ContainedStatus::Decoded && v == 0x1234);
    check("pkcs7 rejects inconsistent padding",
          run("pkcs7", {0x02, 0x02, 0x12, 0x34, 0x04, 0x03, 0x04, 0x04}).status == ContainedStatus::Failed);
    check("pkcs7 rejects a zero pad length",
          run("pkcs7", {0x02, 0x02, 0x12, 0x34, 0x00}).status == ContainedStatus::Failed);
    check("pkcs7 rejects an empty value", run("pkcs7", {}).status == ContainedStatus::Failed);
    check("none skips", run("none", {0x02, 0x01, 0x05}).status == ContainedStatus::Skipped);

    // pkcs7 encode pads to the block size; a full block of padding when aligned.
    {
        Integer i{0x1234};
        std::vector<uint8_t> out;
        std::string err;
        ContainedEncodeArgs ea{i, k_spec, ContainedEncoding::Ber, ContainedDecoders::defaults(), nullptr};
        bool ok = ContainedDecoders::defaults().find("pkcs7")->encode(ea, out, err);
        check("pkcs7 encode pads to 16", ok && out.size() == 16 && out.back() == 12);
        out.clear();
        ContainedDecoders reg;
        reg.pkcs7_block_size = 4;
        ContainedEncodeArgs eb{i, k_spec, ContainedEncoding::Ber, reg, nullptr};
        ok = reg.find("pkcs7")->encode(eb, out, err);
        check("pkcs7 encode adds a whole block when aligned", ok && out.size() == 8 && out.back() == 4);
    }

    // An application decoder replacing a built-in name, calling decode_value
    // after its own transform (here: XOR 0x5A).
    {
        ContainedDecoders reg;
        reg.add("plain", [](const ContainedDecodeArgs& a) {
            std::vector<uint8_t> plain(a.raw.begin(), a.raw.end());
            for (auto& b : plain) b ^= 0x5A;
            return ContainedDecoders::decode_value(a, plain);
        });
        std::vector<uint8_t> enc{0x02 ^ 0x5A, 0x01 ^ 0x5A, 0x07 ^ 0x5A};
        check("application decoder overrides a built-in",
              run("plain", enc, &v, reg).status == ContainedStatus::Decoded && v == 7);
    }

    // Built-in names resolve through the registry's index table, also after
    // an override and in a copy (which must point at its own entries).
    {
        ContainedSpec zp = k_spec;
        zp.decoder = "zero_padding";
        zp.builtin = 1;
        ContainedDecoders reg;
        check("resolve built-in by index", reg.resolve(zp) == reg.find("zero_padding"));
        ContainedDecoders copy = reg;
        check("copy resolves to its own entry", copy.resolve(zp) == copy.find("zero_padding") &&
                                                copy.resolve(zp) != reg.resolve(zp));
        reg.add("zero_padding", [](const ContainedDecodeArgs&) { return ContainedResult::skipped("x"); });
        check("override replaces the indexed entry", reg.resolve(zp) == reg.find("zero_padding"));
        check("copy keeps the original", copy.resolve(zp) != reg.resolve(zp));
        ContainedSpec custom = k_spec;
        custom.decoder = "li_decrypt";
        custom.builtin = kCustomDecoder;
        check("custom name is looked up", reg.resolve(custom) == nullptr);
        reg.add("li_decrypt", [](const ContainedDecodeArgs&) { return ContainedResult::ok(); });
        check("custom name resolves after add", reg.resolve(custom) == reg.find("li_decrypt"));
    }

    // Containing<T> value semantics.
    {
        Containing<Integer> c;
        check("fresh value: not decoded, no value", c.status() == ContainedStatus::NotDecoded && !c.has_value());
        std::vector<uint8_t> raw{0x02, 0x01, 0x05};
        c.set_raw_from_wire(raw, ContainedEncoding::Ber);
        c.emplace_value_object(ContainedOpsFor<Integer>::ops);
        static_cast<Integer*>(c.value_object())->set(5);
        c.set_status(ContainedStatus::Decoded);
        check("decoded value is reachable", c.value() && c.value()->value() == 5 && !c.dirty());

        Containing<Integer> copy = c;
        check("copy clones the inner value", copy.value() && copy.value() != c.value() && copy.value()->value() == 5);
        check("equality compares the raw bytes", copy == c);

        Containing<Integer> moved = std::move(copy);
        check("move takes the inner value", moved.value() && moved.value()->value() == 5 && !copy.has_value());

        c.value_mut()->set(6);
        check("value_mut marks dirty", c.dirty() && c.status() == ContainedStatus::Decoded);
        c.set(std::vector<uint8_t>{0x02, 0x01, 0x09});
        check("setting raw bytes drops the inner value", !c.has_value() && c.status() == ContainedStatus::NotDecoded && !c.dirty());
        c.set_value(Integer{42});
        check("set_value makes a dirty decoded value", c.value()->value() == 42 && c.dirty());
        c.set_status(ContainedStatus::Failed, "boom");
        check("a failure drops the value and keeps the reason", !c.has_value() && c.error() == "boom");
    }

    printf("%s\n", failures ? "FAILED" : "all passed");
    return failures ? 1 : 0;
}
