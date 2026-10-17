// Encode/decode failures are reported, never abort the process (Debug
// build included), in all four codecs:
//   - a descriptor routed to a codec's fallback dispatch slot (a type with
//     no handler, here universal tag 11 EMBEDDED PDV): encode sets the
//     stream's encode_failed(), decode returns an error;
//   - a CHOICE with no alternative selected (_present == 0): encode sets
//     encode_failed() instead of silently writing nothing.
#include <cstdio>
#include <span>
#include <sstream>
#include <vector>
#include <asn1cpp/asn1cpp.hpp>
#include <asn1cpp/codec/BerCodec.hpp>
#include <asn1cpp/codec/JerCodec.hpp>
#include <asn1cpp/codec/PerCodec.hpp>
#include <asn1cpp/codec/XerCodec.hpp>
#include "MsgV1.hpp"

using namespace asn1;

static int failures = 0;

static void check(const char* label, bool cond) {
    if (cond) printf("  \033[32mPASS\033[0m  %s\n", label);
    else      { printf("  \033[31mFAIL\033[0m  %s\n", label); ++failures; }
}

static bool ber_enc_failed(const TypeDescriptor& def, const Asn1Object* obj) {
    std::vector<uint8_t> buf;
    BerWriter w{buf};
    BerEncodeStream s{w};
    BerCodec::instance().encode(s, def, obj);
    return s.encode_failed();
}

static bool xer_enc_failed(const TypeDescriptor& def, const Asn1Object* obj) {
    std::ostringstream os;
    XerEncodeStream s{os};
    XerCodec::instance().encode(s, def, obj);
    return s.encode_failed();
}

static bool jer_enc_failed(const TypeDescriptor& def, const Asn1Object* obj) {
    std::ostringstream os;
    JerEncodeStream s{os};
    JerCodec::instance().encode(s, def, obj);
    return s.encode_failed();
}

static bool per_enc_failed(const TypeDescriptor& def, const Asn1Object* obj) {
    std::vector<uint8_t> buf;
    PerEncodeStream s{buf};
    IEncodeStream& es = s;
    PerCodec::instance().encode(es, def, obj);
    return s.encode_failed();
}

int main() {
    printf("\n── encode/decode failure reporting ──\n");

    const TypeDescriptor stub{"EmbeddedPdvStub", Tag{TagClass::Universal, 11, false}};
    Null value;
    check("BER encode of a type with no handler fails", ber_enc_failed(stub, &value));
    check("XER encode of a type with no handler fails", xer_enc_failed(stub, &value));
    check("JER encode of a type with no handler fails", jer_enc_failed(stub, &value));
    check("PER encode of a type with no handler fails", per_enc_failed(stub, &value));

    {
        const uint8_t ber[] = {0x2B, 0x00};
        BerReader r{std::span<const uint8_t>{ber}};
        BerDecodeStream s{r};
        check("BER decode of a type with no handler is an error",
              !BerCodec::instance().decode(s, stub, &value));
    }
    {
        XerDecodeStream s{"<EmbeddedPdvStub/>"};
        check("XER decode of a type with no handler is an error",
              !XerCodec::instance().decode(s, stub, &value));
    }
    {
        JerDecodeStream s{"null"};
        check("JER decode of a type with no handler is an error",
              !JerCodec::instance().decode(s, stub, &value));
    }
    {
        const uint8_t per[] = {0x00};
        PerDecodeStream s{std::span<const uint8_t>{per}};
        IDecodeStream& ds = s;
        check("PER decode of a type with no handler is an error",
              !PerCodec::instance().decode(ds, stub, &value));
    }

    MsgV1 none;
    check("BER encode of a CHOICE with no alternative fails", ber_enc_failed(MsgV1::asn_DEF, &none));
    check("XER encode of a CHOICE with no alternative fails", xer_enc_failed(MsgV1::asn_DEF, &none));
    check("JER encode of a CHOICE with no alternative fails", jer_enc_failed(MsgV1::asn_DEF, &none));
    check("PER encode of a CHOICE with no alternative fails", per_enc_failed(MsgV1::asn_DEF, &none));

    MsgV1 a;
    a.set_present(MsgV1::PR::a);
    a.a() = Integer{5};
    check("BER encode of a selected alternative succeeds", !ber_enc_failed(MsgV1::asn_DEF, &a));
    check("XER encode of a selected alternative succeeds", !xer_enc_failed(MsgV1::asn_DEF, &a));
    check("JER encode of a selected alternative succeeds", !jer_enc_failed(MsgV1::asn_DEF, &a));
    check("PER encode of a selected alternative succeeds", !per_enc_failed(MsgV1::asn_DEF, &a));

    printf("\n%s (%d failure%s)\n", failures ? "FAILED" : "PASSED", failures, failures == 1 ? "" : "s");
    return failures ? 1 : 0;
}
