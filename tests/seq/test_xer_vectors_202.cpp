// XER vector test: asn1c data-202 (202-XIOTCertificate-OK.asn1).
//
// Decodes s1.xer (a minimal X.509-style certificate) and verifies field values.
// XER encodes BIT STRING in hex format (auto-detected by the decoder).
// No round-trip comparison because our encoder uses binary BIT STRING format.
#include <cstdio>
#include <cstring>
#include <fstream>
#include <string>
#include <filesystem>
#include <asn1cpp/asn1cpp.hpp>
#include <asn1cpp/codec/XerCodec.hpp>
#include "Certificate.hpp"
#include "TBSCertificate.hpp"
#include "Extensions.hpp"
#include "Extension.hpp"
#include "Name.hpp"
#include "DistinguishedName.hpp"
#include "CommonName.hpp"

using namespace asn1;
namespace fs = std::filesystem;

static int failures = 0;

static void check(const char* label, bool cond) {
    if (cond) printf("  \033[32mPASS\033[0m  %s\n", label);
    else      { printf("  \033[31mFAIL\033[0m  %s\n", label); ++failures; }
}

int main(int argc, char** argv) {
    const char* datadir = argc > 1 ? argv[1]
                                   : "tests/tests-c-compiler/data-202";

    printf("\n── XER vectors: data-202 (202-XIOTCertificate-OK.asn1) ─────────────\n");

    fs::path xer_path = fs::path(datadir) / "s1.xer";
    std::ifstream f(xer_path);
    if (!f) {
        fprintf(stderr, "Cannot open %s\n", xer_path.c_str());
        return 1;
    }
    std::string xml((std::istreambuf_iterator<char>(f)), {});

    // s1.xer uses non-standard asn1c extensions: hex BIT STRING and text BOOLEAN.
    Certificate cert{};
    XerDecodeStream xs{xml, XerDecodeMode::Lenient};
    auto r = XerCodec::instance().decode(xs, Certificate::asn_DEF, &cert);
    check("s1.xer  XER decode ok", r.has_value());
    if (!r) {
        printf("  error: %s\n", r.error().message.c_str());
        return 1;
    }

    auto& tbs = cert.tbsCertificate;

    // version = 2 (named value v3(2))
    check("s1.xer  version == 2", (int64_t)tbs.version == 2);

    // signature BIT STRING: hex "3045..." = 69 bytes
    check("s1.xer  signature bit size == 69 bytes", cert.signature.bytes().size() == 69);
    check("s1.xer  signature unused bits == 0", cert.signature.unused_bits() == 0);

    // subjectPublicKey BIT STRING: hex "04AA..." = 32 bytes
    check("s1.xer  subjectPublicKey byte size == 32",
          tbs.subjectPublicKeyInfo.subjectPublicKey.bytes().size() == 32);

    // issuer: SEQUENCE SIZE(1) OF DistinguishedName, each SET SIZE(1) OF CommonName
    check("s1.xer  issuer has 1 DistinguishedName", tbs.issuer.size() == 1);
    check("s1.xer  issuer[0] has 1 CommonName", tbs.issuer[0].size() == 1);
    {
        const CommonName& cn = tbs.issuer[0][0];
        std::string v(cn.value.str().begin(), cn.value.str().end());
        check("s1.xer  issuer CommonName == \"XIOT Root CA\"",
              v == "XIOT Root CA");
    }

    // extensions: OPTIONAL, present with 1 extension
    check("s1.xer  extensions present", tbs.extensions != nullptr);
    if (tbs.extensions) {
        check("s1.xer  extensions has 1 entry", tbs.extensions->size() == 1);
        if (tbs.extensions->size() >= 1) {
            const Extension& ext = (*tbs.extensions)[0];
            // critical DEFAULT FALSE but s1.xer sets it to true
            check("s1.xer  extension critical present", ext.critical != nullptr);
            if (ext.critical)
                check("s1.xer  extension critical == true", ext.critical->value() == true);
            // extnValue OCTET STRING: hex "30030101FF" = 5 bytes
            check("s1.xer  extnValue byte size == 5", ext.extnValue.size() == 5);
        }
    }

    // BER round-trip
    std::vector<uint8_t> ber_buf;
    BerWriter w{ber_buf};
    BerEncodeStream bs{w};
    BerCodec::instance().encode(bs, Certificate::asn_DEF, &cert);
    check("s1.xer  BER encode non-empty", !ber_buf.empty());

    if (!ber_buf.empty()) {
        Certificate cert2{};
        BerReader rb{std::span<const uint8_t>{ber_buf}};
        BerDecodeStream rbs{rb};
        auto r2 = BerCodec::instance().decode(rbs, Certificate::asn_DEF, &cert2);
        check("s1.xer  BER decode ok", r2.has_value());
        if (r2) {
            check("s1.xer  BER round-trip version", (int64_t)cert2.tbsCertificate.version == 2);
            check("s1.xer  BER round-trip signature size",
                  cert2.signature.bytes().size() == 69);
        }
    }

    printf("\n  %d failure(s).\n", failures);
    if (failures) return 1;
    printf("  All tests passed.\n");
    return 0;
}
