// Tests for collision-prefixed C++ name generation.
// Schema: tests/asn1/collision_test.asn1
// CollisionModA::Status + CollisionModB::Status → CollisionModAStatus / CollisionModBStatus
// Both named "Status" in their TypeDescriptor (original ASN.1 name preserved).
#include <cstdio>
#include <vector>
#include <span>
#include <sstream>
#include <string>
#include <asn1cpp/asn1cpp.hpp>
#include "CollisionModAWrapper.hpp"
#include "CollisionModBWrapper.hpp"

using namespace asn1;
static int failures = 0;

static void check(const char* name, bool cond) {
    if (cond) printf("  \033[32mPASS\033[0m  %s\n", name);
    else     { printf("  \033[31mFAIL\033[0m  %s\n", name); ++failures; }
}

template<typename T>
static std::vector<uint8_t> ber_enc(const T& v, const TypeDescriptor& def) {
    std::vector<uint8_t> buf; BerWriter w{buf};
    BerEncodeStream s{w}; BerCodec::instance().encode(s, def, &v); return buf;
}
template<typename T>
static bool ber_dec(std::span<const uint8_t> b, T& out, const TypeDescriptor& def) {
    BerReader r{b}; BerDecodeStream s{r};
    return BerCodec::instance().decode(s, def, &out).has_value();
}
template<typename T>
static std::string xer_enc(const T& v, const TypeDescriptor& def) {
    std::ostringstream o; XerEncodeStream s{o};
    XerCodec::instance().encode(s, def, &v); return o.str();
}

int main() {
    printf("\n── Collision: distinct C++ types, same ASN.1 name ───────────────\n");

    // TypeDescriptor names carry original ASN.1 name "Status", not the C++ struct name
    check("CollisionModAStatus asn_DEF name == \"Status\"",
          std::string(asn_DEF_CollisionModAStatus.name) == "Status");
    check("CollisionModBStatus asn_DEF name == \"Status\"",
          std::string(CollisionModBStatus::asn_DEF.name) == "Status");

    printf("\n── CollisionModAWrapper (INTEGER code) BER ───────────────────────\n");
    {
        CollisionModAWrapper v; v.code = 5;
        auto enc = ber_enc(v, CollisionModAWrapper::asn_DEF);
        CollisionModAWrapper got{};
        check("WrapperA{code=5} BER rt",
              ber_dec(enc, got, CollisionModAWrapper::asn_DEF) && got.code == 5);
    }
    {
        CollisionModAWrapper v; v.code = 0;
        auto enc = ber_enc(v, CollisionModAWrapper::asn_DEF);
        CollisionModAWrapper got{};
        check("WrapperA{code=0} BER rt",
              ber_dec(enc, got, CollisionModAWrapper::asn_DEF) && got.code == 0);
    }

    printf("\n── CollisionModAWrapper XER ──────────────────────────────────────\n");
    {
        CollisionModAWrapper v; v.code = 3;
        auto xml = xer_enc(v, CollisionModAWrapper::asn_DEF);
        check("WrapperA XER has <Wrapper>",  xml.find("<Wrapper>")  != std::string::npos);
        check("WrapperA XER has <code>",     xml.find("<code>")     != std::string::npos);
    }

    printf("\n── CollisionModBWrapper (ENUMERATED state) BER ───────────────────\n");
    {
        CollisionModBWrapper v; v.state = CollisionModBStatus::ok;
        auto enc = ber_enc(v, CollisionModBWrapper::asn_DEF);
        CollisionModBWrapper got{};
        check("WrapperB{ok} BER rt",
              ber_dec(enc, got, CollisionModBWrapper::asn_DEF)
              && got.state == CollisionModBStatus::ok);
    }
    {
        CollisionModBWrapper v; v.state = CollisionModBStatus::pending;
        auto enc = ber_enc(v, CollisionModBWrapper::asn_DEF);
        CollisionModBWrapper got{};
        check("WrapperB{pending} BER rt",
              ber_dec(enc, got, CollisionModBWrapper::asn_DEF)
              && got.state == CollisionModBStatus::pending);
    }

    printf("\n── CollisionModBWrapper XER ──────────────────────────────────────\n");
    {
        CollisionModBWrapper v; v.state = CollisionModBStatus::error;
        auto xml = xer_enc(v, CollisionModBWrapper::asn_DEF);
        check("WrapperB XER has <Wrapper>",  xml.find("<Wrapper>")  != std::string::npos);
        check("WrapperB XER has <state>",    xml.find("<state>")    != std::string::npos);
        check("WrapperB XER has <error/>",   xml.find("<error/>")   != std::string::npos);
    }

    printf("\n── Both wrappers encode independently ────────────────────────────\n");
    {
        // Encode both; their BER bytes should differ in structure (INTEGER vs ENUMERATED)
        CollisionModAWrapper a; a.code = 1;
        CollisionModBWrapper b; b.state = CollisionModBStatus::ok;
        auto ea = ber_enc(a, CollisionModAWrapper::asn_DEF);
        auto eb = ber_enc(b, CollisionModBWrapper::asn_DEF);
        check("WrapperA and WrapperB BER differ", ea != eb);
    }

    printf("\n");
    if (failures) { printf("  %d test(s) FAILED\n", failures); return 1; }
    printf("  All tests passed.\n");
    return 0;
}
