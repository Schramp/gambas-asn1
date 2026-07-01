// JER SEQUENCE OF encode/decode unit test (#157/#158)
// Uses gen_seq_of_test (ByteList/StrList).
#include <cstdio>
#include <sstream>
#include <string>
#include <asn1cpp/asn1cpp.hpp>
#include <asn1cpp/codec/JerCodec.hpp>

#include "ByteList.hpp"
#include "StrList.hpp"

using namespace asn1;

static int failures = 0;

static void check(const char* name, bool cond, const char* detail = "") {
    if (cond) {
        std::printf("  \033[32mPASS\033[0m  %s\n", name);
    } else {
        std::printf("  \033[31mFAIL\033[0m  %s%s%s\n", name, *detail ? ": " : "", detail);
        ++failures;
    }
}

static std::string jer_encode(const TypeDescriptor& def, const Asn1Object* obj) {
    std::ostringstream oss;
    JerEncodeStream s{oss};
    JerCodec::instance().encode(s, def, obj);
    return oss.str();
}

template<typename T>
bool jer_roundtrip(const TypeDescriptor& def, const T& v) {
    std::string json = jer_encode(def, &v);
    T out{};
    JerDecodeStream ds{json};
    auto r = JerCodec::instance().decode(ds, def, &out);
    if (!r) {
        std::fprintf(stderr, "    decode error: %s  json=%s\n", r.error().message.c_str(), json.c_str());
        return false;
    }
    return out == v;
}

int main() {
    std::printf("\n── SEQUENCE OF (ByteList) ──────────────────────────────────\n");
    {
        ByteList empty{};
        check("empty encodes []", jer_encode(asn_DEF_ByteList, &empty) == "[]");
        check("empty round-trip", jer_roundtrip(asn_DEF_ByteList, empty));
    }
    {
        ByteList v{MyByte{1}, MyByte{2}, MyByte{3}};
        check("ByteList{1,2,3} encodes", jer_encode(asn_DEF_ByteList, &v) == "[1,2,3]");
        check("ByteList{1,2,3} round-trip", jer_roundtrip(asn_DEF_ByteList, v));
    }
    {
        // Decode from JSON
        ByteList out{};
        JerDecodeStream ds{"[10,20,30]"};
        auto r = JerCodec::instance().decode(ds, asn_DEF_ByteList, &out);
        check("ByteList decode count",  r.has_value() && out.count() == 3);
        check("ByteList decode [0]=10", r && static_cast<const MyByte&>(*out.get_const(0)) == Integer{10});
        check("ByteList decode [2]=30", r && static_cast<const MyByte&>(*out.get_const(2)) == Integer{30});
    }

    std::printf("\n── SEQUENCE OF (StrList) ───────────────────────────────────\n");
    {
        StrList sl{MyStr{"hi"}, MyStr{"world"}};
        check("StrList round-trip", jer_roundtrip(asn_DEF_StrList, sl));
        std::string enc = jer_encode(asn_DEF_StrList, &sl);
        check("StrList encodes",    enc == "[\"hi\",\"world\"]");
    }

    std::printf("\n── Result ──────────────────────────────────────────────────\n");
    if (failures == 0)
        std::printf("\n\033[32mAll JER SEQUENCE OF tests passed.\033[0m\n\n");
    else
        std::printf("\n\033[31m%d test(s) FAILED.\033[0m\n\n", failures);
    return failures ? 1 : 0;
}
