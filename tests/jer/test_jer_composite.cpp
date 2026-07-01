// JER composite-type encode/decode unit test (#157)
// Covers: SEQUENCE, CHOICE.
// Uses gen_choice_test (HasAlt2/HasAlt4/Alt2/Alt4 + MyByte/MyStr).
#include <cstdio>
#include <sstream>
#include <string>
#include <asn1cpp/asn1cpp.hpp>
#include <asn1cpp/codec/JerCodec.hpp>

// Generated types from choice_test.asn1
#include "HasAlt2.hpp"
#include "Alt2.hpp"
#include "HasAlt4.hpp"
#include "Alt4.hpp"
#include "MyByte.hpp"
#include "MyStr.hpp"

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
    // =========================================================================
    std::printf("\n── CHOICE ──────────────────────────────────────────────────\n");
    // =========================================================================
    {
        Alt2 a2;
        a2.set_present(Alt2::PR::num);
        a2.num() = MyByte{42};
        std::string enc = jer_encode(Alt2::asn_DEF, &a2);
        check("CHOICE num encodes",     enc == "{\"num\":42}");
        check("CHOICE num round-trip",  jer_roundtrip(Alt2::asn_DEF, a2));
    }
    {
        Alt2 a2;
        a2.set_present(Alt2::PR::flag);
        a2.flag() = Boolean{true};
        std::string enc = jer_encode(Alt2::asn_DEF, &a2);
        check("CHOICE BOOLEAN encodes",    enc == "{\"flag\":true}");
        check("CHOICE BOOLEAN round-trip", jer_roundtrip(Alt2::asn_DEF, a2));
    }
    {
        Alt4 a4;
        a4.set_present(Alt4::PR::str);
        a4.str() = MyStr{"hello"};
        std::string enc = jer_encode(Alt4::asn_DEF, &a4);
        check("CHOICE str encodes",     enc == "{\"str\":\"hello\"}");
        check("CHOICE str round-trip",  jer_roundtrip(Alt4::asn_DEF, a4));
    }
    {
        Alt4 a4;
        a4.set_present(Alt4::PR::raw);
        a4.raw() = OctetString{std::vector<uint8_t>{0xAB, 0xCD}};
        check("CHOICE raw round-trip",  jer_roundtrip(Alt4::asn_DEF, a4));
    }
    {
        // Decode CHOICE from JSON
        Alt2 out{};
        JerDecodeStream ds{"{\"flag\":false}"};
        auto r = JerCodec::instance().decode(ds, Alt2::asn_DEF, &out);
        check("CHOICE decode flag=false",  r.has_value() && out.present() == Alt2::PR::flag && !out.flag().value());
    }

    // =========================================================================
    std::printf("\n── SEQUENCE wrapping CHOICE ────────────────────────────────\n");
    // =========================================================================
    {
        HasAlt2 h;
        h.val.set_present(Alt2::PR::num);
        h.val.num() = MyByte{99};
        std::string enc = jer_encode(HasAlt2::asn_DEF, &h);
        check("SEQUENCE CHOICE encodes",
              enc.find("\"val\"") != std::string::npos && enc.find("\"num\":99") != std::string::npos);
        check("SEQUENCE CHOICE round-trip", jer_roundtrip(HasAlt2::asn_DEF, h));
    }
    {
        HasAlt2 h;
        h.val.set_present(Alt2::PR::flag);
        h.val.flag() = Boolean{false};
        check("SEQUENCE CHOICE flag round-trip", jer_roundtrip(HasAlt2::asn_DEF, h));
    }
    {
        HasAlt4 h;
        h.val.set_present(Alt4::PR::str);
        h.val.str() = MyStr{"test"};
        check("SEQUENCE Alt4 str round-trip", jer_roundtrip(HasAlt4::asn_DEF, h));
    }
    {
        // Decode SEQUENCE+CHOICE from JSON
        HasAlt2 out{};
        JerDecodeStream ds{"{\"val\":{\"num\":77}}"};
        auto r = JerCodec::instance().decode(ds, HasAlt2::asn_DEF, &out);
        check("SEQUENCE CHOICE decode",  r.has_value() && out.val.present() == Alt2::PR::num
                                         && out.val.num() == Integer{77});
    }

    // =========================================================================
    std::printf("\n── Result ──────────────────────────────────────────────────\n");
    // =========================================================================
    if (failures == 0)
        std::printf("\n\033[32mAll JER composite tests passed.\033[0m\n\n");
    else
        std::printf("\n\033[31m%d test(s) FAILED.\033[0m\n\n", failures);
    return failures ? 1 : 0;
}
