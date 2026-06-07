// BER / XER tests for cross-module IMPORTS.
// Schema: tests/asn1/imports_test.asn1
// ImportModA: Address { city VisibleString, zip ZipCode }
// ImportModB: Person { name VisibleString, home Address }  (Address imported from ModA)
#include <cstdio>
#include <vector>
#include <span>
#include <sstream>
#include <string>
#include <asn1cpp/asn1cpp.hpp>
#include "Person.hpp"

using namespace asn1;
static int failures = 0;

static void check(const char* name, bool cond) {
    if (cond) printf("  \033[32mPASS\033[0m  %s\n", name);
    else     { printf("  \033[31mFAIL\033[0m  %s\n", name); ++failures; }
}

static std::vector<uint8_t> ber_enc(const Person& v) {
    std::vector<uint8_t> buf; BerWriter w{buf};
    BerEncodeStream s{w}; BerCodec::instance().encode(s, Person::asn_DEF, &v); return buf;
}
static bool ber_dec(std::span<const uint8_t> b, Person& out) {
    BerReader r{b}; BerDecodeStream s{r};
    return BerCodec::instance().decode(s, Person::asn_DEF, &out).has_value();
}
static std::string xer_enc(const Person& v) {
    std::ostringstream o; XerEncodeStream s{o};
    XerCodec::instance().encode(s, Person::asn_DEF, &v); return o.str();
}
static bool xer_dec(const std::string& xml, Person& out) {
    XerDecodeStream s{xml};
    return XerCodec::instance().decode(s, Person::asn_DEF, &out).has_value();
}

static Person make_person(const char* name, const char* city, int64_t zip) {
    Person p;
    p.name = VisibleString{name};
    p.home.city = VisibleString{city};
    p.home.zip = zip;
    return p;
}

int main() {
    printf("\n── Person BER round-trips ────────────────────────────────────────\n");
    {
        auto p = make_person("Alice", "Amsterdam", 1012);
        auto enc = ber_enc(p); Person got{};
        check("Person{Alice,Amsterdam,1012} BER rt",
              ber_dec(enc, got) && got.name.str() == "Alice"
              && got.home.city.str() == "Amsterdam" && got.home.zip == 1012);
    }
    {
        auto p = make_person("Bob", "NYC", 10001);
        auto enc = ber_enc(p); Person got{};
        check("Person{Bob,NYC,10001} BER rt",
              ber_dec(enc, got) && got.name.str() == "Bob"
              && got.home.city.str() == "NYC" && got.home.zip == 10001);
    }

    printf("\n── Person XER round-trips ────────────────────────────────────────\n");
    {
        auto p = make_person("Carol", "Berlin", 10115);
        auto xml = xer_enc(p); Person got{};
        check("Person{Carol,Berlin,10115} XER rt",
              xer_dec(xml, got) && got.name.str() == "Carol"
              && got.home.city.str() == "Berlin" && got.home.zip == 10115);
    }

    printf("\n── XER structure ─────────────────────────────────────────────────\n");
    {
        auto p = make_person("Dave", "Paris", 75001);
        auto xml = xer_enc(p);
        check("XER has <Person>", xml.find("<Person>") != std::string::npos);
        check("XER has <name>",   xml.find("<name>")   != std::string::npos);
        check("XER has <home>",   xml.find("<home>")   != std::string::npos);
        check("XER has <city>",   xml.find("<city>")   != std::string::npos);
        check("XER has <zip>",    xml.find("<zip>")    != std::string::npos);
    }

    printf("\n── Address descriptor carries original ASN.1 name ────────────────\n");
    check("Address::asn_DEF.name == \"Address\"",
          std::string(Address::asn_DEF.name) == "Address");
    check("Person::asn_DEF.name == \"Person\"",
          std::string(Person::asn_DEF.name) == "Person");

    printf("\n");
    if (failures) { printf("  %d test(s) FAILED\n", failures); return 1; }
    printf("  All tests passed.\n");
    return 0;
}
