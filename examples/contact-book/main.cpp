// contact-book example — encode a Contact to BER, decode it back, print as XER.
// Matches the schema in contact.asn1 and the code samples in doc/book.md §7-8.
// If you update the schema or the code samples in the book, update this file too.

#include "Contact.hpp"
#include "PhoneNumber.hpp"
#include "ContactList.hpp"
#include <asn1cpp/codec/BerCodec.hpp>
#include <asn1cpp/codec/XerCodec.hpp>
#include <iostream>
#include <fstream>
#include <vector>

static void encode_example(const char* out_path) {
    Contact c{};
    c.set_name(asn1::Utf8String("Alice Example"));

    // OPTIONAL members are unique_ptr — construct in place
    c.email = std::make_unique<asn1::Ia5String>("alice@example.com");

    c.phone = std::make_unique<PhoneNumber>();
    c.phone->set_countryCode(31);
    c.phone->set_number(asn1::NumericString("612345678"));

    std::vector<uint8_t> buf;
    asn1::BerWriter w{buf};
    asn1::BerEncodeStream s{w};
    asn1::BerCodec::instance().encode(s, Contact::asn_DEF, &c);

    std::ofstream f(out_path, std::ios::binary);
    f.write(reinterpret_cast<const char*>(buf.data()),
            static_cast<std::streamsize>(buf.size()));
    std::cout << "[encode] wrote " << buf.size() << " bytes to " << out_path << "\n";
}

static void decode_and_print(const char* in_path) {
    std::ifstream f(in_path, std::ios::binary);
    std::vector<uint8_t> buf(std::istreambuf_iterator<char>(f), {});

    Contact c{};
    asn1::BerReader reader{buf};
    asn1::BerDecodeStream s{reader};
    auto result = asn1::BerCodec::instance().decode(s, Contact::asn_DEF, &c);
    if (!result) {
        std::cerr << "[decode] error: " << result.error().message << "\n";
        return;
    }

    asn1::XerEncodeStream xs{std::cout};
    asn1::XerCodec::instance().encode(xs, Contact::asn_DEF, &c);
    std::cout << "\n";
}

int main(int argc, char** argv) {
    const char* ber_file = "/tmp/contact.ber";
    if (argc > 1) ber_file = argv[1];

    encode_example(ber_file);
    decode_and_print(ber_file);
}
