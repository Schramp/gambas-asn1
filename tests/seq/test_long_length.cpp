// BER encode/decode of a SEQUENCE holding an OCTET STRING of 2^24 + 1
// bytes through BerCodec: both TLVs need 4 length octets (X.690 §8.1.3.5)
// and the value decodes back unchanged.
// Schema: tests/asn1/long_length_test.asn1
#include <algorithm>
#include <cstdio>
#include <span>
#include <vector>
#include <asn1cpp/asn1cpp.hpp>
#include "LongLen.hpp"

using namespace asn1;

static int failures = 0;

static void check(const char* name, bool cond) {
    if (cond) printf("  \033[32mPASS\033[0m  %s\n", name);
    else { printf("  \033[31mFAIL\033[0m  %s\n", name); ++failures; }
}

int main() {
    printf("\n── Content past 2^24 bytes ─────────────────────────────────────\n");

    const std::size_t n = (std::size_t{1} << 24) + 1;
    std::vector<uint8_t> big(n);
    for (std::size_t i = 0; i < n; ++i) big[i] = static_cast<uint8_t>(i * 13);
    LongLen v;
    v.n = Integer{7};
    v.o.set(big);

    std::vector<uint8_t> enc;
    BerWriter w{enc};
    BerEncodeStream es{w};
    BerCodec::instance().encode(es, LongLen::asn_DEF, &v);

    // SEQUENCE, length 3 + 6 + n = 0x0100000A
    const std::vector<uint8_t> seq_hdr{0x30, 0x84, 0x01, 0x00, 0x00, 0x0A};
    // INTEGER 7, then OCTET STRING with length 0x01000001
    const std::vector<uint8_t> members{0x02, 0x01, 0x07, 0x04, 0x84, 0x01, 0x00, 0x00, 0x01};
    check("SEQUENCE length in 4 octets (84 01 00 00 0A)",
          enc.size() == 15 + n && std::equal(seq_hdr.begin(), seq_hdr.end(), enc.begin()));
    check("OCTET STRING length in 4 octets (84 01 00 00 01)",
          enc.size() == 15 + n && std::equal(members.begin(), members.end(), enc.begin() + 6));

    LongLen back;
    BerReader r{std::span<const uint8_t>(enc)};
    BerDecodeStream ds{r};
    check("decodes back unchanged",
          BerCodec::instance().decode(ds, LongLen::asn_DEF, &back).has_value() && back == v);

    printf("\n%s (%d failure%s)\n", failures ? "FAILED" : "OK", failures, failures == 1 ? "" : "s");
    return failures ? 1 : 0;
}
