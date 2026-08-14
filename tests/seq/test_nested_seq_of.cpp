// BER/XER round-trip + wire-shape test for an anonymous (unnamed) nested
// SEQUENCE OF SEQUENCE OF INTEGER — regression coverage for gambas-asn1#427.
// Schema: tests/asn1/nested_seq_of_test.asn1
//
// Before the fix, the intermediate "SEQUENCE OF INTEGER" collection level
// had no descriptor of its own — the generic SeqOf BER handler read each
// outer element (a VectorSeqOf<Integer> object) as if it were a bare
// Integer, corrupting the encoding. Wire shape asserted explicitly below
// so a regression shows up as a byte mismatch, not just "didn't crash".
#include <cstdio>
#include <vector>
#include <span>
#include <sstream>
#include <asn1cpp/asn1cpp.hpp>
#include "Matrix.hpp"

using namespace asn1;
static int failures = 0;

static void check(const char* name, bool cond) {
    if (cond) printf("  \033[32mPASS\033[0m  %s\n", name);
    else     { printf("  \033[31mFAIL\033[0m  %s\n", name); ++failures; }
}

static Matrix make_matrix() {
    Matrix m;
    VectorSeqOf<Integer> row1;
    row1.push_back(1);
    row1.push_back(2);
    VectorSeqOf<Integer> row2;
    row2.push_back(3);
    m.rows.push_back(row1);
    m.rows.push_back(row2);
    return m;
}

int main() {
    Matrix m = make_matrix();

    std::vector<uint8_t> buf;
    BerWriter w{buf};
    BerEncodeStream s{w};
    BerCodec::instance().encode(s, Matrix::asn_DEF, &m);

    // 30 0f                              Matrix SEQUENCE, len 15
    //   30 0d                            rows SEQUENCE OF, len 13
    //     30 06 02 01 01 02 01 02        row [1, 2]
    //     30 03 02 01 03                 row [3]
    std::vector<uint8_t> expect = {
        0x30, 0x0f,
        0x30, 0x0d,
        0x30, 0x06, 0x02, 0x01, 0x01, 0x02, 0x01, 0x02,
        0x30, 0x03, 0x02, 0x01, 0x03,
    };
    check("nested seq-of encodes the expected well-formed BER shape", buf == expect);

    Matrix m2;
    BerReader r{std::span<const uint8_t>(buf)};
    BerDecodeStream ds{r};
    bool decoded = BerCodec::instance().decode(ds, Matrix::asn_DEF, &m2).has_value();
    check("nested seq-of BER decode succeeds", decoded);
    if (decoded) {
        check("nested seq-of BER round-trip: row count",
              m2.rows.size() == 2);
        check("nested seq-of BER round-trip: row[0] values",
              m2.rows.size() == 2 && m2.rows[0].size() == 2 &&
              m2.rows[0][0].value() == 1 && m2.rows[0][1].value() == 2);
        check("nested seq-of BER round-trip: row[1] values",
              m2.rows.size() == 2 && m2.rows[1].size() == 1 &&
              m2.rows[1][0].value() == 3);
    }

    std::ostringstream xs;
    XerEncodeStream xes{xs};
    XerCodec::instance().encode(xes, Matrix::asn_DEF, &m);
    Matrix m3;
    XerDecodeStream xds{xs.str()};
    bool xer_decoded = XerCodec::instance().decode(xds, Matrix::asn_DEF, &m3).has_value();
    check("nested seq-of XER decode succeeds", xer_decoded);
    if (xer_decoded) {
        check("nested seq-of XER round-trip matches original",
              m3.rows.size() == 2 && m3.rows[0].size() == 2 && m3.rows[1].size() == 1 &&
              m3.rows[0][0].value() == 1 && m3.rows[0][1].value() == 2 &&
              m3.rows[1][0].value() == 3);
    }

    printf("\n%d failure(s)\n", failures);
    return failures == 0 ? 0 : 1;
}
