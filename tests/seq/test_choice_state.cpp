// CHOICE selection state after a failed alternative decode.
// Schema: tests/asn1/choice_state_test.asn1
//   Pick ::= CHOICE { a [0] INTEGER, b [1] OCTET STRING }
//   Root ::= SEQUENCE { id [0] INTEGER, pick [1] Pick }
//
// A decoder constructs the alternative it selects before decoding into it.
// When that decode fails, _present must still name the alternative held in
// the storage, so the next decode into the same object, an encode, or the
// destructor never reads one alternative's storage as another's type. Each
// case below reuses one object across a failing decode, as a record stream
// or BerProjectionResult's bound targets do.
#include <cstdio>
#include <span>
#include <sstream>
#include <string>
#include <vector>
#include <asn1cpp/asn1cpp.hpp>
#include <asn1cpp/codec/BerProjection.hpp>
#include "Pick.hpp"
#include "Root.hpp"

using namespace asn1;
static int failures = 0;

static void check(const char* name, bool cond) {
    if (cond) printf("  \033[32mPASS\033[0m  %s\n", name);
    else     { printf("  \033[31mFAIL\033[0m  %s\n", name); ++failures; }
}

static bool ber_dec(const std::vector<uint8_t>& b, Pick& out) {
    BerReader r{b}; BerDecodeStream s{r};
    return BerCodec::instance().decode(s, Pick::asn_DEF, &out).has_value();
}
static std::vector<uint8_t> ber_enc(const Pick& v) {
    std::vector<uint8_t> buf; BerWriter w{buf};
    BerEncodeStream s{w}; BerCodec::instance().encode(s, Pick::asn_DEF, &v); return buf;
}

// The INTEGER record's 8 content octets would be a std::string's data
// pointer if they landed in the OCTET STRING alternative's storage.
static const std::vector<uint8_t> kA5   = {0x80, 0x01, 0x05};
static const std::vector<uint8_t> kBBad = {0x81, 0x05, 0x41};   // length 5, 1 octet
static const std::vector<uint8_t> kAPtr = {0x80, 0x08, 0x41, 0x41, 0x41, 0x41, 0x41, 0x41, 0x41, 0x41};

static void test_ber_reuse() {
    printf("\n── BER: one object, record stream with a failing record ─────────\n");
    Pick p;
    check("a=5 decodes", ber_dec(kA5, p) && p.present() == Pick::PR::a);
    check("truncated b fails", !ber_dec(kBBad, p));
    check("  ...b stays selected over b's storage", p.present() == Pick::PR::b);
    check("a decodes again", ber_dec(kAPtr, p) && p.present() == Pick::PR::a);
    check("  ...re-encodes to its input", ber_enc(p) == kAPtr);
}

static void test_projection_reuse() {
    printf("\n── BerProjection: bound CHOICE reused across apply() ────────────\n");
    BerProjection proj{Root::asn_DEF};
    auto h = proj.add_path("pick");
    proj.finalize();
    BerProjectionResult res{proj};
    Asn1Optional<Pick> pick;
    res.bind(h, pick);
    auto frame = [](const std::vector<uint8_t>& alt) {
        std::vector<uint8_t> f = {0x30, 0, 0xA1, static_cast<uint8_t>(alt.size())};
        f.insert(f.end(), alt.begin(), alt.end());
        f[1] = static_cast<uint8_t>(f.size() - 2);
        return f;
    };
    for (const auto& alt : {kA5, kBBad, kAPtr}) {
        auto f = frame(alt);
        res.apply(std::span<const uint8_t>(f));
    }
    check("last frame selects a", pick.found && pick.present() == Pick::PR::a);
    check("  ...re-encodes to its input", ber_enc(pick) == kAPtr);
}

static void test_jer_duplicate_key() {
    printf("\n── JER: duplicate member, second CHOICE value fails ─────────────\n");
    Root r;
    std::string json = R"({"id":1,"pick":{"b":"41414141414141414141414141414141"},"pick":{"a":x}})";
    JerDecodeStream ds{json};
    check("decode fails", !JerCodec::instance().decode(ds, Root::asn_DEF, &r).has_value());
    check("  ...a stays selected over a's storage", r.pick.present() == Pick::PR::a);
    std::ostringstream o; XerEncodeStream xs{o};
    XerCodec::instance().encode(xs, Root::asn_DEF, &r);
    check("  ...partial value encodes", o.str().find("<a>") != std::string::npos);
}

// X.680 §25: each SEQUENCE component occurs once. A repeated leaf TLV used
// to count toward the projection's early exit, so the leaves after it were
// never looked at (pick reported absent although present).
static void test_projection_duplicate_leaf() {
    printf("\n── BerProjection: repeated leaf TLV ──────────────────────────────\n");
    BerProjection proj{Root::asn_DEF};
    auto hid = proj.add_path("id");
    auto hpick = proj.add_path("pick");
    proj.finalize();
    BerProjectionResult res{proj};
    Asn1Optional<Integer> id;
    Asn1Optional<Pick> pick;
    res.bind(hid, id);
    res.bind(hpick, pick);
    const std::vector<uint8_t> ok = {0x30, 0x08, 0x80, 0x01, 0x01, 0xA1, 0x03, 0x80, 0x01, 0x05};
    check("well-formed frame applies", res.apply(std::span<const uint8_t>(ok)));
    const std::vector<uint8_t> dup = {0x30, 0x0B, 0x80, 0x01, 0x01, 0x80, 0x01, 0x02,
                                      0xA1, 0x03, 0x80, 0x01, 0x05};
    check("repeated id reported malformed", !res.apply(std::span<const uint8_t>(dup)));
    check("  ...first id kept", id.found && static_cast<int64_t>(id) == 1);
    check("  ...pick after it still found", pick.found && pick.present() == Pick::PR::a);
}

int main() {
    test_ber_reuse();
    test_projection_reuse();
    test_jer_duplicate_key();
    test_projection_duplicate_leaf();
    printf("\n");
    if (failures) { printf("  %d test(s) FAILED\n", failures); return 1; }
    printf("  All tests passed.\n");
    return 0;
}
