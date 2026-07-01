// Tests for BerCursor / BerLayer / BerMutableCursor / ber_path / ber_walk
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <vector>
#include <span>
#include <asn1cpp/codec/BerCursor.hpp>

using namespace asn1;

static int failures = 0;

static void check(const char* name, bool cond, const char* detail = "") {
    if (cond) {
        printf("  \033[32mPASS\033[0m  %s\n", name);
    } else {
        printf("  \033[31mFAIL\033[0m  %s%s%s\n", name, *detail ? ": " : "", detail);
        ++failures;
    }
}

// ── Hand-crafted TLV helpers ─────────────────────────────────────────────────

// Build a definite-length TLV: [tag_byte][len][value...]
static std::vector<uint8_t> tlv(uint8_t tag_byte,
                                std::vector<uint8_t> value) {
    std::vector<uint8_t> out;
    out.push_back(tag_byte);
    size_t vlen = value.size();
    if (vlen < 0x80) {
        out.push_back(static_cast<uint8_t>(vlen));
    } else if (vlen <= 0xFF) {
        out.push_back(0x81);
        out.push_back(static_cast<uint8_t>(vlen));
    } else {
        out.push_back(0x82);
        out.push_back(static_cast<uint8_t>(vlen >> 8));
        out.push_back(static_cast<uint8_t>(vlen & 0xFF));
    }
    out.insert(out.end(), value.begin(), value.end());
    return out;
}

// Long-form tag (number >= 31): class 0x80 (context) | 0x20 (constructed) | 0x1F
static std::vector<uint8_t> tlv_long_tag(uint8_t class_constr,  // e.g. 0xA0 = context+constructed
                                          uint32_t tag_number,
                                          std::vector<uint8_t> value) {
    std::vector<uint8_t> out;
    out.push_back(static_cast<uint8_t>((class_constr & 0xE0) | 0x1F));
    // base-128 encode tag_number
    uint8_t buf[5]; int n = 0;
    uint32_t t = tag_number;
    buf[n++] = t & 0x7F; t >>= 7;
    while (t) { buf[n++] = (t & 0x7F) | 0x80; t >>= 7; }
    for (int i = n - 1; i >= 0; --i) out.push_back(buf[i]);
    // length
    size_t vlen = value.size();
    if (vlen < 0x80) {
        out.push_back(static_cast<uint8_t>(vlen));
    } else {
        out.push_back(0x81);
        out.push_back(static_cast<uint8_t>(vlen));
    }
    out.insert(out.end(), value.begin(), value.end());
    return out;
}

static std::span<const uint8_t> sp(const std::vector<uint8_t>& v) {
    return {v.data(), v.size()};
}

// ── Tag factory helpers ───────────────────────────────────────────────────────

static Tag ctx(uint32_t n, bool c = false) {
    return Tag{TagClass::Context, n, c};
}
static Tag univ(uint32_t n, bool c = false) {
    return Tag{TagClass::Universal, n, c};
}

// ── Tests: basic BerCursor ────────────────────────────────────────────────────

static void test_basic_cursor() {
    // INTEGER 42 = 0x02 0x01 0x2A
    std::vector<uint8_t> buf = {0x02, 0x01, 0x2A};
    BerCursor c{sp(buf)};
    check("cursor_valid",   c.valid());
    check("cursor_tag_cls", c.tag().cls == TagClass::Universal);
    check("cursor_tag_num", c.tag().number == 2);  // INTEGER
    check("cursor_length",  c.length() == 1);
    check("cursor_value",   c.value().size() == 1 && c.value()[0] == 0x2A);
}

static void test_cursor_empty() {
    std::vector<uint8_t> buf;
    BerCursor c{sp(buf)};
    check("empty_invalid", !c.valid());
}

static void test_cursor_next() {
    // Two siblings: INTEGER 1, BOOLEAN true
    auto a = tlv(0x02, {0x01});  // INTEGER 1
    auto b = tlv(0x01, {0xFF});  // BOOLEAN true
    std::vector<uint8_t> buf;
    buf.insert(buf.end(), a.begin(), a.end());
    buf.insert(buf.end(), b.begin(), b.end());

    BerCursor c{sp(buf)};
    check("next_first_valid",   c.valid());
    check("next_first_tag",     c.tag().number == 2);
    c.next();
    check("next_second_valid",  c.valid());
    check("next_second_tag",    c.tag().number == 1);
    c.next();
    check("next_exhausted",     !c.valid());
}

// ── Tests: multi-byte tag ─────────────────────────────────────────────────────

static void test_long_tag() {
    // Context [31] constructed, value = {0xAB}
    auto buf = tlv_long_tag(0xA0, 31, {0xAB});
    BerCursor c{sp(buf)};
    check("long_tag_valid",    c.valid());
    check("long_tag_cls",      c.tag().cls == TagClass::Context);
    check("long_tag_number",   c.tag().number == 31);
    check("long_tag_constructed", c.tag().constructed);
    check("long_tag_value",    c.value().size() == 1 && c.value()[0] == 0xAB);
}

// ── Tests: BerLayer expand-once ───────────────────────────────────────────────

static void test_layer_expand_once() {
    // SEQUENCE containing [0] 0x01, [1] 0x02, [2] 0x03
    auto c0 = tlv(0x80, {0x01});
    auto c1 = tlv(0x81, {0x02});
    auto c2 = tlv(0x82, {0x03});
    std::vector<uint8_t> children;
    children.insert(children.end(), c0.begin(), c0.end());
    children.insert(children.end(), c1.begin(), c1.end());
    children.insert(children.end(), c2.begin(), c2.end());

    BerLayer layer{sp(children)};
    check("layer_size_3",     layer.size() == 3);  // triggers expand

    // find each child
    auto f0 = layer.find(ctx(0));
    auto f1 = layer.find(ctx(1));
    auto f2 = layer.find(ctx(2));
    check("layer_find_0",     f0.valid() && f0.value()[0] == 0x01);
    check("layer_find_1",     f1.valid() && f1.value()[0] == 0x02);
    check("layer_find_2",     f2.valid() && f2.value()[0] == 0x03);

    // size unchanged after multiple finds — expand ran once
    check("layer_size_stable", layer.size() == 3);

    // missing tag → invalid
    check("layer_find_miss",  !layer.find(ctx(5)).valid());
}

// ── Tests: enter() + nested walk ─────────────────────────────────────────────

static void test_nested_enter() {
    // Build: SEQUENCE { SEQUENCE { INTEGER 99 } }
    auto inner_int = tlv(0x02, {0x63});                // INTEGER 99
    auto inner_seq = tlv(0x30, inner_int);             // SEQUENCE { INTEGER 99 }
    auto outer_seq = tlv(0x30, inner_seq);             // SEQUENCE { SEQUENCE { ... } }

    BerCursor outer{sp(outer_seq)};
    check("outer_valid",    outer.valid());
    check("outer_tag",      outer.tag().number == 16);  // SEQUENCE = 16

    BerLayer inner_layer = outer.enter();
    check("inner_size",     inner_layer.size() == 1);

    auto inner = inner_layer.find(univ(16, true));
    check("inner_valid",    inner.valid());

    BerLayer leaf_layer = inner.enter();
    check("leaf_size",      leaf_layer.size() == 1);

    auto leaf = leaf_layer.find(univ(2));
    check("leaf_valid",     leaf.valid());
    check("leaf_value",     leaf.value().size() == 1 && leaf.value()[0] == 0x63);
}

// ── Tests: BerCursor::find (scan siblings) ────────────────────────────────────

static void test_cursor_find() {
    auto a = tlv(0x80, {0x01});  // [0]
    auto b = tlv(0x81, {0x02});  // [1]
    auto c = tlv(0x82, {0x03});  // [2]
    std::vector<uint8_t> buf;
    buf.insert(buf.end(), a.begin(), a.end());
    buf.insert(buf.end(), b.begin(), b.end());
    buf.insert(buf.end(), c.begin(), c.end());

    BerCursor cur{sp(buf)};
    auto found = cur.find(ctx(1));
    check("sibling_find_1",   found.valid() && found.value()[0] == 0x02);
    check("sibling_find_miss", !cur.find(ctx(9)).valid());
}

// ── Tests: BerMutableCursor write_value ──────────────────────────────────────

static void test_mutable_write() {
    // [0] IMPLICIT, value = {0xAA, 0xBB}
    std::vector<uint8_t> buf = {0x80, 0x02, 0xAA, 0xBB};
    BerMutableCursor mc{std::span<uint8_t>{buf.data(), buf.size()}};
    check("mut_valid",   mc.valid());
    check("mut_length",  mc.length() == 2);

    // Write same-size replacement
    uint8_t new_val[] = {0xCC, 0xDD};
    bool ok = mc.write_value(std::span<const uint8_t>{new_val, 2});
    check("mut_write_ok",      ok);
    check("mut_wrote_cc",      buf[2] == 0xCC);
    check("mut_wrote_dd",      buf[3] == 0xDD);
    check("mut_tag_unchanged", buf[0] == 0x80);
    check("mut_len_unchanged", buf[1] == 0x02);

    // Wrong size → rejected
    uint8_t bad[] = {0x01};
    check("mut_write_reject",  !mc.write_value(std::span<const uint8_t>{bad, 1}));
}

// ── Tests: ber_path ───────────────────────────────────────────────────────────

static void test_ber_path() {
    // Build: [0] { [1] { [2] 0xBE } }
    auto leaf  = tlv(0x82, {0xBE});
    auto mid   = tlv(0xA1, leaf);    // [1] constructed
    auto outer = tlv(0xA0, mid);     // [0] constructed
    std::vector<uint8_t> buf = outer;

    auto found = ber_path(sp(buf), {ctx(0), ctx(1), ctx(2)});
    check("ber_path_found",      found.valid());
    check("ber_path_value",      found.value().size() == 1 && found.value()[0] == 0xBE);

    auto miss = ber_path(sp(buf), {ctx(0), ctx(5)});
    check("ber_path_miss",       !miss.valid());
}

// ── Tests: ber_walk ───────────────────────────────────────────────────────────

static void test_ber_walk() {
    // SEQUENCE { INTEGER 1, INTEGER 2 }
    auto i1  = tlv(0x02, {0x01});
    auto i2  = tlv(0x02, {0x02});
    std::vector<uint8_t> children;
    children.insert(children.end(), i1.begin(), i1.end());
    children.insert(children.end(), i2.begin(), i2.end());
    auto seq = tlv(0x30, children);

    int visit_count = 0;
    int max_depth_seen = 0;
    ber_walk(sp(seq), [&](BerCursor c, int depth) {
        ++visit_count;
        if (depth > max_depth_seen) max_depth_seen = depth;
    });
    // 1 SEQUENCE + 2 INTEGER = 3
    check("walk_count",     visit_count == 3);
    check("walk_max_depth", max_depth_seen == 1);

    // max_depth=0: only top-level
    visit_count = 0;
    ber_walk(sp(seq), [&](BerCursor, int) { ++visit_count; }, 0);
    check("walk_depth0",    visit_count == 1);
}

// ── Tests: ber_find_paths / ber_collect_paths ─────────────────────────────────

static void test_find_paths() {
    // SEQUENCE { [0] 0x01, [1] 0x02 }
    auto c0  = tlv(0x80, {0x01});
    auto c1  = tlv(0x81, {0x02});
    std::vector<uint8_t> children;
    children.insert(children.end(), c0.begin(), c0.end());
    children.insert(children.end(), c1.begin(), c1.end());
    auto seq = tlv(0x30, children);  // SEQUENCE = Universal 16 constructed

    auto paths = ber_collect_paths(sp(seq));
    // Expect: "[U16*]", "[U16*]/[C0]", "[U16*]/[C1]"
    check("paths_count",    paths.size() == 3);

    bool has_seq  = false, has_c0 = false, has_c1 = false;
    for (auto& p : paths) {
        if (p == "[U16]*")         has_seq = true;
        if (p == "[U16]*/[C0]")    has_c0  = true;
        if (p == "[U16]*/[C1]")    has_c1  = true;
    }
    check("paths_has_seq", has_seq);
    check("paths_has_c0",  has_c0);
    check("paths_has_c1",  has_c1);

    // leaf_only=true: skip the constructed SEQUENCE node
    auto leaf_paths = ber_collect_paths(sp(seq), true);
    check("leaf_paths_count", leaf_paths.size() == 2);

    // Visitor form: collect (path, value) pairs
    int visit_count = 0;
    ber_find_paths(sp(seq), [&](const std::string&, BerCursor) { ++visit_count; });
    check("find_paths_visit", visit_count == 3);
}

int main() {
    printf("=== BerCursor basic ===\n");
    test_basic_cursor();
    test_cursor_empty();
    test_cursor_next();

    printf("=== Multi-byte tag ===\n");
    test_long_tag();

    printf("=== BerLayer expand-once ===\n");
    test_layer_expand_once();

    printf("=== Nested enter() ===\n");
    test_nested_enter();

    printf("=== Sibling find ===\n");
    test_cursor_find();

    printf("=== BerMutableCursor write ===\n");
    test_mutable_write();

    printf("=== ber_path ===\n");
    test_ber_path();

    printf("=== ber_walk ===\n");
    test_ber_walk();

    printf("=== ber_find_paths / ber_collect_paths ===\n");
    test_find_paths();

    printf("\n%s — %d failure(s)\n", failures ? "FAIL" : "PASS", failures);
    return failures ? EXIT_FAILURE : EXIT_SUCCESS;
}
