#include <asn1cpp/codec/BerCursor.hpp>
#include <asn1cpp/codec/BerReader.hpp>
#include <cstring>

namespace asn1 {

// ── Tag match helper ─────────────────────────────────────────────────────────
// Match on class + number only; constructed bit is an encoding detail.
static bool tag_matches(Tag a, Tag b) {
    return a.cls == b.cls && a.number == b.number;
}

// ── Parse helper — extract header/value sizes from a BerReader result ────────
static bool parse_buf(std::span<const uint8_t> buf,
                      Tag& out_tag, size_t& out_hdr, size_t& out_vlen) {
    if (buf.empty()) return false;
    BerReader r{buf};
    auto tlv = r.read_tlv();
    if (!tlv || tlv->indefinite) return false;
    out_tag  = tlv->tag;
    out_vlen = tlv->value.size();
    out_hdr  = r.pos() - out_vlen;
    return true;
}

// ── BerCursor ────────────────────────────────────────────────────────────────

BerCursor::BerCursor(std::span<const uint8_t> buf) : buf_(buf) { parse(); }

void BerCursor::parse() {
    valid_ = parse_buf(buf_, tag_, hdr_, vlen_);
}

std::span<const uint8_t> BerCursor::value() const {
    return valid_ ? buf_.subspan(hdr_, vlen_) : std::span<const uint8_t>{};
}

BerCursor& BerCursor::next() {
    if (!valid_) return *this;
    size_t step = hdr_ + vlen_;
    if (step >= buf_.size()) { valid_ = false; return *this; }
    buf_ = buf_.subspan(step);
    parse();
    return *this;
}

BerLayer BerCursor::enter() const {
    return BerLayer{value()};
}

BerCursor BerCursor::find(Tag t) const {
    BerCursor c = *this;
    while (c.valid()) {
        if (tag_matches(c.tag_, t)) return c;
        c.next();
    }
    return {};
}

// ── BerMutableCursor ─────────────────────────────────────────────────────────

BerMutableCursor::BerMutableCursor(std::span<uint8_t> buf) : buf_(buf) { parse(); }

void BerMutableCursor::parse() {
    // Parse via const view — no mutation in parse phase
    std::span<const uint8_t> cbuf{buf_.data(), buf_.size()};
    valid_ = parse_buf(cbuf, tag_, hdr_, vlen_);
}

std::span<const uint8_t> BerMutableCursor::value() const {
    return valid_ ? std::span<const uint8_t>{buf_.data() + hdr_, vlen_} : std::span<const uint8_t>{};
}

std::span<uint8_t> BerMutableCursor::mutable_value() {
    return valid_ ? buf_.subspan(hdr_, vlen_) : std::span<uint8_t>{};
}

BerMutableCursor& BerMutableCursor::next() {
    if (!valid_) return *this;
    size_t step = hdr_ + vlen_;
    if (step >= buf_.size()) { valid_ = false; return *this; }
    buf_ = buf_.subspan(step);
    parse();
    return *this;
}

BerMutableLayer BerMutableCursor::enter() {
    return BerMutableLayer{mutable_value()};
}

BerMutableCursor BerMutableCursor::find(Tag t) {
    BerMutableCursor c = *this;
    while (c.valid()) {
        if (tag_matches(c.tag_, t)) return c;
        c.next();
    }
    return {};
}

bool BerMutableCursor::write_value(std::span<const uint8_t> new_val) {
    if (!valid_ || new_val.size() != vlen_) return false;
    std::memcpy(buf_.data() + hdr_, new_val.data(), vlen_);
    return true;
}

BerCursor BerMutableCursor::as_const() const {
    return BerCursor{std::span<const uint8_t>{buf_.data(), buf_.size()}};
}

// ── BerLayer ─────────────────────────────────────────────────────────────────

BerLayer::BerLayer(std::span<const uint8_t> data) : data_(data) {}

void BerLayer::expand() const {
    if (expanded_) return;
    expanded_ = true;
    BerReader r{data_};
    while (!r.at_end()) {
        size_t start = r.pos();
        auto tlv = r.read_tlv();
        if (!tlv || tlv->indefinite) break;
        size_t total = r.pos() - start;
        size_t hdr   = total - tlv->value.size();
        entries_.push_back({tlv->tag, start, hdr, tlv->value.size()});
    }
}

BerCursor BerLayer::find(Tag t) const {
    expand();
    for (const auto& e : entries_)
        if (tag_matches(e.tag, t))
            return BerCursor{data_.subspan(e.offset)};
    return {};
}

void BerLayer::for_each(std::function<void(BerCursor)> fn) const {
    expand();
    for (const auto& e : entries_)
        fn(BerCursor{data_.subspan(e.offset)});
}

size_t BerLayer::size() const {
    expand();
    return entries_.size();
}

// ── BerMutableLayer ──────────────────────────────────────────────────────────

BerMutableLayer::BerMutableLayer(std::span<uint8_t> data) : data_(data) {}

void BerMutableLayer::expand() const {
    if (expanded_) return;
    expanded_ = true;
    std::span<const uint8_t> cbuf{data_.data(), data_.size()};
    BerReader r{cbuf};
    while (!r.at_end()) {
        size_t start = r.pos();
        auto tlv = r.read_tlv();
        if (!tlv || tlv->indefinite) break;
        size_t total = r.pos() - start;
        size_t hdr   = total - tlv->value.size();
        entries_.push_back({tlv->tag, start, hdr, tlv->value.size()});
    }
}

BerMutableCursor BerMutableLayer::find(Tag t) {
    expand();
    for (const auto& e : entries_)
        if (tag_matches(e.tag, t))
            return BerMutableCursor{data_.subspan(e.offset)};
    return {};
}

void BerMutableLayer::for_each(std::function<void(BerMutableCursor)> fn) {
    expand();
    for (const auto& e : entries_)
        fn(BerMutableCursor{data_.subspan(e.offset)});
}

size_t BerMutableLayer::size() {
    expand();
    return entries_.size();
}

BerLayer BerMutableLayer::as_const() const {
    return BerLayer{std::span<const uint8_t>{data_.data(), data_.size()}};
}

// ── Utilities ─────────────────────────────────────────────────────────────────

BerCursor ber_path(std::span<const uint8_t> buf,
                   std::initializer_list<Tag> path) {
    if (path.size() == 0) return BerCursor{buf};
    std::span<const uint8_t> cur = buf;
    BerCursor result;
    for (auto it = path.begin(); it != path.end(); ++it) {
        result = BerCursor{cur}.find(*it);
        if (!result.valid()) return {};
        if (std::next(it) != path.end())
            cur = result.value();  // descend into value for next step
    }
    return result;
}

static void ber_walk_impl(std::span<const uint8_t> buf, BerVisitor& visitor,
                          int max_depth, int depth) {
    BerCursor c{buf};
    while (c.valid()) {
        visitor(c, depth);
        if (c.tag().constructed && (max_depth < 0 || depth < max_depth))
            ber_walk_impl(c.value(), visitor, max_depth, depth + 1);
        c.next();
    }
}

void ber_walk(std::span<const uint8_t> buf, BerVisitor visitor, int max_depth) {
    ber_walk_impl(buf, visitor, max_depth, 0);
}


} // namespace asn1
