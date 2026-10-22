#include "Json.hpp"
#include <cstdint>

namespace asn1::config {

const JsonValue* JsonValue::find(std::string_view name) const {
    auto* o = std::get_if<Object>(&v);
    if (!o) return nullptr;
    for (const auto& [k, val] : *o)
        if (k == name) return &val;
    return nullptr;
}

namespace {

/// Recursive-descent reader over ECMA-404 JSON text; reports the line of
/// the first error.
class Parser {
public:
    explicit Parser(std::string_view t) : t_(t) {}

    std::unique_ptr<JsonValue> run(std::string& error) {
        auto v = std::make_unique<JsonValue>();
        bool ok = value(*v, 0);
        if (ok) {
            ws();
            if (pos_ != t_.size()) ok = fail("trailing characters after the JSON value");
        }
        if (!ok) {
            error = "line " + std::to_string(err_line_) + ": " + err_;
            return nullptr;
        }
        return v;
    }

private:
    static constexpr int kMaxDepth = 64;
    std::string_view t_;
    std::size_t pos_ = 0;
    int line_ = 1;
    std::string err_;
    int err_line_ = 0;

    bool fail(std::string msg) {
        if (err_.empty()) { err_ = std::move(msg); err_line_ = line_; }
        return false;
    }
    void ws() {
        while (pos_ < t_.size()) {
            char c = t_[pos_];
            if (c == '\n') ++line_;
            else if (c != ' ' && c != '\t' && c != '\r') break;
            ++pos_;
        }
    }
    bool lit(std::string_view w) {
        if (t_.substr(pos_, w.size()) != w) return false;
        pos_ += w.size();
        return true;
    }

    bool value(JsonValue& out, int depth) {
        if (depth > kMaxDepth) return fail("nesting too deep");
        ws();
        out.line = line_;
        if (pos_ >= t_.size()) return fail("unexpected end of input");
        char c = t_[pos_];
        if (c == '{') return object(out, depth);
        if (c == '[') return array(out, depth);
        if (c == '"') { std::string s; if (!string(s)) return false; out.v = std::move(s); return true; }
        if (lit("true"))  { out.v = true;  return true; }
        if (lit("false")) { out.v = false; return true; }
        if (lit("null"))  { out.v = std::monostate{}; return true; }
        if (c == '-' || (c >= '0' && c <= '9')) return number(out);
        return fail(std::string("unexpected character '") + c + "'");
    }

    bool object(JsonValue& out, int depth) {
        ++pos_;
        JsonValue::Object members;
        ws();
        if (pos_ < t_.size() && t_[pos_] == '}') { ++pos_; out.v = std::move(members); return true; }
        while (true) {
            ws();
            if (pos_ >= t_.size() || t_[pos_] != '"') return fail("expected a member name string");
            std::string name;
            if (!string(name)) return false;
            for (const auto& [k, _] : members)
                if (k == name) return fail("duplicate member \"" + name + "\"");
            ws();
            if (pos_ >= t_.size() || t_[pos_] != ':') return fail("expected ':' after member name");
            ++pos_;
            JsonValue v;
            if (!value(v, depth + 1)) return false;
            members.emplace_back(std::move(name), std::move(v));
            ws();
            if (pos_ < t_.size() && t_[pos_] == ',') { ++pos_; continue; }
            if (pos_ < t_.size() && t_[pos_] == '}') { ++pos_; break; }
            return fail("expected ',' or '}' in object");
        }
        out.v = std::move(members);
        return true;
    }

    bool array(JsonValue& out, int depth) {
        ++pos_;
        JsonValue::Array items;
        ws();
        if (pos_ < t_.size() && t_[pos_] == ']') { ++pos_; out.v = std::move(items); return true; }
        while (true) {
            JsonValue v;
            if (!value(v, depth + 1)) return false;
            items.push_back(std::move(v));
            ws();
            if (pos_ < t_.size() && t_[pos_] == ',') { ++pos_; continue; }
            if (pos_ < t_.size() && t_[pos_] == ']') { ++pos_; break; }
            return fail("expected ',' or ']' in array");
        }
        out.v = std::move(items);
        return true;
    }

    bool number(JsonValue& out) {
        std::size_t start = pos_;
        auto digits = [&] {
            std::size_t s = pos_;
            while (pos_ < t_.size() && t_[pos_] >= '0' && t_[pos_] <= '9') ++pos_;
            return pos_ > s;
        };
        if (t_[pos_] == '-') ++pos_;
        if (pos_ < t_.size() && t_[pos_] == '0') ++pos_;
        else if (!digits()) return fail("malformed number");
        if (pos_ < t_.size() && t_[pos_] == '.') { ++pos_; if (!digits()) return fail("malformed number"); }
        if (pos_ < t_.size() && (t_[pos_] == 'e' || t_[pos_] == 'E')) {
            ++pos_;
            if (pos_ < t_.size() && (t_[pos_] == '+' || t_[pos_] == '-')) ++pos_;
            if (!digits()) return fail("malformed number");
        }
        out.v = JsonValue::Number{std::string(t_.substr(start, pos_ - start))};
        return true;
    }

    static void put_utf8(std::string& s, uint32_t cp) {
        if (cp < 0x80) s += static_cast<char>(cp);
        else if (cp < 0x800) { s += static_cast<char>(0xC0 | (cp >> 6)); s += static_cast<char>(0x80 | (cp & 0x3F)); }
        else if (cp < 0x10000) {
            s += static_cast<char>(0xE0 | (cp >> 12));
            s += static_cast<char>(0x80 | ((cp >> 6) & 0x3F));
            s += static_cast<char>(0x80 | (cp & 0x3F));
        } else {
            s += static_cast<char>(0xF0 | (cp >> 18));
            s += static_cast<char>(0x80 | ((cp >> 12) & 0x3F));
            s += static_cast<char>(0x80 | ((cp >> 6) & 0x3F));
            s += static_cast<char>(0x80 | (cp & 0x3F));
        }
    }
    bool hex4(uint32_t& cp) {
        if (pos_ + 4 > t_.size()) return fail("truncated \\u escape");
        cp = 0;
        for (int i = 0; i < 4; ++i) {
            char c = t_[pos_++];
            cp <<= 4;
            if (c >= '0' && c <= '9') cp |= c - '0';
            else if (c >= 'a' && c <= 'f') cp |= c - 'a' + 10;
            else if (c >= 'A' && c <= 'F') cp |= c - 'A' + 10;
            else return fail("bad hex digit in \\u escape");
        }
        return true;
    }
    bool string(std::string& out) {
        ++pos_;
        while (true) {
            if (pos_ >= t_.size()) return fail("unterminated string");
            char c = t_[pos_++];
            if (c == '"') return true;
            if (static_cast<unsigned char>(c) < 0x20) return fail("control character in string");
            if (c != '\\') { out += c; continue; }
            if (pos_ >= t_.size()) return fail("unterminated escape");
            char e = t_[pos_++];
            switch (e) {
            case '"': out += '"'; break;
            case '\\': out += '\\'; break;
            case '/': out += '/'; break;
            case 'b': out += '\b'; break;
            case 'f': out += '\f'; break;
            case 'n': out += '\n'; break;
            case 'r': out += '\r'; break;
            case 't': out += '\t'; break;
            case 'u': {
                uint32_t cp;
                if (!hex4(cp)) return false;
                if (cp >= 0xD800 && cp <= 0xDBFF) {
                    uint32_t lo;
                    if (!lit("\\u") || !hex4(lo) || lo < 0xDC00 || lo > 0xDFFF)
                        return fail("unpaired surrogate in \\u escape");
                    cp = 0x10000 + ((cp - 0xD800) << 10) + (lo - 0xDC00);
                } else if (cp >= 0xDC00 && cp <= 0xDFFF) {
                    return fail("unpaired surrogate in \\u escape");
                }
                put_utf8(out, cp);
                break;
            }
            default: return fail(std::string("bad escape '\\") + e + "'");
            }
        }
    }
};

} // namespace

std::unique_ptr<JsonValue> parse_json(std::string_view text, std::string& error) {
    return Parser(text).run(error);
}

} // namespace asn1::config
