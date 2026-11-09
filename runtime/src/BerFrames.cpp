#include <asn1cpp/codec/BerFrames.hpp>
#include <asn1cpp/codec/BerCodec.hpp>
#include <asn1cpp/codec/DecodeDepth.hpp>
#include <cerrno>
#include <cstring>
#include <istream>
#include <string>

namespace asn1 {

namespace {

using FrameLength = Expected<std::optional<std::size_t>, DecodeError>;

FrameLength frame_error(std::string message, std::uint64_t offset) {
    return make_unexpected<std::optional<std::size_t>, DecodeError>(
        DecodeError(std::move(message), static_cast<std::size_t>(offset)));
}

/// @brief The parsed identifier and length octets of one TLV inside a frame.
struct Header {
    std::size_t end = 0;          ///< Frame offset just past the length octets.
    std::uint64_t length = 0;     ///< Definite length (0 when indefinite).
    bool indefinite = false;      ///< Length octet was 0x80 (X.690 §8.1.3.6).
    bool eoc = false;             ///< The end-of-contents octets 00 00 (X.690 §8.1.5).
};

/// @brief Find the length of the record at the start of \p src: the walk
///        shared by \c BerFrameReader and \c BerSpanFrames.
///
/// \p src makes the first n octets of the frame available on demand
/// (`fill(n)`, false when the input ends first), so a stream source reads
/// exactly up to the end of the record and a span source only checks
/// bounds. Definite contents are skipped without being parsed; an
/// indefinite-length record is closed by walking its nested headers to the
/// matching end-of-contents octets.
/// @param src        Frame source (see \c StreamSource, \c SpanSource).
/// @param base       Absolute input offset of the frame, for error offsets.
/// @param max_frame  \c FrameLimits::max_frame.
/// @return The frame length; \c std::nullopt when the input ends before the
///         record's first octet; or a reason-keyed framing error.
/// @see X.690 §8.1.2 (identifier), §8.1.3 (length), §8.1.5 (end-of-contents).
template <class Source>
FrameLength frame_length(Source& src, std::uint64_t base, std::size_t max_frame) {
    // Make the first n frame octets available: frame-too-large past the
    // limit (checked before reading), truncated when the input ends first.
    auto need = [&](std::size_t n) -> std::optional<DecodeError> {
        if (n > max_frame)
            return DecodeError("frame-too-large: record longer than " + std::to_string(max_frame) + " octets",
                               static_cast<std::size_t>(base));
        auto got = src.fill(n);
        if (!got) {
            DecodeError e = got.error();
            e.offset = static_cast<std::size_t>(base + src.available());
            return e;
        }
        if (!*got)
            return DecodeError("truncated: input ends inside a record",
                               static_cast<std::size_t>(base + src.available()));
        return std::nullopt;
    };

    auto header = [&](std::size_t pos, Header& h) -> std::optional<DecodeError> {
        if (auto e = need(pos + 1)) return e;
        const std::uint8_t first = src.at(pos);
        const bool constructed = first & 0x20;
        std::size_t p = pos + 1;
        if ((first & 0x1F) == 0x1F) {
            std::uint64_t number = 0;
            for (int k = 1;; ++k) {
                if (auto e = need(p + 1)) return e;
                const std::uint8_t b = src.at(p++);
                number = (number << 7) | (b & 0x7F);
                if (!(b & 0x80)) break;
                if (k == 5)
                    return DecodeError("tag-too-long: tag number longer than 5 octets or above 2^31-1",
                                       static_cast<std::size_t>(base + pos));
            }
            if (number > 0x7FFFFFFF)
                return DecodeError("tag-too-long: tag number longer than 5 octets or above 2^31-1",
                                   static_cast<std::size_t>(base + pos));
        }
        if (auto e = need(p + 1)) return e;
        const std::uint8_t l = src.at(p);
        h = Header{};
        h.eoc = first == 0 && l == 0;
        if (l == 0x80) {
            if (!constructed)
                return DecodeError("indefinite-primitive: indefinite length on a primitive encoding",
                                   static_cast<std::size_t>(base + p));
            h.indefinite = true;
            h.end = p + 1;
        } else if (l & 0x80) {
            const std::size_t n = l & 0x7F;
            if (n > 8)
                return DecodeError("length-field-too-long: length field of " + std::to_string(n) +
                                       " octets (at most 8)",
                                   static_cast<std::size_t>(base + p));
            if (auto e = need(p + 1 + n)) return e;
            for (std::size_t i = 0; i < n; ++i)
                h.length = (h.length << 8) | src.at(p + 1 + i);
            h.end = p + 1 + n;
        } else {
            h.length = l;
            h.end = p + 1;
        }
        return std::nullopt;
    };

    // Skip definite contents: the whole TLV must fit the limit.
    auto skip = [&](const Header& h) -> std::optional<DecodeError> {
        if (h.length > max_frame - std::min(h.end, max_frame))
            return DecodeError("frame-too-large: record longer than " + std::to_string(max_frame) + " octets",
                               static_cast<std::size_t>(base));
        return need(h.end + static_cast<std::size_t>(h.length));
    };

    auto first = src.fill(1);
    if (!first) {
        DecodeError e = first.error();
        e.offset = static_cast<std::size_t>(base);
        return make_unexpected<std::optional<std::size_t>, DecodeError>(std::move(e));
    }
    if (!*first) return std::optional<std::size_t>{};

    Header h;
    if (auto e = header(0, h)) return make_unexpected<std::optional<std::size_t>, DecodeError>(std::move(*e));
    if (!h.indefinite) {
        if (auto e = skip(h)) return make_unexpected<std::optional<std::size_t>, DecodeError>(std::move(*e));
        return std::optional<std::size_t>{h.end + static_cast<std::size_t>(h.length)};
    }
    int depth = 1;
    std::size_t pos = h.end;
    for (;;) {
        Header c;
        if (auto e = header(pos, c)) return make_unexpected<std::optional<std::size_t>, DecodeError>(std::move(*e));
        if (c.eoc) {
            pos = c.end;
            if (--depth == 0) return std::optional<std::size_t>{pos};
        } else if (c.indefinite) {
            if (depth == kMaxDecodeDepth)
                return frame_error("too-deep: more than " + std::to_string(kMaxDecodeDepth) +
                                       " nested indefinite-length levels",
                                   base + pos);
            ++depth;
            pos = c.end;
        } else {
            if (auto e = skip(c)) return make_unexpected<std::optional<std::size_t>, DecodeError>(std::move(*e));
            pos = c.end + static_cast<std::size_t>(c.length);
        }
    }
}

/// @brief Frame source over an \c IByteInput: reads into \p buf exactly as
///        many octets as the walk asks for.
struct StreamSource {
    IByteInput& in;
    std::vector<std::uint8_t>& buf;

    Expected<bool, DecodeError> fill(std::size_t n) {
        while (buf.size() < n) {
            const std::size_t old = buf.size();
            buf.resize(n);
            auto got = in.read(std::span<std::uint8_t>(buf.data() + old, n - old));
            if (!got) {
                buf.resize(old);
                return make_unexpected<bool, DecodeError>(std::move(got.error()));
            }
            buf.resize(old + *got);
            if (*got == 0) return false;
        }
        return true;
    }
    std::uint8_t at(std::size_t i) const { return buf[i]; }
    std::size_t available() const { return buf.size(); }
};

/// @brief Frame source over the unread part of a span: bounds checks only.
struct SpanSource {
    std::span<const std::uint8_t> rest;

    Expected<bool, DecodeError> fill(std::size_t n) const { return n <= rest.size(); }
    std::uint8_t at(std::size_t i) const { return rest[i]; }
    std::size_t available() const { return rest.size(); }
};

} // namespace

Expected<std::size_t, DecodeError> IstreamInput::read(std::span<std::uint8_t> dst) {
    in_.read(reinterpret_cast<char*>(dst.data()), static_cast<std::streamsize>(dst.size()));
    if (in_.bad())
        return make_unexpected<std::size_t, DecodeError>(DecodeError("read error: stream failure"));
    return static_cast<std::size_t>(in_.gcount());
}

Expected<std::size_t, DecodeError> FileInput::read(std::span<std::uint8_t> dst) {
    const std::size_t got = std::fread(dst.data(), 1, dst.size(), f_);
    if (got == 0 && std::ferror(f_))
        return make_unexpected<std::size_t, DecodeError>(
            DecodeError(std::string("read error: ") + std::strerror(errno)));
    return got;
}

Expected<std::optional<BerFrame>, DecodeError> BerFrameReader::next() {
    if (failed_) return make_unexpected<std::optional<BerFrame>, DecodeError>(*failed_);
    buf_.clear();
    StreamSource src{in_, buf_};
    auto len = frame_length(src, offset_, limits_.max_frame);
    if (!len) {
        failed_ = len.error();
        return make_unexpected<std::optional<BerFrame>, DecodeError>(std::move(len.error()));
    }
    if (!*len) return std::optional<BerFrame>{};
    BerFrame frame{offset_, std::span<const std::uint8_t>(buf_.data(), **len)};
    offset_ += **len;
    return std::optional<BerFrame>{frame};
}

Expected<std::optional<BerFrame>, DecodeError> BerSpanFrames::next() {
    if (failed_) return make_unexpected<std::optional<BerFrame>, DecodeError>(*failed_);
    SpanSource src{data_.subspan(pos_)};
    auto len = frame_length(src, base_ + pos_, limits_.max_frame);
    if (!len) {
        failed_ = len.error();
        return make_unexpected<std::optional<BerFrame>, DecodeError>(std::move(len.error()));
    }
    if (!*len) return std::optional<BerFrame>{};
    BerFrame frame{base_ + pos_, data_.subspan(pos_, **len)};
    pos_ += **len;
    return std::optional<BerFrame>{frame};
}

DecodeResult decode_frame(const BerFrame& frame, const TypeDescriptor& def, Asn1Object* dest,
                          const ContainedOptions* contained) {
    BerReader r{frame.bytes, DecodeDepth{}, contained};
    BerDecodeStream s{r};
    auto result = BerCodec::instance().decode(s, def, dest);
    if (!result) result.error().offset += static_cast<std::size_t>(frame.offset);
    return result;
}

} // namespace asn1
