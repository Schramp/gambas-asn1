#pragma once
#include <cstddef>
#include <cstdint>
#include <cstdio>
#include <iosfwd>
#include <optional>
#include <span>
#include <vector>
#include "../Error.hpp"
#include "../Expected.hpp"
#include "ICodec.hpp"

namespace asn1 {

struct ContainedOptions;

/// @brief Limits a BER framer applies to each record.
struct FrameLimits {
    /// @brief Largest frame (header, contents and end-of-contents octets)
    ///        accepted; a longer record is refused before it is read.
    std::size_t max_frame = std::size_t{64} << 20;
};

/// @brief One complete top-level BER record, as returned by a framer.
struct BerFrame {
    std::uint64_t offset = 0;              ///< Absolute offset of the record's first octet in the input.
    std::span<const std::uint8_t> bytes;   ///< Tag, length and contents (plus EOC for indefinite length).
};

/// @brief Pull-style byte input for \c BerFrameReader.
///
/// The framer asks for exactly the octets it needs, never more, so the input
/// is left at the start of the next record after each frame.
class IByteInput {
public:
    virtual ~IByteInput() = default;
    /// @brief Read up to \p dst.size() octets into \p dst.
    /// @param dst  Buffer to fill.
    /// @return The number of octets read; 0 only at the end of the input.
    ///         A read failure is a \c DecodeError "read error: <reason>".
    virtual Expected<std::size_t, DecodeError> read(std::span<std::uint8_t> dst) = 0;
};

/// @brief \c IByteInput over a \c std::istream (opened in binary mode).
class IstreamInput final : public IByteInput {
    std::istream& in_;
public:
    /// @brief Read from \p in; it must outlive this object.
    explicit IstreamInput(std::istream& in) : in_(in) {}
    /// @brief See \c IByteInput::read; a stream in the bad state is a read error.
    Expected<std::size_t, DecodeError> read(std::span<std::uint8_t> dst) override;
};

/// @brief \c IByteInput over a C \c FILE* opened for binary reading.
class FileInput final : public IByteInput {
    std::FILE* f_;
public:
    /// @brief Read from \p f; the caller keeps ownership and closes it.
    explicit FileInput(std::FILE* f) : f_(f) {}
    /// @brief See \c IByteInput::read; \c ferror() is a read error.
    Expected<std::size_t, DecodeError> read(std::span<std::uint8_t> dst) override;
};

/// @brief Reads BER records one at a time from an \c IByteInput.
///
/// Memory holds the current record only: its bytes live in a buffer that is
/// reused for the next one, so a file of any size is read in constant
/// memory (the largest record). The framer reads exactly up to the end of
/// each record. After a framing error it reports that same error again on
/// every later call: it cannot know where the next record starts.
///
/// @code
/// std::ifstream f("records.ber", std::ios::binary);
/// asn1::IstreamInput in{f};
/// asn1::BerFrameReader frames{in};
/// while (true) {
///     auto frame = frames.next();
///     if (!frame) { report(frame.error()); break; }   // framing or read error
///     if (!*frame) break;                             // end of input
///     PS_PDU pdu{};
///     if (auto ok = asn1::decode_frame(**frame, PS_PDU::asn_DEF, &pdu); !ok)
///         report(ok.error());                         // next record is still read
/// }
/// @endcode
///
/// @see X.690 §8.1 — identifier, length and contents octets of a record.
/// @see book.md "Reading Records from Files and Streams" — the contract.
class BerFrameReader {
    IByteInput& in_;
    FrameLimits limits_;
    std::vector<std::uint8_t> buf_;
    std::uint64_t offset_ = 0;
    std::optional<DecodeError> failed_;

public:
    /// @brief Frame the records of \p in, which must outlive this reader.
    explicit BerFrameReader(IByteInput& in, FrameLimits limits = {}) : in_(in), limits_(limits) {}

    /// @brief Read the next record.
    /// @return The frame, valid until the next call; \c std::nullopt at the
    ///         end of the input; or a framing / read error.
    Expected<std::optional<BerFrame>, DecodeError> next();

    /// @brief Offset of the next record (the octets consumed so far).
    std::uint64_t offset() const { return offset_; }
};

/// @brief Reads BER records one at a time from a buffer in memory (or a
///        memory-mapped file), without copying.
///
/// Same contract and errors as \c BerFrameReader; the frames are views into
/// the buffer.
class BerSpanFrames {
    std::span<const std::uint8_t> data_;
    FrameLimits limits_;
    std::uint64_t base_;
    std::size_t pos_ = 0;
    std::optional<DecodeError> failed_;

public:
    /// @brief Frame the records of \p data, which must outlive this object.
    /// @param data    The records, back to back.
    /// @param limits  Limits per record.
    /// @param base    Offset of \p data in a larger input; added to every
    ///                frame and error offset.
    explicit BerSpanFrames(std::span<const std::uint8_t> data, FrameLimits limits = {},
                           std::uint64_t base = 0)
        : data_(data), limits_(limits), base_(base) {}

    /// @brief Read the next record.
    /// @return A view of the frame; \c std::nullopt at the end of the data;
    ///         or a framing error.
    Expected<std::optional<BerFrame>, DecodeError> next();
};

/// @brief BER-decode one frame into \p dest.
/// @param frame      A frame from \c BerFrameReader or \c BerSpanFrames.
/// @param def        TypeDescriptor of the record's type.
/// @param dest       Default-constructed target object.
/// @param contained  Settings for contained values, or null for the defaults.
/// @return The decode result; an error's offset is absolute in the input
///         (the frame's offset added).
DecodeResult decode_frame(const BerFrame& frame, const TypeDescriptor& def, Asn1Object* dest,
                          const ContainedOptions* contained = nullptr);

} // namespace asn1
