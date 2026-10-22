#pragma once
#include <cstdint>
#include <functional>
#include <map>
#include <optional>
#include <span>
#include <string>
#include <string_view>
#include <vector>
#include "../types/Containing.hpp"
#include "DecodeDepth.hpp"

namespace asn1 {

struct TypeDescriptor;
class ContainedDecoders;
struct ContainedOptions;

/// @brief Outcome of a contained-value decoder.
struct ContainedResult {
    ContainedStatus status = ContainedStatus::Decoded;
    std::string     message;   ///< Reason for Skipped/Failed.

    static ContainedResult ok() { return {}; }
    static ContainedResult skipped(std::string why) { return {ContainedStatus::Skipped, std::move(why)}; }
    static ContainedResult failed(std::string why)  { return {ContainedStatus::Failed, std::move(why)}; }
};

/// @brief What a contained-value decoder gets: the raw bytes, the field's
///        spec, a default-constructed inner value to fill, and the enclosing
///        value so a hook can look at its siblings (e.g. an encryption type).
struct ContainedDecodeArgs {
    std::span<const uint8_t>  raw;
    const ContainedSpec&      spec;
    Asn1Object&               inner;        ///< Default inner value to decode into.
    const Asn1Object*         outer;        ///< Enclosing SEQUENCE/SET or CHOICE value.
    const TypeDescriptor*     outer_def;    ///< Its descriptor.
    ContainedEncoding         encoding;     ///< Resolved encoding (never Outer).
    DecodeDepth               depth;        ///< Nesting depth at the field.
    const ContainedDecoders&  decoders;     ///< Registry in use.
    const ContainedOptions*   options;      ///< Settings in use; passed on to nested decodes.
};

/// @brief What a contained-value encoder gets: the inner value to encode
///        into the field's bytes.
struct ContainedEncodeArgs {
    const Asn1Object&         inner;
    const ContainedSpec&      spec;
    ContainedEncoding         encoding;     ///< Resolved encoding (never Outer).
    const ContainedDecoders&  decoders;     ///< Registry in use.
    const ContainedOptions*   options;      ///< Settings in use; passed on to nested encodes.
};

/// @brief Decoder: fills \c args.inner from \c args.raw.
using ContainedDecodeFn = std::function<ContainedResult(const ContainedDecodeArgs& args)>;
/// @brief Encoder: produces the field's bytes from \c args.inner.
/// @return false with \p error set when the value cannot be encoded.
using ContainedEncodeFn = std::function<bool(const ContainedEncodeArgs& args,
                                             std::vector<uint8_t>& out, std::string& error)>;

/// @brief Named contained-value decoders, as referenced by a field's
///        `decoder` setting. Pre-loaded with the built-ins:
///
/// | Name           | Decode | Encode |
/// |----------------|--------|--------|
/// | `plain`        | the bytes are exactly one value | the value's encoding |
/// | `zero_padding` | one value, then only 0x00 octets (block padding) | no padding |
/// | `pkcs7`        | strip RFC 5652 §6.3 padding, then `plain` | pad to the block size |
/// | `none`         | never decodes (Skipped) | — |
///
/// An application registers its own names (e.g. a decrypting decoder), or
/// replaces a built-in, and passes the registry to the decode via
/// \c ContainedOptions.
class ContainedDecoders {
public:
    struct Entry {
        ContainedDecodeFn decode;
        ContainedEncodeFn encode;   ///< Empty: the inner value cannot be re-encoded.
    };

    ContainedDecoders();
    /// @brief The built-in registry, used when no options are given.
    static const ContainedDecoders& defaults();

    /// @brief Register or replace the decoder \p name.
    void add(std::string name, ContainedDecodeFn decode, ContainedEncodeFn encode = {});
    /// @return The entry for \p name, or nullptr.
    const Entry* find(std::string_view name) const;

    /// @brief Block size the `pkcs7` encoder pads to (default 16, AES).
    std::size_t pkcs7_block_size = 16;

    /// @brief Decode \p bytes with the args' encoding into \c args.inner,
    ///        for use by decoders after they transformed the raw bytes.
    /// @param consumed  Receives the number of octets the value used; when
    ///                  null, the value must use all of \p bytes.
    static ContainedResult decode_value(const ContainedDecodeArgs& args,
                                        std::span<const uint8_t> bytes,
                                        std::size_t* consumed = nullptr);
    /// @brief Encode \c args.inner with the args' encoding.
    static bool encode_value(const ContainedEncodeArgs& args, std::vector<uint8_t>& out,
                             std::string& error);

private:
    std::map<std::string, Entry, std::less<>> entries_;
};

/// @brief Contained-value settings for one decode or encode, carried on the
///        codec streams/readers (and on to nested readers).
struct ContainedOptions {
    const ContainedDecoders*      decoders = nullptr;   ///< nullptr: ContainedDecoders::defaults().
    bool                          off = false;          ///< Decode no contained value at all.
    std::optional<ContainedText>  xer;                  ///< Override every field's XER form.
    std::optional<ContainedText>  jer;                  ///< Override every field's JER form.

    const ContainedDecoders& registry() const {
        return decoders ? *decoders : ContainedDecoders::defaults();
    }
};

/// @brief Decode the contained members of a decoded SEQUENCE/SET value
///        (all members are present, so `when` siblings can be read).
/// @param outer_encoding  Encoding rules of the outer decode (Ber or PerUnaligned).
/// @return false with \p error set only for a field with `on_error: fail`.
/// @see X.682 §11.4
bool decode_contained_members(const TypeDescriptor& def, Asn1Object* value,
                              ContainedEncoding outer_encoding, const DecodeDepth& depth,
                              const ContainedOptions* opts, std::string& error);

/// @brief Decode the active alternative of a decoded CHOICE value when it is
///        a contained field.
/// @return false with \p error set only for a field with `on_error: fail`.
bool decode_contained_alternative(const TypeDescriptor& def, Asn1Object* value,
                                  ContainedEncoding outer_encoding, const DecodeDepth& depth,
                                  const ContainedOptions* opts, std::string& error);

/// @brief The bytes a contained field encodes as: its raw bytes, or, after
///        the inner value was modified, the inner value's encoding.
/// @param scratch  Storage for derived bytes.
/// @return The bytes to write.
std::span<const uint8_t> contained_wire_bytes(const TypeDescriptor& field_def,
                                              const ContainedBase& v,
                                              ContainedEncoding outer_encoding,
                                              const ContainedOptions* opts,
                                              std::vector<uint8_t>& scratch);

} // namespace asn1
