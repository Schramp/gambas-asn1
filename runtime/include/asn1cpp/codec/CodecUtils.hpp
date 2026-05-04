#pragma once
#include "ICodec.hpp"
#include "../TypeDescriptor.hpp"

namespace asn1 {

// Typed encode — takes a const T& instead of const void*.
template<typename T>
void encode(ICodec& codec, IEncodeStream& dst, const TypeDescriptor& def, const T& v) {
    codec.encode(dst, def, &v);
}

// Typed decode — takes T& instead of void*.
template<typename T>
auto decode(ICodec& codec, IDecodeStream& src, const TypeDescriptor& def, T& v) {
    return codec.decode(src, def, &v);
}

} // namespace asn1
