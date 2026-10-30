#pragma once
#include <ostream>
#include "TypeDescriptor.hpp"

namespace asn1 {

/// @brief Write one type's descriptor tables as one line of canonical JSON.
///
/// Part of the cross-language table check: every runtime serialises its own
/// static tables in the same format (doc/backend-guide.md, Appendix A), and
/// validation-tools/table_diff compares the dumps field by field. The dump
/// reads the tables only; it never encodes or decodes a value.
/// @param def  the type's top-level descriptor (\c T::asn_DEF or \c asn_DEF_T).
/// @param os   receives one JSON object followed by a newline.
void dump_tables(const TypeDescriptor& def, std::ostream& os);

} // namespace asn1
