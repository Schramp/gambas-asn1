#pragma once

// Lean include for generated code — type classes + TypeDescriptor tables only.
// No codec internals (BerCodec, XerCodec, PerCodec, RandomFiller, Validation).
// Generated .hpp/.cpp files include this; callers that need codec ops include asn1cpp.hpp.

#include "Asn1Object.hpp"
#include "EnumValue.hpp"
#include "SeqOfBase.hpp"
#include "SequenceInterface.hpp"
#include "ChoiceInterface.hpp"
#include "Expected.hpp"
#include "Error.hpp"
#include "Tag.hpp"

#include "types/Integer.hpp"
#include "types/Boolean.hpp"
#include "types/Null.hpp"
#include "types/OctetString.hpp"
#include "types/BitString.hpp"
#include "types/Real.hpp"
#include "types/Oid.hpp"
#include "types/Strings.hpp"
#include "types/Time.hpp"
#include "TypeDescriptor.hpp"
#include "codec/ValidateCounter.hpp"
