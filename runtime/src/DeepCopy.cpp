#include <asn1cpp/codec/DeepCopy.hpp>
#include <asn1cpp/TypeDescriptor.hpp>
#include <asn1cpp/ChoiceInterface.hpp>
#include <asn1cpp/SeqOfBase.hpp>

namespace asn1 {

void deep_copy(const TypeDescriptor& def, Asn1Object* dst, const Asn1Object* src) {
    if (def.sequence_spec) {
        const auto& spec = *def.sequence_spec;
        for (int i = 0; i < spec.count; ++i) {
            const auto& mbr = spec.members[i];
            if (!mbr.type_descriptor) continue;
            if (mbr.optional) {
                bool src_present = mbr.optional_ops.is_present(src);
                bool dst_present = mbr.optional_ops.is_present(dst);
                if (!src_present) {
                    if (dst_present) mbr.optional_ops.set_present(dst, false);
                    continue;
                }
                if (!dst_present) mbr.optional_ops.set_present(dst, true);
            }
            Asn1Object*       dst_m = mbr.optional_ops.member_ptr(dst,                          mbr.offset);
            const Asn1Object* src_m = mbr.optional_ops.member_ptr(const_cast<Asn1Object*>(src), mbr.offset);
            deep_copy(*mbr.type_descriptor, dst_m, src_m);
        }
    } else if (def.choice_spec) {
        const auto& spec  = *def.choice_spec;
        auto*       dst_ch = static_cast<ChoiceInterface*>(dst);
        const auto* src_ch = static_cast<const ChoiceInterface*>(src);
        int idx = src_ch->_present;

        // Destroy dst's current alternative.
        dst_ch->active_lifecycle->destroy(dst_ch->val_);
        dst_ch->active_lifecycle = &ChoiceInterface::k_noop_lifecycle;
        dst_ch->_present = 0;

        if (idx <= 0 || idx > spec.count) return; // src is NOTHING

        const auto& alt     = spec.alternatives[idx - 1];
        const auto& alt_def = *alt.type_descriptor;

        // Construct a fresh default alternative, then recursively copy content.
        // Using construct+recurse (not clone) so this works even for arm types
        // that are themselves SEQUENCE-with-optionals or CHOICE.
        alt_def.lifecycle.construct(dst_ch->val_);
        dst_ch->active_lifecycle = &alt_def.lifecycle;
        dst_ch->_present = idx;

        Asn1Object*       dst_val = alt.get_mut_fn(dst);
        const Asn1Object* src_val = alt.get_const_fn(const_cast<Asn1Object*>(src));
        deep_copy(alt_def, dst_val, src_val);

    } else if (def.seq_of_spec) {
        const auto& spec    = *def.seq_of_spec;
        auto&       dst_seq = *static_cast<SeqOfBase*>(dst);
        const auto& src_seq = *static_cast<const SeqOfBase*>(src);
        std::size_t n       = src_seq.count();
        dst_seq.resize(n);
        const auto& edef = *spec.element;
        for (std::size_t i = 0; i < n; ++i)
            deep_copy(edef, dst_seq.get_mut(i), src_seq.get_const(i));

    } else {
        // Primitive / ENUMERATED / leaf: destroy current value, clone from src.
        def.lifecycle.destroy(dst);
        def.lifecycle.clone(dst, src);
    }
}

} // namespace asn1
