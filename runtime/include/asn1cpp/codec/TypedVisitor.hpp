#pragma once
#include <functional>
#include <map>
#include <type_traits>

#include "../Asn1Object.hpp"
#include "../ChoiceInterface.hpp"
#include "../SeqOfBase.hpp"
#include "../TypeDescriptor.hpp"

/// @file TypedVisitor.hpp
/// @brief Register-per-type callback walkers over a fully-decoded object tree.
///
/// Traverse a decoded ASN.1 object once, firing a typed callback for each
/// registered type. Multiple types can be registered for a single traversal;
/// each match delivers a typed \c const T& (\c TypedVisitor) or \c T&
/// (\c TypedMutator) — no re-decode, no reinterpret_cast.
///
/// The traversal mirrors \c BerCodec::encode: SEQUENCE/SET via
/// \c sequence_spec->members and \c MemberDescriptor::offset, CHOICE via the
/// active \c ChoiceInterface alternative, SEQUENCE OF / SET OF via
/// \c SeqOfBase::count() + \c get_const()/get_mut(). Dispatch is by
/// \c TypeDescriptor pointer identity (\c &T::asn_DEF), matching the
/// descriptor-identity semantics used elsewhere in the runtime.
///
/// Visit order is pre-order (a matched node fires before its children are
/// walked), in document order. A matched node is still descended into unless
/// the callback returns \c SkipChildren.

namespace asn1 {

/// @brief Callback return value controlling traversal after a match.
enum class VisitControl {
    Continue,     ///< Keep walking (descend into this node's children).
    SkipChildren, ///< Do not descend into this node; continue with siblings.
    Stop,         ///< Abort the whole traversal immediately.
};

namespace detail {

/// @brief Shared traversal core for \c TypedVisitor / \c TypedMutator.
/// @tparam Ptr  Either \c const Asn1Object* (visitor) or \c Asn1Object* (mutator).
template<typename Ptr>
class TypedWalkerBase {
    static_assert(std::is_pointer_v<Ptr>, "Ptr must be a pointer type");
    static constexpr bool kMutable = !std::is_const_v<std::remove_pointer_t<Ptr>>;

protected:
    std::map<const TypeDescriptor*, std::function<VisitControl(Ptr)>> handlers_;

    /// @brief Walk \p obj (typed by \p def), firing registered callbacks.
    /// @return \c Stop if traversal was aborted, else \c Continue.
    VisitControl walk(const TypeDescriptor& def, Ptr obj, int depth) const {
        if (auto it = handlers_.find(&def); it != handlers_.end()) {
            switch (it->second(obj)) {
                case VisitControl::Stop:         return VisitControl::Stop;
                case VisitControl::SkipChildren: return VisitControl::Continue;
                case VisitControl::Continue:     break;
            }
        }

        switch (def.kind) {
            case TypeKind::Sequence: {  // also SET
                const auto& spec = *def.sequence_spec;
                for (int i = 0; i < spec.count; ++i) {
                    const auto& mbr = spec.members[i];
                    if (!mbr.type_descriptor) continue;
                    if (mbr.optional_ops && !mbr.optional_ops.is_present(obj)) continue;
                    Ptr mptr = mbr.optional_ops.member_ptr(obj, mbr.offset);
                    if (walk(*mbr.type_descriptor, mptr, depth + 1) == VisitControl::Stop)
                        return VisitControl::Stop;
                }
                break;
            }
            case TypeKind::Choice: {
                const auto* ch = static_cast<const ChoiceInterface*>(obj);
                const auto& spec = *def.choice_spec;
                int idx = ch->choice_present();  // 1-based; 0 = no alternative set
                if (idx > 0 && idx <= spec.count) {
                    const auto& alt = spec.alternatives[idx - 1];
                    if (alt.type_descriptor) {
                        Ptr aptr;
                        if constexpr (kMutable) aptr = alt.get_mut_fn(obj);
                        else                    aptr = alt.get_const_fn(obj);
                        if (aptr &&
                            walk(*alt.type_descriptor, aptr, depth + 1) == VisitControl::Stop)
                            return VisitControl::Stop;
                    }
                }
                break;
            }
            case TypeKind::SeqOf: {  // also SET OF
                const auto& edef = *def.seq_of_spec->element;
                if constexpr (kMutable) {
                    auto* seq = static_cast<SeqOfBase*>(obj);
                    std::size_t n = seq->count();
                    for (std::size_t i = 0; i < n; ++i)
                        if (walk(edef, seq->get_mut(i), depth + 1) == VisitControl::Stop)
                            return VisitControl::Stop;
                } else {
                    const auto* seq = static_cast<const SeqOfBase*>(obj);
                    std::size_t n = seq->count();
                    for (std::size_t i = 0; i < n; ++i)
                        if (walk(edef, seq->get_const(i), depth + 1) == VisitControl::Stop)
                            return VisitControl::Stop;
                }
                break;
            }
            default:  // Primitive / Enumerated / Any — leaf, nothing to descend.
                break;
        }
        return VisitControl::Continue;
    }
};

}  // namespace detail

/// @brief Read-only per-type callback walker over a decoded object tree.
///
/// @code
/// TypedVisitor v;
/// v.on<CCPayload>([&](const CCPayload& cc){ pcap_write(cc); return VisitControl::Continue; });
/// v.on<Location>([&](const Location& loc){ dump(loc);      return VisitControl::Continue; });
/// v.visit(pdu);   // single pass, both callbacks fire in document order
/// @endcode
class TypedVisitor : public detail::TypedWalkerBase<const Asn1Object*> {
public:
    /// @brief Register a callback for every node of type \c T (dispatch by \c &T::asn_DEF).
    /// A later registration for the same type replaces the earlier one.
    template<typename T>
    void on(std::function<VisitControl(const T&)> cb) {
        handlers_[&T::asn_DEF] = [cb = std::move(cb)](const Asn1Object* p) {
            return cb(*static_cast<const T*>(p));
        };
    }

    /// @brief Walk \p root, firing all registered callbacks.
    template<typename RootT>
    void visit(const RootT& root) const {
        walk(RootT::asn_DEF, &root, 0);
    }
};

/// @brief Mutable sibling of \c TypedVisitor — callbacks receive \c T& and may
/// modify fields in place; re-encoding the object reflects the changes.
class TypedMutator : public detail::TypedWalkerBase<Asn1Object*> {
public:
    /// @brief Register a mutating callback for every node of type \c T.
    template<typename T>
    void on(std::function<VisitControl(T&)> cb) {
        handlers_[&T::asn_DEF] = [cb = std::move(cb)](Asn1Object* p) {
            return cb(*static_cast<T*>(p));
        };
    }

    /// @brief Walk \p root, firing all registered mutating callbacks.
    template<typename RootT>
    void visit(RootT& root) const {
        walk(RootT::asn_DEF, &root, 0);
    }
};

}  // namespace asn1
