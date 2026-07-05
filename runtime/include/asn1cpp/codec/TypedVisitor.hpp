#pragma once
#include <functional>
#include <map>
#include <type_traits>
#include <unordered_map>
#include <unordered_set>
#include <vector>

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
///
/// @tparam Ptr  Either \c const Asn1Object* (visitor) or \c Asn1Object* (mutator);
///              constrained to a (possibly const) pointer-to-\c Asn1Object.
///
/// @par Thread safety
/// Registration (\c on<T>) mutates \c handlers_ and is not thread-safe: register
/// all callbacks first. The first \c visit for a given root also builds the
/// reachability set (see Pruning), which mutates internal state — so before
/// sharing a visitor read-only across threads, warm it once with \c prepare<Root>().
/// After that, \c walk / \c visit only read shared state and a single visitor may
/// be shared to walk different objects concurrently. \c TypedMutator additionally
/// mutates the walked object, so two threads must not mutate the same object.
///
/// @par Pruning
/// By default the walk skips any subtree whose type cannot reach a registered
/// target through the static descriptor graph — e.g. searching for a Location in
/// a CC-only PDU never descends the CC subtree. The reachability set is computed
/// once per root (reverse-BFS over the descriptor graph) and cached. Results are
/// identical to a full traversal; only dead subtrees are skipped. Disable with
/// \c set_pruning(false) (e.g. for benchmarking the difference).
///
/// @par Handler storage
/// \c handlers_ is keyed by \c TypeDescriptor pointer identity. The registered
/// set is tiny (one entry per registered type — typically a handful), so an
/// ordered \c std::map lookup per node is negligible.
template<typename Ptr>
class TypedWalkerBase {
    static_assert(
        std::is_same_v<std::remove_const_t<std::remove_pointer_t<Ptr>>, Asn1Object>,
        "Ptr must be Asn1Object* or const Asn1Object*");
    static constexpr bool kMutable = !std::is_const_v<std::remove_pointer_t<Ptr>>;

public:
    /// @brief Enable/disable static subtree pruning (default: enabled).
    ///
    /// When enabled, a reachability set is computed once per root (lazily on the
    /// first \c visit, or eagerly via \c prepare) and the walk skips any subtree
    /// whose type cannot reach a registered target through the schema graph.
    /// Results are identical either way — only unreachable subtrees are not
    /// descended. Disable to force a full traversal (e.g. for benchmarking).
    void set_pruning(bool on) {
        pruning_ = on;
        if (!on) { reachable_.clear(); reach_root_ = nullptr; }
    }
    bool pruning() const { return pruning_; }

    /// @brief Pre-compute the reachability set for \c RootT (warm the cache).
    /// Call before sharing a visitor read-only across threads: the first
    /// \c visit otherwise builds it, which mutates internal state.
    template<typename RootT>
    void prepare() const { ensure_reach(RootT::asn_DEF); }

protected:
    std::map<const TypeDescriptor*, std::function<VisitControl(Ptr)>> handlers_;

    bool pruning_ = true;
    /// Types from which a registered target is reachable (targets + their
    /// ancestors in the descriptor graph). Empty until built. Keyed to \c reach_root_.
    mutable std::unordered_set<const TypeDescriptor*> reachable_;
    mutable const TypeDescriptor* reach_root_ = nullptr;

    /// @brief True when descent into a node of type \p d should be pruned.
    bool pruned(const TypeDescriptor* d) const {
        return pruning_ && reach_root_ && !reachable_.count(d);
    }

    /// @brief Build (once) the set of types that can reach any registered target,
    /// starting from \p root. Reverse-BFS over the static descriptor graph:
    /// forward-enumerate reachable types + parent edges, then walk backward from
    /// the targets marking every ancestor. Cycle-safe (recursive schemas).
    void ensure_reach(const TypeDescriptor& root) const {
        if (!pruning_ || reach_root_ == &root) return;
        reachable_.clear();
        reach_root_ = &root;
        if (handlers_.empty()) return;  // no targets → everything prunes

        std::unordered_set<const TypeDescriptor*> nodes{&root};
        std::unordered_map<const TypeDescriptor*, std::vector<const TypeDescriptor*>> parents;
        std::vector<const TypeDescriptor*> stack{&root};
        auto add_edge = [&](const TypeDescriptor* p, const TypeDescriptor* c) {
            if (!c) return;
            parents[c].push_back(p);
            if (nodes.insert(c).second) stack.push_back(c);
        };
        while (!stack.empty()) {
            const TypeDescriptor* d = stack.back(); stack.pop_back();
            switch (d->kind) {
                case TypeKind::Sequence: { const auto& s = *d->sequence_spec;
                    for (int i = 0; i < s.count; ++i) add_edge(d, s.members[i].type_descriptor); } break;
                case TypeKind::Choice: { const auto& s = *d->choice_spec;
                    for (int i = 0; i < s.count; ++i) add_edge(d, s.alternatives[i].type_descriptor); } break;
                case TypeKind::SeqOf: add_edge(d, d->seq_of_spec->element); break;
                default: break;
            }
        }
        std::vector<const TypeDescriptor*> q;
        for (const auto& kv : handlers_)
            if (nodes.count(kv.first) && reachable_.insert(kv.first).second)
                q.push_back(kv.first);
        while (!q.empty()) {
            const TypeDescriptor* c = q.back(); q.pop_back();
            auto it = parents.find(c);
            if (it == parents.end()) continue;
            for (const TypeDescriptor* p : it->second)
                if (reachable_.insert(p).second) q.push_back(p);
        }
    }

    /// @brief Walk \p obj (typed by \p def), firing registered callbacks.
    /// @return \c Stop if traversal was aborted, else \c Continue.
    VisitControl walk(const TypeDescriptor& def, Ptr obj, int depth) const {
        if (pruned(&def)) return VisitControl::Continue;  // no target here or below

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
                    if (!mbr.type_descriptor || pruned(mbr.type_descriptor)) continue;
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
                    if (alt.type_descriptor && !pruned(alt.type_descriptor)) {
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
                if (pruned(&edef)) break;
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
        ensure_reach(RootT::asn_DEF);
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
        ensure_reach(RootT::asn_DEF);
        walk(RootT::asn_DEF, &root, 0);
    }
};

}  // namespace asn1
