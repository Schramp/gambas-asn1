#pragma once
#include <vector>
#include <cstddef>
#include "Asn1Object.hpp"

namespace asn1 {

// Abstract interface for SEQUENCE OF / SET OF containers.
// Replaces the four type-erased function pointers in SeqOfSpec.
// Inherits Asn1Object so codec handlers can cast void* -> SeqOfBase* safely.
class SeqOfBase : public Asn1Object {
public:
    virtual std::size_t       count()                    const = 0;
    virtual Asn1Object*       get_mut(std::size_t i)           = 0;
    virtual const Asn1Object* get_const(std::size_t i)   const = 0;
    virtual void              resize(std::size_t n)            = 0;
    virtual ~SeqOfBase() = default;
};

// Concrete SEQUENCE OF / SET OF backed by std::vector<ElemType>.
// Generated code emits: using FooList = asn1::VectorSeqOf<ElemType>;
template<typename ElemType>
class VectorSeqOf : public SeqOfBase {
    std::vector<ElemType> data_;
public:
    VectorSeqOf() = default;
    VectorSeqOf(std::initializer_list<ElemType> init) : data_(init) {}

    // SeqOfBase interface
    std::size_t       count() const override { return data_.size(); }
    Asn1Object*       get_mut(std::size_t i) override { return &data_[i]; }
    const Asn1Object* get_const(std::size_t i) const override { return &data_[i]; }
    void        resize(std::size_t n) override { data_.resize(n); }

    // Standard container interface for user code
    ElemType&       operator[](std::size_t i)       { return data_[i]; }
    const ElemType& operator[](std::size_t i) const { return data_[i]; }
    auto begin()        { return data_.begin(); }
    auto end()          { return data_.end(); }
    auto begin()  const { return data_.begin(); }
    auto end()    const { return data_.end(); }
    std::size_t size()  const { return data_.size(); }
    bool empty()        const { return data_.empty(); }
    void push_back(ElemType v) { data_.push_back(std::move(v)); }
    void clear()        { data_.clear(); }
    ElemType& back()          { return data_.back(); }
    const ElemType& back()  const { return data_.back(); }
    const ElemType& front() const { return data_.front(); }

    bool operator==(const VectorSeqOf&) const = default;
};

} // namespace asn1
