//! Regression test for the SEQUENCE-OF-as-member BER decode path
//! (`ber::object::decode_seqof_content`): unlike the standalone
//! `ber::sequence::decode_seq_of_content` (which pre-counts top-level
//! TLVs via `count_top_level_tlvs` and reserves the `Vec` once),
//! `decode_seqof_content` grows the element `Vec` one `push` at a time
//! through `Asn1SeqOf::push_default_mut`, with no upfront reservation —
//! X.690 §8.9 content is a flat run of element TLVs, so the same
//! zero-copy pre-count used by the standalone path is just as available
//! here; the member path simply doesn't take it.
//!
//! This test decodes a `SEQUENCE { items SEQUENCE OF INTEGER }` (the
//! member path, not the standalone-type path) with N elements and counts
//! how many times the backing allocation for `items` actually grows.
//! `Vec::push`'s geometric doubling means growth count is `ceil(log2(N))`
//! for N elements starting from empty; a single upfront
//! `Vec::with_capacity(N)` would cost exactly 1. A separate global
//! allocator per integration-test binary is required to isolate the
//! count to just this process's `Vec<Integer>` growth (no XER/JER string
//! allocation is on this path — pure BER decode).

use std::alloc::{GlobalAlloc, Layout, System};
use std::sync::atomic::{AtomicUsize, Ordering};

use asn1cpp_wire::ber::object::{decode_seq_into, encode_seq_into};
use asn1cpp_wire::ber::reader::Reader;
use asn1cpp_wire::integer::Integer;
use asn1cpp_wire::spec::choice::BerTagging;
use asn1cpp_wire::spec::object::{
    Asn1Seq, MemberMeta, MemberRef, MemberRefMut, SequenceSpec, XerInstruction,
};
use asn1cpp_wire::spec::sequence::SEQUENCE_TAG;
use asn1cpp_wire::constraints::UNCONSTRAINED;

static GROW_COUNT: AtomicUsize = AtomicUsize::new(0);

/// Counts every `realloc` call whose new size is larger than the old one
/// (a genuine backing-store grow, not a shrink) — `Vec::push`'s geometric
/// doubling shows up here one call per capacity jump.
struct CountingAlloc;

unsafe impl GlobalAlloc for CountingAlloc {
    unsafe fn alloc(&self, layout: Layout) -> *mut u8 {
        System.alloc(layout)
    }
    unsafe fn dealloc(&self, ptr: *mut u8, layout: Layout) {
        System.dealloc(ptr, layout)
    }
    unsafe fn realloc(&self, ptr: *mut u8, layout: Layout, new_size: usize) -> *mut u8 {
        if new_size > layout.size() {
            GROW_COUNT.fetch_add(1, Ordering::Relaxed);
        }
        System.realloc(ptr, layout, new_size)
    }
}

#[global_allocator]
static ALLOC: CountingAlloc = CountingAlloc;

/// `Container ::= SEQUENCE { items SEQUENCE OF INTEGER }` — the element
/// SeqOf is a *member* of a SEQUENCE, so its decode routes through
/// `ber::object::decode_seqof_content`, not the standalone
/// `ber::sequence::decode_seq_of_content` fast path.
#[derive(Debug, Default, Clone, PartialEq)]
struct Container {
    items: asn1cpp_wire::ber::sequence::SeqOf<Integer>,
}

static CONTAINER_MEMBERS: [MemberMeta; 1] = [MemberMeta {
    name: "items",
    tag: SEQUENCE_TAG,
    optional: false,
    ber: BerTagging::Delegate,
    constraints: &UNCONSTRAINED,
    xer_instruction: XerInstruction::Default,
}];

static CONTAINER_SPEC: SequenceSpec = SequenceSpec {
    name: "Container",
    tag: SEQUENCE_TAG,
    members: &CONTAINER_MEMBERS,
    ext_at: -1,
    roms_count: 0,
    is_set: false,
    ext_units: &[],
    group_member_optional: &[],
};

impl Asn1Seq for Container {
    fn spec(&self) -> &'static SequenceSpec {
        &CONTAINER_SPEC
    }
    fn get_member(&self, index: usize) -> MemberRef<'_> {
        match index {
            0 => MemberRef::SeqOf(&self.items),
            _ => unreachable!(),
        }
    }
    fn get_member_mut(&mut self, index: usize) -> MemberRefMut<'_> {
        match index {
            0 => MemberRefMut::SeqOf(&mut self.items),
            _ => unreachable!(),
        }
    }
    fn set_default(&mut self, _index: usize) {}
    fn is_default_equal(&self, _index: usize) -> bool {
        false
    }
    fn validate(&self, _index: usize) -> i64 {
        0
    }
}

fn integer(v: i64) -> Integer {
    let mut i = Integer::default();
    *i = v;
    i
}

#[test]
fn seqof_member_decode_does_not_regrow_geometrically() {
    const N: usize = 64;

    let mut src = Container::default();
    src.items.0 = (0..N as i64).map(integer).collect();

    let mut wire = Vec::new();
    encode_seq_into(&src, &mut wire);

    GROW_COUNT.store(0, Ordering::Relaxed);
    let mut decoded = Container::default();
    let mut r = Reader::new(&wire);
    decode_seq_into(&mut decoded, &mut r).expect("decode must succeed");

    assert_eq!(decoded.items.0.len(), N);
    assert_eq!(decoded, src);

    let grows = GROW_COUNT.load(Ordering::Relaxed);
    // A single Vec::with_capacity(N) reservation costs 0 realloc grows
    // (the initial allocation isn't a realloc). Geometric doubling from
    // empty costs ceil(log2(N)) = 6 for N=64. Anything above 1 proves the
    // member path isn't pre-reserving the way the standalone
    // `decode_seq_of_content` path does.
    assert!(
        grows <= 1,
        "expected <=1 backing-store grow for a pre-reserved Vec of {N} elements, got {grows} \
         (ber::object::decode_seqof_content grows geometrically via plain Vec::push, \
         unlike ber::sequence::decode_seq_of_content's count_top_level_tlvs pre-reserve)"
    );
}
