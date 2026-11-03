package io.github.schramp.gambasasn1.wire.spec;

import java.util.Collections;
import java.util.IdentityHashMap;
import java.util.Map;
import java.util.Set;

/**
 * Where each node of a decoded value lies in its encoding, recorded by a
 * BER or PER decode that was asked for positions ({@code
 * BerObject.decodeWithPositions}, {@code PerObject.decodeWithPositions}).
 *
 * <p>A node is any value object the decode filled: a SEQUENCE/SET, CHOICE,
 * SEQUENCE OF/SET OF, ENUMERATED or primitive value, and a contained field
 * plus every node of its decoded inner value. Nodes are keys by identity, so
 * {@code positions.bitOffset(pdu.payload())} finds that very object. A
 * builtin alias class ({@code LIID ::= OCTET STRING}) and the builtin value
 * in its {@code value} field are the same node.
 *
 * <p>Each node has three spans, each a start bit and an end bit just after
 * it:
 * <ul>
 * <li>its <em>encoding</em> ({@link #bitOffset}, {@link #endBitOffset},
 *     {@link #sizeBits}): in BER from its first tag octet (the outer tag of
 *     an EXPLICIT member) to its last octet, end-of-contents octets of an
 *     indefinite length included; in PER from its first bit (preamble,
 *     length or value) to its last;
 * <li>its <em>contents</em> ({@link #contentsBitOffset} ...): in BER the
 *     contents octets of a primitive value or contained field (X.690 §8.1.1;
 *     inside an EXPLICIT tag the inner TLV's); in PER the octets of a
 *     contained field after their length determinant (X.691 §17.8);
 * <li>its <em>value</em> ({@link #valueBitOffset} ...): the bits that hold
 *     the decoded value itself, for consumers that want the place of the
 *     data rather than of its encoding. In BER this is the contents, except
 *     that a BIT STRING's value leaves out the unused-bits octet and the
 *     unused bits (X.690 §8.6.2), and that a SEQUENCE, SET, SEQUENCE OF or
 *     SET OF value is its contents octets without the end-of-contents
 *     octets. In PER it is the octets of an OCTET STRING, the bits of a BIT
 *     STRING and the octets of a contained field, each after its length
 *     determinant, when that length is not fragmented (X.691 §11.9.3.8). A
 *     CHOICE's value is its chosen alternative's.
 * </ul>
 * A span that does not apply to a node is reported as -1.
 *
 * <p>Offsets are bits from the start of the decode call. {@link #withBase}
 * gives a view that adds a fixed offset, for instance the record's position
 * in an enclosing buffer. An inner value decoded from a contained field is
 * placed at the field's contents octets and ends where its own encoding
 * ends, before any padding the contained-value decoder stripped; this holds
 * for contained-value decoders that pass the octets through or only strip
 * trailing padding (the built-in {@code plain}, {@code zero_padding} and
 * {@code pkcs7}).
 */
public final class Positions {
    /** What the decode recorded about one node, in absolute bits; -1 where nothing was recorded. */
    private static final class Span {
        long start = -1;
        long end = -1;
        long contents = -1;
        long contentsEnd = -1;
        long value = -1;
        long valueEnd = -1;
        long placement = -1;
    }

    private final Map<Object, Span> spans;
    private final Map<Object, Object> owners;
    private final long base;

    private Positions(Map<Object, Span> spans, Map<Object, Object> owners, long base) {
        this.spans = spans;
        this.owners = owners;
        this.base = base;
    }

    /** An empty recorder for one decode. */
    public static Positions recording() {
        return new Positions(new IdentityHashMap<>(), new IdentityHashMap<>(), 0);
    }

    private Span span(Object node) {
        return spans.computeIfAbsent(node, k -> new Span());
    }

    private Span find(Object node) {
        Object v = owners.get(node);
        return spans.get(v == null ? node : v);
    }

    /**
     * Records that {@code node} starts at absolute bit {@code bit}; the first
     * record of a node wins (a CHOICE and its untagged alternative share an
     * offset, the outer one is recorded first). Called by the decoders.
     */
    public void record(Object node, long bit) {
        Span s = span(node);
        if (s.start < 0) {
            s.start = bit;
        }
    }

    /**
     * Records that the encoding of {@code node} ends just before absolute bit
     * {@code bit}; the last record wins, so where a value is read inside an
     * EXPLICIT tag the outer TLV's end is kept, matching {@link #record}.
     * Called by the decoders.
     */
    public void recordEnd(Object node, long bit) {
        span(node).end = bit;
    }

    /**
     * Records that {@code owner}, a generated class holding a builtin value,
     * is the same node as {@code value}. Called by the decoders.
     */
    public void recordOwner(Object owner, Object value) {
        if (owner != value) {
            owners.put(owner, value);
        }
    }

    /**
     * Records that the contents octets of {@code node} span absolute bits
     * {@code bit} up to {@code endBit} (exclusive). Called by the decoders.
     */
    public void recordContents(Object node, long bit, long endBit) {
        Span s = span(node);
        s.contents = bit;
        s.contentsEnd = endBit;
    }

    /**
     * Records that the decoded value of {@code node} is held by absolute bits
     * {@code bit} up to {@code endBit} (exclusive). Called by the decoders.
     */
    public void recordValue(Object node, long bit, long endBit) {
        Span s = span(node);
        s.value = bit;
        s.valueEnd = endBit;
    }

    /**
     * Records that the inner value {@code node} of a contained field is
     * decoded from octets starting at absolute bit {@code bit}. Called by the
     * contained-value decoders.
     */
    public void recordPlacement(Object node, long bit) {
        span(node).placement = bit;
    }

    /** Absolute bit where inner value {@code node} is decoded from, or -1. Used by the decoders. */
    public long placementBit(Object node) {
        Span s = find(node);
        return s == null ? -1 : s.placement;
    }

    /** Absolute bit where the contents of {@code node} start, or -1. Used by the decoders. */
    public long contentsBit(Object node) {
        Span s = find(node);
        return s == null ? -1 : s.contents;
    }

    /** Absolute bit just after the contents of {@code node}, or -1. Used by the decoders. */
    public long contentsEndBit(Object node) {
        Span s = find(node);
        return s == null ? -1 : s.contentsEnd;
    }

    private long shifted(long bit) {
        return bit < 0 ? -1 : bit + base;
    }

    private static long length(long from, long to) {
        return from < 0 || to < 0 ? -1 : to - from;
    }

    /** Bit offset of {@code node}, plus this view's base; -1 when the decode did not produce it. */
    public long bitOffset(Object node) {
        Span s = find(node);
        return s == null ? -1 : shifted(s.start);
    }

    /** {@link #bitOffset} in whole octets (rounded down); -1 when absent. */
    public long byteOffset(Object node) {
        long b = bitOffset(node);
        return b < 0 ? -1 : b >>> 3;
    }

    /** Bit just after the encoding of {@code node}, plus this view's base; -1 when not recorded. */
    public long endBitOffset(Object node) {
        Span s = find(node);
        return s == null ? -1 : shifted(s.end);
    }

    /** {@link #endBitOffset} in whole octets (rounded up, so a PER value's last partial octet counts); -1 when absent. */
    public long endByteOffset(Object node) {
        long b = endBitOffset(node);
        return b < 0 ? -1 : (b + 7) >>> 3;
    }

    /** Length in bits of the encoding of {@code node}; -1 when not recorded. A PER value can take 0 bits. */
    public long sizeBits(Object node) {
        Span s = find(node);
        return s == null ? -1 : length(s.start, s.end);
    }

    /** Bit offset where the contents octets of {@code node} start, plus this view's base; -1 when not recorded. */
    public long contentsBitOffset(Object node) {
        Span s = find(node);
        return s == null ? -1 : shifted(s.contents);
    }

    /** Bit just after the contents octets of {@code node}, plus this view's base; -1 when not recorded. */
    public long contentsEndBitOffset(Object node) {
        Span s = find(node);
        return s == null ? -1 : shifted(s.contentsEnd);
    }

    /** Length in bits of the contents octets of {@code node}; -1 when not recorded. */
    public long contentsSizeBits(Object node) {
        Span s = find(node);
        return s == null ? -1 : length(s.contents, s.contentsEnd);
    }

    /** The span holding the decoded value of {@code node}, following a CHOICE to its alternative. */
    private Span valueSpan(Object node) {
        Span s = find(node);
        if (s != null && s.value >= 0) {
            return s;
        }
        if (node instanceof Asn1Choice c && c.activeIndex() >= 0) {
            Object alt = nodeOf(c.getActive());
            return alt == null ? null : valueSpan(alt);
        }
        return null;
    }

    /** Bit offset where the decoded value of {@code node} starts, plus this view's base; -1 when not recorded. */
    public long valueBitOffset(Object node) {
        Span s = valueSpan(node);
        return s == null ? -1 : shifted(s.value);
    }

    /** Bit just after the decoded value of {@code node}, plus this view's base; -1 when not recorded. */
    public long valueEndBitOffset(Object node) {
        Span s = valueSpan(node);
        return s == null ? -1 : shifted(s.valueEnd);
    }

    /** Length in bits of the decoded value of {@code node}; -1 when not recorded. */
    public long valueSizeBits(Object node) {
        Span s = valueSpan(node);
        return s == null ? -1 : length(s.value, s.valueEnd);
    }

    /** Whether the decode recorded {@code node}. */
    public boolean contains(Object node) {
        Span s = find(node);
        return s != null && s.start >= 0;
    }

    /** Number of recorded nodes. */
    public int size() {
        return nodes().size();
    }

    /** The recorded nodes, by identity; a builtin alias node by its builtin value. */
    public Set<Object> nodes() {
        Set<Object> out = Collections.newSetFromMap(new IdentityHashMap<>());
        for (Map.Entry<Object, Span> e : spans.entrySet()) {
            if (e.getValue().start >= 0) {
                out.add(e.getKey());
            }
        }
        return Collections.unmodifiableSet(out);
    }

    /**
     * The value object behind a member reference, the key its position is
     * recorded under; null for an absent or unsupported member.
     */
    public static Object nodeOf(MemberRef m) {
        return switch (m) {
            case MemberRef.Primitive(var v, var owner) -> v;
            case MemberRef.Composite(var v) -> v;
            case MemberRef.Choice(var v) -> v;
            case MemberRef.SeqOf(var v) -> v;
            case MemberRef.Enumerated(var v, var spec) -> v;
            case MemberRef.Contained(var v, var spec) -> v;
            case MemberRef.Absent a -> null;
            case MemberRef.Unsupported u -> null;
        };
    }

    /**
     * The generated object behind a member reference: for a builtin held by
     * an alias class that class's object, otherwise {@link #nodeOf}.
     */
    public static Object ownerOf(MemberRef m) {
        return m instanceof MemberRef.Primitive(var v, var owner) ? owner : nodeOf(m);
    }

    /** The same positions with {@code baseBits} added to every offset. */
    public Positions withBase(long baseBits) {
        return new Positions(spans, owners, base + baseBits);
    }

    /** This view's base: what {@link #bitOffset} adds to the recorded offsets. */
    public long base() {
        return base;
    }
}
