package io.github.schramp.gambasasn1.wire.spec;

import java.util.Collections;
import java.util.IdentityHashMap;
import java.util.Map;
import java.util.Set;

/**
 * Where each node of a decoded value starts in its encoding, recorded by a
 * BER or PER decode that was asked for positions ({@code
 * BerObject.decodeWithPositions}, {@code PerObject.decodeWithPositions}).
 *
 * <p>A node is any value object the decode filled: a SEQUENCE/SET, CHOICE,
 * SEQUENCE OF/SET OF, ENUMERATED or primitive value, and a contained field
 * plus every node of its decoded inner value. Nodes are keys by identity, so
 * {@code positions.bitOffset(pdu.payload())} finds that very object. The
 * offset is where the node's encoding starts: its first tag octet in BER,
 * its first bit (preamble, length or value) in PER. The end offset is the
 * bit just after the node's encoding (its last contents octet, or the
 * end-of-contents octets of an indefinite length, in BER), so
 * {@link #sizeBits} is the length of the node's whole encoding.
 *
 * <p>A BER primitive value and a contained field also have a contents span:
 * where their contents octets start and end (X.690 §8.1.1), inside an
 * EXPLICIT tag the inner TLV's. For a contained field under PER the span is
 * its octets after their length determinant (X.691 §17.8). The decoded
 * inner value of a contained field starts at the field's contents and ends
 * where its own encoding ends, before any padding the contained-value
 * decoder stripped.
 *
 * <p>Offsets are bits from the start of the decode call. {@link #withBase}
 * gives a view that adds a fixed offset, for instance the record's position
 * in an enclosing buffer. An inner value decoded from a contained field is
 * placed at the field's contents octets; this holds for contained-value
 * decoders that pass the octets through or only strip trailing padding (the
 * built-in {@code plain}, {@code zero_padding} and {@code pkcs7}).
 */
public final class Positions {
    private final Map<Object, Long> bits;
    private final Map<Object, Long> ends;
    private final Map<Object, Long> contents;
    private final Map<Object, Long> contentsEnds;
    private final Map<Object, Long> placements;
    private final long base;

    private Positions(Map<Object, Long> bits, Map<Object, Long> ends, Map<Object, Long> contents,
            Map<Object, Long> contentsEnds, Map<Object, Long> placements, long base) {
        this.bits = bits;
        this.ends = ends;
        this.contents = contents;
        this.contentsEnds = contentsEnds;
        this.placements = placements;
        this.base = base;
    }

    /** An empty recorder for one decode. */
    public static Positions recording() {
        return new Positions(new IdentityHashMap<>(), new IdentityHashMap<>(), new IdentityHashMap<>(),
                new IdentityHashMap<>(), new IdentityHashMap<>(), 0);
    }

    /**
     * Records that {@code node} starts at absolute bit {@code bit}; the first
     * record of a node wins (a CHOICE and its untagged alternative share an
     * offset, the outer one is recorded first). Called by the decoders.
     */
    public void record(Object node, long bit) {
        bits.putIfAbsent(node, bit);
    }

    /**
     * Records that the encoding of {@code node} ends just before absolute bit
     * {@code bit}; the last record wins, so where a value is read inside an
     * EXPLICIT tag the outer TLV's end is kept, matching {@link #record}.
     * Called by the decoders.
     */
    public void recordEnd(Object node, long bit) {
        ends.put(node, bit);
    }

    /**
     * Records that the contents octets of {@code node} span absolute bits
     * {@code bit} up to {@code endBit} (exclusive). Called by the decoders.
     */
    public void recordContents(Object node, long bit, long endBit) {
        contents.put(node, bit);
        contentsEnds.put(node, endBit);
    }

    /**
     * Records that the inner value {@code node} of a contained field is
     * decoded from octets starting at absolute bit {@code bit}. Called by the
     * contained-value decoders.
     */
    public void recordPlacement(Object node, long bit) {
        placements.put(node, bit);
    }

    /** Absolute bit where inner value {@code node} is decoded from, or -1. Used by the decoders. */
    public long placementBit(Object node) {
        Long b = placements.get(node);
        return b == null ? -1 : b;
    }

    /** Absolute bit where the contents of {@code node} start, or -1. Used by the decoders. */
    public long contentsBit(Object node) {
        Long b = contents.get(node);
        return b == null ? -1 : b;
    }

    /** Absolute bit just after the contents of {@code node}, or -1. Used by the decoders. */
    public long contentsEndBit(Object node) {
        Long b = contentsEnds.get(node);
        return b == null ? -1 : b;
    }

    /** Bit offset of {@code node}, plus this view's base; -1 when the decode did not produce it. */
    public long bitOffset(Object node) {
        Long b = bits.get(node);
        return b == null ? -1 : b + base;
    }

    /** {@link #bitOffset} in whole octets (rounded down); -1 when absent. */
    public long byteOffset(Object node) {
        long b = bitOffset(node);
        return b < 0 ? -1 : b >>> 3;
    }

    /** Bit just after the encoding of {@code node}, plus this view's base; -1 when not recorded. */
    public long endBitOffset(Object node) {
        Long b = ends.get(node);
        return b == null ? -1 : b + base;
    }

    /** {@link #endBitOffset} in whole octets (rounded up, so a PER value's last partial octet counts); -1 when absent. */
    public long endByteOffset(Object node) {
        long b = endBitOffset(node);
        return b < 0 ? -1 : (b + 7) >>> 3;
    }

    /** Length in bits of the encoding of {@code node}; -1 when not recorded. A PER value can take 0 bits. */
    public long sizeBits(Object node) {
        Long s = bits.get(node);
        Long e = ends.get(node);
        return s == null || e == null ? -1 : e - s;
    }

    /** Bit offset where the contents octets of {@code node} start, plus this view's base; -1 when not recorded. */
    public long contentsBitOffset(Object node) {
        Long b = contents.get(node);
        return b == null ? -1 : b + base;
    }

    /** Bit just after the contents octets of {@code node}, plus this view's base; -1 when not recorded. */
    public long contentsEndBitOffset(Object node) {
        Long b = contentsEnds.get(node);
        return b == null ? -1 : b + base;
    }

    /** Length in bits of the contents octets of {@code node}; -1 when not recorded. */
    public long contentsSizeBits(Object node) {
        Long s = contents.get(node);
        Long e = contentsEnds.get(node);
        return s == null || e == null ? -1 : e - s;
    }

    /** Whether the decode recorded {@code node}. */
    public boolean contains(Object node) {
        return bits.containsKey(node);
    }

    /** Number of recorded nodes. */
    public int size() {
        return bits.size();
    }

    /** The recorded nodes, by identity. */
    public Set<Object> nodes() {
        return Collections.unmodifiableSet(bits.keySet());
    }

    /**
     * The value object behind a member reference, the key its position is
     * recorded under; null for an absent or unsupported member.
     */
    public static Object nodeOf(MemberRef m) {
        return switch (m) {
            case MemberRef.Primitive(var v) -> v;
            case MemberRef.Composite(var v) -> v;
            case MemberRef.Choice(var v) -> v;
            case MemberRef.SeqOf(var v) -> v;
            case MemberRef.Enumerated(var v, var spec) -> v;
            case MemberRef.Contained(var v, var spec) -> v;
            case MemberRef.Absent a -> null;
            case MemberRef.Unsupported u -> null;
        };
    }

    /** The same positions with {@code baseBits} added to every offset. */
    public Positions withBase(long baseBits) {
        return new Positions(bits, ends, contents, contentsEnds, placements, base + baseBits);
    }

    /** This view's base: what {@link #bitOffset} adds to the recorded offsets. */
    public long base() {
        return base;
    }
}
