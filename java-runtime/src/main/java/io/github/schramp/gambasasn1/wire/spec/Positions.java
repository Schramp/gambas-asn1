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
 * its first bit (preamble, length or value) in PER.
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
    private final Map<Object, Long> contents;
    private final long base;

    private Positions(Map<Object, Long> bits, Map<Object, Long> contents, long base) {
        this.bits = bits;
        this.contents = contents;
        this.base = base;
    }

    /** An empty recorder for one decode. */
    public static Positions recording() {
        return new Positions(new IdentityHashMap<>(), new IdentityHashMap<>(), 0);
    }

    /**
     * Records that {@code node} starts at absolute bit {@code bit}; the first
     * record of a node wins (a CHOICE and its untagged alternative share an
     * offset, the outer one is recorded first). Called by the decoders.
     */
    public void record(Object node, long bit) {
        bits.putIfAbsent(node, bit);
    }

    /** Records where the contents octets of contained field {@code node} start. Called by the decoders. */
    public void recordContents(Object node, long bit) {
        contents.put(node, bit);
    }

    /** Absolute bit where the contents of contained field {@code node} start, or -1. Used by the decoders. */
    public long contentsBit(Object node) {
        Long b = contents.get(node);
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
        return new Positions(bits, contents, base + baseBits);
    }

    /** This view's base: what {@link #bitOffset} adds to the recorded offsets. */
    public long base() {
        return base;
    }
}
