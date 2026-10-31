package io.github.schramp.gambasasn1.wire.spec;

/**
 * Type-erased view of a {@link Containing} field for the codec walkers: an
 * OCTET STRING whose bytes are the encoding of another type (X.682 §11).
 */
public interface Asn1Contained {
    /** The raw bytes, not a copy. */
    byte[] rawOctets();

    ContainedStatus status();

    /** The inner value, or null when none is decoded or set. */
    AsMemberRef value();

    /** True after the inner value was set or edited: encode derives the bytes from it. */
    boolean dirty();

    /** Encoding rules the raw bytes are known to be in; {@code OUTER} when unknown. */
    ContainedEncoding rawEncoding();

    /** Raw bytes from the wire, decoded under {@code encoding}; drops the inner value. */
    void setRawFromWire(byte[] raw, ContainedEncoding encoding);

    /** A new default inner value, for a decoder to fill. */
    AsMemberRef newInner();

    /**
     * Stores a decode outcome: {@code inner} is kept when {@code result} is
     * {@code DECODED}. Leaves the value clean.
     */
    void install(ContainedResult result, AsMemberRef inner);
}
