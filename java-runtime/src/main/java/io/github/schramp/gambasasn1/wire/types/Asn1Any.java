package io.github.schramp.gambasasn1.wire.types;

import java.util.Arrays;
import java.util.HexFormat;
import java.util.Objects;

/**
 * ANY, the X.208 open type: the complete encoding of whatever value was on
 * the wire, held verbatim. It has no tag of its own; BER decode captures
 * the encoding and encode replays it unchanged.
 */
public final class Asn1Any implements Asn1Primitive {
    private static final byte[] EMPTY = new byte[0];
    private byte[] encoding = EMPTY;

    public Asn1Any() {
    }

    public Asn1Any(byte[] encoding) {
        set(encoding);
    }

    /** The captured encoding itself, not a copy. */
    public byte[] get() {
        return encoding;
    }

    /** Takes {@code encoding} as is, without copying it. */
    public void set(byte[] encoding) {
        this.encoding = Objects.requireNonNull(encoding);
    }

    @Override
    public String xerElementName() {
        return "ANY";
    }

    @Override
    public boolean equals(Object o) {
        return o instanceof Asn1Any a && Arrays.equals(a.encoding, encoding);
    }

    @Override
    public int hashCode() {
        return Arrays.hashCode(encoding);
    }

    @Override
    public String toString() {
        return HexFormat.of().formatHex(encoding);
    }
}
