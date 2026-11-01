package io.github.schramp.gambasasn1.wire.types;

import java.util.Arrays;
import java.util.HexFormat;
import java.util.Objects;

/** OCTET STRING (X.680 §23): a mutable holder of the octets. */
public final class Asn1OctetString implements Asn1Primitive {
    private static final byte[] EMPTY = new byte[0];
    private byte[] value = EMPTY;

    public Asn1OctetString() {
    }

    public Asn1OctetString(byte[] value) {
        set(value);
    }

    /** The octets themselves, not a copy. */
    public byte[] get() {
        return value;
    }

    /** Takes {@code value} as is, without copying it. */
    public void set(byte[] value) {
        this.value = Objects.requireNonNull(value);
    }

    @Override
    public String xerElementName() {
        return "OCTET_STRING";
    }

    @Override
    public boolean equals(Object o) {
        return o instanceof Asn1OctetString s && Arrays.equals(s.value, value);
    }

    @Override
    public int hashCode() {
        return Arrays.hashCode(value);
    }

    @Override
    public String toString() {
        return HexFormat.of().formatHex(value);
    }
}
