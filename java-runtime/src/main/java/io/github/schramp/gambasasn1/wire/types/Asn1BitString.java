package io.github.schramp.gambasasn1.wire.types;

import java.util.Arrays;
import java.util.HexFormat;
import java.util.Objects;

/**
 * BIT STRING (X.680 §22): the bits packed first-bit-high into octets, and
 * the number of unused bits in the last octet (0 to 7).
 */
public final class Asn1BitString implements Asn1Primitive {
    private static final byte[] EMPTY = new byte[0];
    private byte[] bytes = EMPTY;
    private int unusedBits;

    public Asn1BitString() {
    }

    public Asn1BitString(byte[] bytes, int unusedBits) {
        set(bytes, unusedBits);
    }

    /** The packed bits themselves, not a copy. */
    public byte[] bytes() {
        return bytes;
    }

    public int unusedBits() {
        return unusedBits;
    }

    /** The number of bits: eight per octet, less the unused ones. */
    public int bitCount() {
        return bytes.length * 8 - unusedBits;
    }

    /**
     * Takes {@code bytes} as is, without copying it.
     *
     * @throws IllegalArgumentException when {@code unusedBits} is outside 0..7,
     *         or not 0 for an empty string (X.690 §8.6.2.3)
     */
    public void set(byte[] bytes, int unusedBits) {
        Objects.requireNonNull(bytes);
        if (unusedBits < 0 || unusedBits > 7 || (bytes.length == 0 && unusedBits != 0)) {
            throw new IllegalArgumentException("unused bits " + unusedBits + " with " + bytes.length + " octets");
        }
        this.bytes = bytes;
        this.unusedBits = unusedBits;
    }

    @Override
    public String xerElementName() {
        return "BIT_STRING";
    }

    @Override
    public boolean equals(Object o) {
        return o instanceof Asn1BitString s && s.unusedBits == unusedBits && Arrays.equals(s.bytes, bytes);
    }

    @Override
    public int hashCode() {
        return 31 * Arrays.hashCode(bytes) + unusedBits;
    }

    @Override
    public String toString() {
        return HexFormat.of().formatHex(bytes) + "/" + unusedBits;
    }
}
