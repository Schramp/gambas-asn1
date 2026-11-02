package io.github.schramp.gambasasn1.wire.ber;

/** Tag class, in identifier-octet order (X.690 §8.1.2.2). */
public enum TagClass {
    UNIVERSAL, APPLICATION, CONTEXT, PRIVATE;

    /** The two class bits of the identifier octet. */
    public int bits() {
        return ordinal();
    }

    public static TagClass fromBits(int bits) {
        return values()[bits & 0x03];
    }
}
