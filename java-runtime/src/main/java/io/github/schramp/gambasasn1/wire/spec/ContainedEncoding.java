package io.github.schramp.gambasasn1.wire.spec;

/**
 * Encoding rules of a contained value's bytes (X.682 §11.4, §11.6).
 * {@code OUTER} means the rules the enclosing OCTET STRING is encoded with.
 */
public enum ContainedEncoding {
    OUTER, BER, CER, DER, PER_ALIGNED, PER_UNALIGNED
}
