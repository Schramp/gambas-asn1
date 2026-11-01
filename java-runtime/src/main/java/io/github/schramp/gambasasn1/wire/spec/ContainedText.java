package io.github.schramp.gambasasn1.wire.spec;

/**
 * XER/JER form of a contained value: hex only, the inner value in place of
 * the hex (X.680 §22.4, X.697 §25.4), or the inner value plus the raw hex
 * (an extension, not standard-conformant).
 */
public enum ContainedText {
    HEX, INLINE, INLINE_RAW
}
