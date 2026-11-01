package io.github.schramp.gambasasn1.wire.spec;

/** State of a contained value after the outer decode. */
public enum ContainedStatus {
    /** No inner decode attempted: a new value, or raw bytes set directly. */
    NOT_DECODED,
    /** The inner value is available. */
    DECODED,
    /** Not decoded on purpose: decoding off, a {@code when} mismatch, or decoder {@code none}. */
    SKIPPED,
    /** The inner decode failed; the raw bytes are kept. */
    FAILED
}
