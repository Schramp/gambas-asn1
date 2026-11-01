package io.github.schramp.gambasasn1.wire.io;

/**
 * A malformed or unsupported input, reported with the byte offset where
 * decoding stopped. Decoders throw it instead of failing in any other way,
 * whatever the input.
 */
public final class DecodeException extends RuntimeException {
    private static final long serialVersionUID = 1L;

    private final int position;

    public DecodeException(String message, int position) {
        super(message + " at byte " + position);
        this.position = position;
    }

    /** Byte offset in the input where decoding stopped. */
    public int position() {
        return position;
    }
}
