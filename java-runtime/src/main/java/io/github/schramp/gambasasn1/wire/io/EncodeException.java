package io.github.schramp.gambasasn1.wire.io;

/**
 * A value the encoder cannot represent, for example a CHOICE with no
 * alternative selected or one that violates its constraints. Unchecked, like
 * {@link IllegalArgumentException}: the value is the caller's own, so a
 * failure is a programming error rather than an expected condition. Decode
 * failures are {@link DecodeException}, which is checked.
 */
public final class EncodeException extends RuntimeException {
    private static final long serialVersionUID = 1L;

    public EncodeException(String message) {
        super(message);
    }
}
