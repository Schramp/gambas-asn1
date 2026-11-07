package io.github.schramp.gambasasn1.wire.io;

/** A value the encoder cannot represent, for example one that violates its constraints. */
public final class EncodeException extends Asn1Exception {
    private static final long serialVersionUID = 1L;

    public EncodeException(String message) {
        super(message);
    }
}
