package io.github.schramp.gambasasn1.wire.io;

/**
 * Base of every failure the runtime's encoders and decoders report:
 * {@link DecodeException} for input that is not a valid encoding,
 * {@link EncodeException} for a value that has no encoding. Catch this one
 * type to handle both, for example to skip one bad record and go on with
 * the next.
 *
 * <p>Unchecked, like every exception of this runtime: the {@code encode} and
 * {@code decode} methods document it with {@code @throws}, and the compiler
 * does not ask callers to catch or declare it.
 */
public abstract class Asn1Exception extends RuntimeException {
    private static final long serialVersionUID = 1L;

    /** @param message the full message, as {@link #getMessage()} returns it */
    protected Asn1Exception(String message) {
        super(message);
    }
}
