package io.github.schramp.gambasasn1.wire.ber;

/**
 * One complete top-level BER record, as {@link BerFrames} returns it.
 *
 * @param offset absolute offset of the record's first octet in the input
 * @param bytes  the tag, length and contents octets (plus the end-of-contents
 *               octets of an indefinite-length record); the array is the
 *               caller's
 */
public record Frame(long offset, byte[] bytes) {
}
