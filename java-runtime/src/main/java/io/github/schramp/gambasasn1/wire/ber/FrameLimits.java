package io.github.schramp.gambasasn1.wire.ber;

/**
 * Limits {@link BerFrames} applies to each record.
 *
 * @param maxFrame the largest frame (header, contents and end-of-contents
 *                 octets) accepted, in octets; a longer record is refused
 *                 before it is read
 */
public record FrameLimits(int maxFrame) {
    /** 64 MiB per record. */
    public static final FrameLimits DEFAULT = new FrameLimits(64 << 20);

    public FrameLimits {
        if (maxFrame <= 0) {
            throw new IllegalArgumentException("maxFrame must be positive: " + maxFrame);
        }
    }
}
