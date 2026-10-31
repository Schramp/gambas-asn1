package io.github.schramp.gambasasn1.wire.containing;

/**
 * Contained-value settings for one decode or encode. A decode's
 * {@code BerReader} carries them, and every reader it opens over nested
 * contents too.
 *
 * @param decoders the registry; null means {@link ContainedDecoders#defaults()}
 * @param off      decode no contained value at all
 */
public record ContainedOptions(ContainedDecoders decoders, boolean off) {
    /** The registry in use. */
    public ContainedDecoders registry() {
        return decoders != null ? decoders : ContainedDecoders.defaults();
    }

    /** The registry of {@code o}, which may be null. */
    static ContainedDecoders registry(ContainedOptions o) {
        return o != null ? o.registry() : ContainedDecoders.defaults();
    }
}
