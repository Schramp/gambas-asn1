package io.github.schramp.gambasasn1.wire.containing;

import io.github.schramp.gambasasn1.wire.spec.ContainedText;

/**
 * Contained-value settings for one decode or encode. A decode's
 * {@code BerReader} carries them, and every reader it opens over nested
 * contents too.
 *
 * @param decoders the registry; null means {@link ContainedDecoders#defaults()}
 * @param off      decode no contained value at all
 * @param xer      XER form of every contained field, in place of each row's; null keeps the rows'
 * @param jer      JER form of every contained field, in place of each row's; null keeps the rows'
 */
public record ContainedOptions(ContainedDecoders decoders, boolean off, ContainedText xer, ContainedText jer) {
    /** Settings that keep every row's XER and JER form. */
    public ContainedOptions(ContainedDecoders decoders, boolean off) {
        this(decoders, off, null, null);
    }

    /** The XER form of a field whose row says {@code row}. */
    public ContainedText xerForm(ContainedText row) {
        return xer != null ? xer : row;
    }

    /** The registry in use. */
    public ContainedDecoders registry() {
        return decoders != null ? decoders : ContainedDecoders.defaults();
    }

    /** The registry of {@code o}, which may be null. */
    static ContainedDecoders registry(ContainedOptions o) {
        return o != null ? o.registry() : ContainedDecoders.defaults();
    }
}
