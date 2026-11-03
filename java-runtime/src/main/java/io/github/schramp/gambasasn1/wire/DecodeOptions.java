package io.github.schramp.gambasasn1.wire;

import io.github.schramp.gambasasn1.wire.containing.ContainedOptions;

/**
 * Settings of a decoder, made once and passed to any number of decodes:
 * the decode's reader carries them, and every reader it opens over nested
 * or contained contents too.
 *
 * @param contained        contained-value settings; null for the defaults
 * @param checkConstraints reject a value that breaks its type's constraints
 *                         (X.680 §51); off, a decode takes any value the
 *                         encoding can carry
 * @param richErrors       a {@code DecodeException} names the path of the
 *                         value being decoded and shows the input octets
 *                         where decoding stopped
 */
public record DecodeOptions(ContainedOptions contained, boolean checkConstraints, boolean richErrors) {
    /** No constraint checks, plain errors, default contained-value settings. */
    public static final DecodeOptions DEFAULT = new DecodeOptions(null, false, false);

    /** These settings with contained-value settings {@code c}. */
    public DecodeOptions withContained(ContainedOptions c) {
        return new DecodeOptions(c, checkConstraints, richErrors);
    }

    /** These settings with constraint checks on or off. */
    public DecodeOptions withConstraintChecks(boolean on) {
        return new DecodeOptions(contained, on, richErrors);
    }

    /** These settings with rich errors on or off. */
    public DecodeOptions withRichErrors(boolean on) {
        return new DecodeOptions(contained, checkConstraints, on);
    }

    /** {@code o}, or {@link #DEFAULT} when it is null. */
    public static DecodeOptions orDefault(DecodeOptions o) {
        return o != null ? o : DEFAULT;
    }
}
