package io.github.schramp.gambasasn1.wire;

import io.github.schramp.gambasasn1.wire.containing.ContainedOptions;
import java.util.function.Consumer;

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
 * @param relaxed          accept input a strict decoder rejects but whose
 *                         meaning is clear (see the codecs' documentation)
 * @param trace            receives one line per member, alternative and
 *                         element decoded; null for no tracing
 */
public record DecodeOptions(ContainedOptions contained, boolean checkConstraints, boolean richErrors,
        boolean relaxed, Consumer<String> trace) {
    /** Strict, unchecked, plain errors, no tracing, default contained-value settings. */
    public static final DecodeOptions DEFAULT = new DecodeOptions(null, false, false, false, null);

    /** These settings with contained-value settings {@code c}. */
    public DecodeOptions withContained(ContainedOptions c) {
        return new DecodeOptions(c, checkConstraints, richErrors, relaxed, trace);
    }

    /** These settings with constraint checks on or off. */
    public DecodeOptions withConstraintChecks(boolean on) {
        return new DecodeOptions(contained, on, richErrors, relaxed, trace);
    }

    /** These settings with rich errors on or off. */
    public DecodeOptions withRichErrors(boolean on) {
        return new DecodeOptions(contained, checkConstraints, on, relaxed, trace);
    }

    /** These settings with relaxed decoding on or off. */
    public DecodeOptions withRelaxed(boolean on) {
        return new DecodeOptions(contained, checkConstraints, richErrors, on, trace);
    }

    /** These settings tracing to {@code sink}, or not tracing when it is null. */
    public DecodeOptions withTrace(Consumer<String> sink) {
        return new DecodeOptions(contained, checkConstraints, richErrors, relaxed, sink);
    }

    /** Whether a walker can take its plain path: no checks, rich errors or tracing. */
    public boolean plain() {
        return !checkConstraints && !richErrors && trace == null;
    }

    /** {@code o}, or {@link #DEFAULT} when it is null. */
    public static DecodeOptions orDefault(DecodeOptions o) {
        return o != null ? o : DEFAULT;
    }
}
