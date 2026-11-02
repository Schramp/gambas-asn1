package io.github.schramp.gambasasn1.wire.spec;

/**
 * Outcome of a contained-value decoder.
 *
 * @param status  the new state of the field
 * @param message reason of {@code SKIPPED}/{@code FAILED}; for {@code DECODED} a warning, or empty
 */
public record ContainedResult(ContainedStatus status, String message) {
    public static ContainedResult ok() {
        return new ContainedResult(ContainedStatus.DECODED, "");
    }

    public static ContainedResult skipped(String why) {
        return new ContainedResult(ContainedStatus.SKIPPED, why);
    }

    public static ContainedResult failed(String why) {
        return new ContainedResult(ContainedStatus.FAILED, why);
    }
}
