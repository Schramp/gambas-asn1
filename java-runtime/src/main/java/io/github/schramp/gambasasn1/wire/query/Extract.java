package io.github.schramp.gambasasn1.wire.query;

import io.github.schramp.gambasasn1.wire.spec.AsMemberRef;
import io.github.schramp.gambasasn1.wire.spec.Decoded;
import java.util.List;

/** One-target shorthands over {@link ExtractPlan}, which they compile once per root and target class. */
public final class Extract {
    private Extract() {
    }

    /**
     * Every value of {@code target} below {@code root} (and {@code root}
     * itself when it is one), in depth-first order, without offsets.
     * {@code root} is a value of a generated type.
     */
    public static <T> List<T> all(AsMemberRef root, Class<T> target) {
        return plan(root, target).run(root).values(target);
    }

    /** {@link #all(AsMemberRef, Class)} with each value's offset from {@code decoded}. */
    public static <T> List<Extraction.Hit<T>> all(AsMemberRef root, Decoded decoded, Class<T> target) {
        return plan(root, target).run(root, decoded.positions()).get(target);
    }

    private static ExtractPlan plan(AsMemberRef root, Class<?> target) {
        return ExtractPlan.of(root.getClass(), List.of(target));
    }
}
