package io.github.schramp.gambasasn1.wire.query;

import io.github.schramp.gambasasn1.wire.spec.Positions;
import java.util.ArrayList;
import java.util.List;

/** The values one run of an {@link ExtractPlan} found, per target, in tree order. */
public final class Extraction {
    /** One value found, with the bit offset where it starts in the input, or -1 when unknown. */
    public record Hit<T>(T value, long bitOffset) {
        /** The byte offset where the value starts, or -1 when unknown. */
        public long byteOffset() {
            return bitOffset < 0 ? -1 : bitOffset / 8;
        }
    }

    private final List<Class<?>> targets;
    private final Positions positions;
    private final List<List<Hit<?>>> hits = new ArrayList<>();
    int visited;

    Extraction(List<Class<?>> targets, Positions positions) {
        this.targets = targets;
        this.positions = positions;
        for (int i = 0; i < targets.size(); i++) {
            hits.add(new ArrayList<>());
        }
    }

    void add(int target, Object value) {
        hits.get(target).add(new Hit<>(value, positions == null ? -1 : positions.bitOffset(value)));
    }

    /** The values of {@code target}, one of the plan's targets, in the order a depth-first walk meets them. */
    @SuppressWarnings("unchecked")
    public <T> List<Hit<T>> get(Class<T> target) {
        int i = targets.indexOf(target);
        if (i < 0) {
            throw new IllegalArgumentException(target.getName() + " is not a target of this plan");
        }
        List<?> l = hits.get(i);
        return (List<Hit<T>>) l;
    }

    /** {@link #get} without the offsets. */
    public <T> List<T> values(Class<T> target) {
        return get(target).stream().map(Hit::value).toList();
    }

    /** How many values the run looked at; the values the plan cut away are not counted. */
    public int visited() {
        return visited;
    }
}
