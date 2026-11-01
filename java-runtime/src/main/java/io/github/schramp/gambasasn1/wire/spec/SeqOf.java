package io.github.schramp.gambasasn1.wire.spec;

import io.github.schramp.gambasasn1.wire.ber.Tag;
import java.util.ArrayList;
import java.util.List;
import java.util.function.Supplier;

/**
 * A SEQUENCE OF value (X.680 §25): the elements in order. Used directly as
 * the type of an inline SEQUENCE OF member, and as the base class of a
 * named SEQUENCE OF type. It carries no codec code; the walkers reach it
 * through {@link Asn1SeqOf}.
 *
 * @param <T> the element type
 */
public class SeqOf<T extends AsMemberRef> implements Asn1SeqOf, AsMemberRef {
    private static final Tag SEQUENCE_TAG = Tag.universal(16, true);

    private final Supplier<? extends T> factory;
    private final List<T> items = new ArrayList<>();
    private T sample;

    /** An empty collection whose new elements {@code factory} makes. */
    public SeqOf(Supplier<? extends T> factory) {
        this.factory = factory;
    }

    /** The elements, in order; the list can be changed in place. */
    public List<T> items() {
        return items;
    }

    /** Appends {@code v}. */
    public void add(T v) {
        items.add(java.util.Objects.requireNonNull(v));
    }

    /** A default element, made once, that answers the element type's static facts. */
    private T sample() {
        if (sample == null) {
            sample = factory.get();
        }
        return sample;
    }

    @Override
    public Tag naturalTag() {
        return SEQUENCE_TAG;
    }

    @Override
    public String ownXerName() {
        return "SEQUENCE_OF";
    }

    @Override
    public int size() {
        return items.size();
    }

    @Override
    public MemberRef get(int index) {
        return items.get(index).asMemberRef();
    }

    @Override
    public MemberRef addDefault() {
        T v = factory.get();
        items.add(v);
        return v.asMemberRef();
    }

    @Override
    public void clear() {
        items.clear();
    }

    @Override
    public String elemNaturalXerName(int index) {
        return items.get(index).ownElementXerName();
    }

    @Override
    public XerInstruction elemXerInstruction() {
        return sample().xerInstruction();
    }

    @Override
    public BerTagging elemBerFraming() {
        return sample().berFraming();
    }

    @Override
    public MemberRef asMemberRef() {
        return new MemberRef.SeqOf(this);
    }

    @Override
    public String ownElementXerName() {
        return ownXerName();
    }

    /** Equal when both hold equal elements in the same order, seen through their MemberRef. */
    @Override
    public boolean equals(Object o) {
        if (o == null || o.getClass() != getClass()) {
            return false;
        }
        SeqOf<?> other = (SeqOf<?>) o;
        if (other.size() != size()) {
            return false;
        }
        for (int i = 0; i < size(); i++) {
            if (!get(i).equals(other.get(i))) {
                return false;
            }
        }
        return true;
    }

    @Override
    public int hashCode() {
        int h = 1;
        for (int i = 0; i < size(); i++) {
            h = 31 * h + get(i).hashCode();
        }
        return h;
    }
}
