package io.github.schramp.gambasasn1.wire.spec;

import io.github.schramp.gambasasn1.wire.ber.Tag;
import java.util.function.Supplier;

/**
 * A SET OF value (X.680 §27): a {@link SeqOf} under the universal SET tag.
 * The elements keep the order they were added or decoded in; the BER
 * walker writes them in DER order (X.690 §11.6).
 *
 * @param <T> the element type
 */
public class SetOf<T extends AsMemberRef> extends SeqOf<T> {
    private static final Tag SET_TAG = Tag.universal(17, true);

    /** An empty collection whose new elements {@code factory} makes. */
    public SetOf(Supplier<? extends T> factory) {
        super(factory);
    }

    @Override
    public Tag naturalTag() {
        return SET_TAG;
    }

    @Override
    public String ownXerName() {
        return "SET_OF";
    }
}
