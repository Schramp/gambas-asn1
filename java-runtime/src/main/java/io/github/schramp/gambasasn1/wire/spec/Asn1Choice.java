package io.github.schramp.gambasasn1.wire.spec;

import io.github.schramp.gambasasn1.wire.ber.Tag;

/** A CHOICE value: one selected alternative, or an unknown extension kept as raw bytes. */
public interface Asn1Choice {

    /** An extension alternative this version of the schema does not know (X.680 §29.7). */
    record UnknownExtension(Tag tag, byte[] bytes) {
    }

    ChoiceSpec spec();

    /** Index of the selected alternative, or -1 when none is selected. */
    int activeIndex();

    /** The selected alternative's value. */
    MemberRef getActive();

    /** Selects alternative {@code index} with a default value and returns it. */
    MemberRef select(int index);

    /** Keeps an unknown extension alternative as raw bytes. */
    void setUnknownExtension(UnknownExtension ext);

    /** The unknown extension alternative this value holds, or null. */
    UnknownExtension unknownExtension();
}
