package io.github.schramp.gambasasn1.wire.spec;

import io.github.schramp.gambasasn1.wire.ber.Tag;

/** A SEQUENCE OF or SET OF value (X.680 §26, §28). */
public interface Asn1SeqOf {

    /** Universal SEQUENCE (16) or SET (17), constructed. */
    Tag naturalTag();

    /** The collection's own XER element name. */
    String ownXerName();

    int size();

    MemberRef get(int index);

    /** Appends a default element and returns it. */
    MemberRef addDefault();

    /** Element {@code index}'s own XER element name (see {@link AsMemberRef#ownElementXerName}). */
    String elemNaturalXerName(int index);

    /** The element type's X.693 §21 override. */
    XerInstruction elemXerInstruction();

    /** The element type's own BER framing (see {@link AsMemberRef#berFraming}). */
    default BerTagging elemBerFraming() {
        return BerTagging.DELEGATE;
    }

    /** The X.693 §12 element identifier a named type declares, or null. */
    default String elemXerName() {
        return null;
    }
}
