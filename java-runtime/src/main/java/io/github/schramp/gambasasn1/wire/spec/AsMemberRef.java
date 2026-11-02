package io.github.schramp.gambasasn1.wire.spec;

/** Any value a codec can reach: a generated type, a builtin or a collection. */
public interface AsMemberRef {

    /** This value by reflective shape. A builtin alias unwraps to its builtin. */
    MemberRef asMemberRef();

    /**
     * This value's own X.693 §12 XER element name, from before
     * {@link #asMemberRef} unwraps it: a named alias answers its declared name.
     */
    String ownElementXerName();

    /** This type's X.693 §21 ENCODING-CONTROL override. */
    default XerInstruction xerInstruction() {
        return XerInstruction.DEFAULT;
    }

    /**
     * This type's own BER framing (X.680 §31.2): IMPLICIT or EXPLICIT for a
     * builtin or ENUMERATED type assignment with its own non-universal tag,
     * {@link BerTagging#DELEGATE} otherwise.
     */
    default BerTagging berFraming() {
        return BerTagging.DELEGATE;
    }
}
