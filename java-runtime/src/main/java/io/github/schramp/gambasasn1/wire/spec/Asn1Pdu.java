package io.github.schramp.gambasasn1.wire.spec;

/**
 * A generated type usable as a whole-document root: SEQUENCE/SET, CHOICE,
 * or a named SEQUENCE OF/SET OF. Every codec's top-level encode and decode
 * accepts it; the marker itself carries no codec code.
 */
public interface Asn1Pdu extends AsMemberRef {

    /** A named SEQUENCE OF/SET OF type's own SIZE constraint (X.691 §19, §20). */
    default Constraints pduConstraints() {
        return Constraints.UNCONSTRAINED;
    }
}
