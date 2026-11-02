package io.github.schramp.gambasasn1.wire.types;

/** RELATIVE-OID (X.680 §33): the arcs below some known base, one per subidentifier (X.690 §8.20). */
public final class Asn1RelativeOid extends Asn1Arcs {
    public Asn1RelativeOid() {
    }

    public Asn1RelativeOid(long... arcs) {
        set(arcs);
    }

    @Override
    public String xerElementName() {
        return "RELATIVE_OID";
    }
}
