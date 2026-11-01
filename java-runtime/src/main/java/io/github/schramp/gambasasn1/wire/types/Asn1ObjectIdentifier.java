package io.github.schramp.gambasasn1.wire.types;

/**
 * OBJECT IDENTIFIER (X.680 §32): the arc list, first two arcs already split
 * from their combined first subidentifier (X.690 §8.19.4).
 */
public final class Asn1ObjectIdentifier extends Asn1Arcs {
    public Asn1ObjectIdentifier() {
    }

    public Asn1ObjectIdentifier(long... arcs) {
        set(arcs);
    }

    @Override
    public String xerElementName() {
        return "OBJECT_IDENTIFIER";
    }
}
