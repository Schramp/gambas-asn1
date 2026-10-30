package io.github.schramp.gambasasn1.wire.types;

/** NULL (X.680 §24): a value with no content. */
public final class Asn1Null implements Asn1Primitive {

    @Override
    public String xerElementName() {
        return "NULL";
    }

    @Override
    public boolean equals(Object o) {
        return o instanceof Asn1Null;
    }

    @Override
    public int hashCode() {
        return 0;
    }

    @Override
    public String toString() {
        return "NULL";
    }
}
