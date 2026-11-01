package io.github.schramp.gambasasn1.wire.types;

/** BOOLEAN (X.680 §18): a mutable holder, so a decoder writes into it in place. */
public final class Asn1Boolean implements Asn1Primitive {
    private boolean value;

    public Asn1Boolean() {
    }

    public Asn1Boolean(boolean value) {
        this.value = value;
    }

    public boolean get() {
        return value;
    }

    public void set(boolean value) {
        this.value = value;
    }

    @Override
    public String xerElementName() {
        return "BOOLEAN";
    }

    @Override
    public boolean equals(Object o) {
        return o instanceof Asn1Boolean b && b.value == value;
    }

    @Override
    public int hashCode() {
        return Boolean.hashCode(value);
    }

    @Override
    public String toString() {
        return Boolean.toString(value);
    }
}
