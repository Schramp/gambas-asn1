package io.github.schramp.gambasasn1.wire.types;

/** INTEGER (X.680 §19) in signed 64-bit storage; mutable, so a decoder writes into it in place. */
public final class Asn1Integer implements Asn1Primitive {
    private long value;

    public Asn1Integer() {
    }

    public Asn1Integer(long value) {
        this.value = value;
    }

    public long get() {
        return value;
    }

    public void set(long value) {
        this.value = value;
    }

    @Override
    public String xerElementName() {
        return "INTEGER";
    }

    @Override
    public boolean equals(Object o) {
        return o instanceof Asn1Integer i && i.value == value;
    }

    @Override
    public int hashCode() {
        return Long.hashCode(value);
    }

    @Override
    public String toString() {
        return Long.toString(value);
    }
}
