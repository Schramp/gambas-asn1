package io.github.schramp.gambasasn1.wire.types;

/**
 * INTEGER (X.680 §19) whose range needs unsigned 64-bit storage, for
 * example {@code INTEGER (0..MAX)}. The value is held in a {@code long}
 * read as unsigned: {@link #get()} returns its bits, {@link #toString()}
 * prints it unsigned.
 */
public final class Asn1UInteger implements Asn1Primitive {
    private long value;

    public Asn1UInteger() {
    }

    /** @param value the value's bits, read as unsigned */
    public Asn1UInteger(long value) {
        this.value = value;
    }

    /** The value's bits, read as unsigned (see {@link Long#toUnsignedString}). */
    public long get() {
        return value;
    }

    /** @param value the value's bits, read as unsigned */
    public void set(long value) {
        this.value = value;
    }

    @Override
    public String xerElementName() {
        return "INTEGER";
    }

    @Override
    public boolean equals(Object o) {
        return o instanceof Asn1UInteger i && i.value == value;
    }

    @Override
    public int hashCode() {
        return Long.hashCode(value);
    }

    @Override
    public String toString() {
        return Long.toUnsignedString(value);
    }
}
