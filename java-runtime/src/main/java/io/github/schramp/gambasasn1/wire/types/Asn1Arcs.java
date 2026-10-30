package io.github.schramp.gambasasn1.wire.types;

import java.util.Arrays;
import java.util.Objects;
import java.util.stream.Collectors;

/**
 * The arc list shared by OBJECT IDENTIFIER and RELATIVE-OID. Arcs are
 * unsigned 32-bit values held in {@code long}s, the range the C++ and Rust
 * runtimes and asn1c accept.
 */
public abstract sealed class Asn1Arcs implements Asn1Primitive permits Asn1ObjectIdentifier, Asn1RelativeOid {
    /** Largest arc value. */
    public static final long MAX_ARC = 0xFFFF_FFFFL;

    private static final long[] EMPTY = new long[0];
    private long[] arcs = EMPTY;

    /** The arcs themselves, not a copy. */
    public long[] get() {
        return arcs;
    }

    /**
     * Takes {@code arcs} as is, without copying it.
     *
     * @throws IllegalArgumentException if an arc is outside {@code 0..MAX_ARC}
     */
    public void set(long... arcs) {
        for (long a : Objects.requireNonNull(arcs)) {
            if (a < 0 || a > MAX_ARC) {
                throw new IllegalArgumentException("arc " + a + " outside 0.." + MAX_ARC);
            }
        }
        this.arcs = arcs;
    }

    @Override
    public boolean equals(Object o) {
        return o != null && o.getClass() == getClass() && Arrays.equals(((Asn1Arcs) o).arcs, arcs);
    }

    @Override
    public int hashCode() {
        return Arrays.hashCode(arcs);
    }

    /** Dotted decimal, for example {@code 2.5.4.3}. */
    @Override
    public String toString() {
        return Arrays.stream(arcs).mapToObj(Long::toString).collect(Collectors.joining("."));
    }
}
