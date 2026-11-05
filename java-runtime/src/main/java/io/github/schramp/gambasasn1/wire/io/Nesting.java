package io.github.schramp.gambasasn1.wire.io;

/**
 * Decode nesting limit, shared by every codec's walker. Each codec's reader
 * carries its depth; every SEQUENCE/SET, CHOICE and SEQUENCE OF/SET OF level
 * a decoder descends into enters one level, and past
 * {@link #MAX_DECODE_DEPTH} levels the decode fails instead of recursing
 * further, so a forged deeply nested value of a recursive type (X.680 §3.6.55)
 * cannot exhaust the stack. A reader opened over a nested value's bytes
 * starts at its parent's depth. The C++ and Rust runtimes apply the same
 * limit.
 */
public final class Nesting {
    /** Constructed nesting levels a decode may descend. */
    public static final int MAX_DECODE_DEPTH = 256;

    /**
     * Item count above which a PER SEQUENCE OF/SET OF may not hold an
     * element encoded in zero bits (NULL, X.691 §18; an INTEGER or
     * ENUMERATED with a single value, §11.1.3). Such elements cost no input,
     * so a few octets of length determinant (X.691 §11.9.3.8) would
     * otherwise allocate millions of them. asn1c applies the same rule with
     * 200 ({@code constr_SET_OF_uper.c}). Change it here and rebuild the
     * runtime. The C++ and Rust runtimes use the same limit.
     */
    public static final int MAX_ZERO_WIDTH_ITEMS = 200;

    private Nesting() {
    }

    /** Message of a decode that exceeded {@link #MAX_DECODE_DEPTH}. */
    public static String tooDeep() {
        return "nesting deeper than " + MAX_DECODE_DEPTH + " levels";
    }
}
