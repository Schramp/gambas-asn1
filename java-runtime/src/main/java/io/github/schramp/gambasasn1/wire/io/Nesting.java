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

    private Nesting() {
    }

    /** Message of a decode that exceeded {@link #MAX_DECODE_DEPTH}. */
    public static String tooDeep() {
        return "nesting deeper than " + MAX_DECODE_DEPTH + " levels";
    }
}
