package io.github.schramp.gambasasn1.wire.spec;

/** Storage of one ENUMERATED value. */
public interface EnumSlot {
    long enumGet();

    /** Stores {@code value}; false when it is not one of the type's items. */
    boolean enumSet(long value);
}
