package io.github.schramp.gambasasn1.wire.spec;

/**
 * Storage of one ENUMERATED value. An extensible ENUMERATED can also hold an
 * item of a newer schema version (X.680 §52.1) as {@link #enumUnknown()};
 * {@link #enumGet()} then returns its number, ordinal or 0. The defaults
 * refuse, for a type that cannot hold one.
 */
public interface EnumSlot {
    long enumGet();

    /** Stores {@code value}; false when it is not one of the type's items. */
    boolean enumSet(long value);

    /** The unknown item held, or null. */
    default EnumUnknown enumUnknown() {
        return null;
    }

    /** Stores an unknown item; false when the type is not extensible. */
    default boolean enumSetUnknown(EnumUnknown u) {
        return false;
    }
}
