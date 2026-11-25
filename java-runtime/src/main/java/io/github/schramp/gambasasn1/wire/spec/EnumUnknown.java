package io.github.schramp.gambasasn1.wire.spec;

/**
 * An ENUMERATED item of a newer schema version (X.680 §52.1), as far as its
 * codec carried it. Only an extensible ENUMERATED holds one.
 *
 * @param kind  which part of the item the codec carried
 * @param value the number ({@link Kind#VALUE}), the extension ordinal
 *              ({@link Kind#ORDINAL}), or 0 ({@link Kind#IDENTIFIER})
 */
public record EnumUnknown(Kind kind, long value) {

    /** Which part of an unknown item a codec carries. */
    public enum Kind {
        /** BER: the number on the wire (also a JER or XER bare number). */
        VALUE,
        /** PER: the extension ordinal past the known items (X.691 §14). */
        ORDINAL,
        /** XER/JER: an identifier the type does not define (X.693 §8.6.4); the name is not kept. */
        IDENTIFIER
    }

    /** A number that is no item, read from BER or a JER/XER bare number. */
    public static EnumUnknown ofValue(long v) {
        return new EnumUnknown(Kind.VALUE, v);
    }

    /** An extension ordinal past the known items, read from PER. */
    public static EnumUnknown ofOrdinal(long ordinal) {
        return new EnumUnknown(Kind.ORDINAL, ordinal);
    }

    /** An identifier the type does not define, read from XER or JER. */
    public static EnumUnknown ofIdentifier() {
        return new EnumUnknown(Kind.IDENTIFIER, 0);
    }

    /**
     * The encode error for a codec that cannot write this item, e.g.
     * "ENUMERATED Color: extension item #3 of a newer schema version has no BER encoding".
     *
     * @param spec  the type's table, for its name
     * @param codec the encoding codec's name
     * @return the message
     */
    public String encodeError(EnumSpec spec, String codec) {
        String what = switch (kind) {
            case VALUE -> "value " + value;
            case ORDINAL -> "extension item #" + value;
            case IDENTIFIER -> "an unknown identifier";
        };
        return "ENUMERATED " + spec.name() + ": " + what + " of a newer schema version has no " + codec + " encoding";
    }

    /**
     * Stores a number that is no item: an extensible type keeps it as an
     * unknown {@link Kind#VALUE}, any other type refuses it.
     *
     * @return false when the slot refused the number
     */
    public static boolean setNumber(EnumSlot slot, EnumSpec spec, long v) {
        return slot.enumSet(v) || (spec.extensible() && slot.enumSetUnknown(ofValue(v)));
    }
}
