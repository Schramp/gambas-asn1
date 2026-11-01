package io.github.schramp.gambasasn1.wire.ber;

import java.util.Comparator;

/**
 * A BER identifier: class, number and encoding form (X.690 §8.1.2).
 *
 * @param tagClass    the tag class
 * @param number      the tag number, 0 or more
 * @param constructed true for the constructed encoding form
 */
public record Tag(TagClass tagClass, int number, boolean constructed) {

    /**
     * Order of CHOICE alternatives and SET members by tag: class, then
     * number (X.680 §8.6). Every sorted BER dispatch table uses it.
     */
    public static final Comparator<Tag> IDENTIFIER_ORDER =
            Comparator.comparingInt((Tag t) -> t.tagClass().bits()).thenComparingInt(Tag::number);

    public Tag {
        if (number < 0) {
            throw new IllegalArgumentException("negative tag number " + number);
        }
    }

    public static Tag universal(int number, boolean constructed) {
        return new Tag(TagClass.UNIVERSAL, number, constructed);
    }

    public static Tag context(int number, boolean constructed) {
        return new Tag(TagClass.CONTEXT, number, constructed);
    }

    /** Same class and number; the encoding form is not compared. */
    public boolean matchesIdentifier(Tag other) {
        return tagClass == other.tagClass && number == other.number;
    }
}
