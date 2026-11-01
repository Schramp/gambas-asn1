package io.github.schramp.gambasasn1.wire.spec;

/**
 * PER-visible constraints of one type or member, as plain data (X.691 §10).
 * Codecs read them; no code is generated per constraint. Flag values are
 * shared by every runtime.
 *
 * @param flags         bit set of the flag constants below
 * @param rangeBits     bits for a finite value range (X.691 §10.5)
 * @param lowerBound    lower value bound, signed storage
 * @param upperBound    upper value bound, signed storage
 * @param lowerU64      lower value bound, unsigned storage (read as unsigned)
 * @param upperU64      upper value bound, unsigned storage (read as unsigned)
 * @param sizeRangeBits bits for a finite SIZE range
 * @param sizeLower     SIZE lower bound
 * @param sizeUpper     SIZE upper bound, meaningful with SIZE_CONSTRAINED
 * @param encodeTable   character to alphabet index, 256 entries (0xFFFF = not permitted), or null
 * @param alphabetBits  bits per character under a FROM constraint (X.691 §26.5.4), 0 without one
 * @param alphabet      alphabet index to character, sorted, or null
 * @param alphabetSize  number of permitted characters
 * @param element       a SEQUENCE OF / SET OF element's own constraints, or null
 * @param realLower     REAL lower bound, with REAL_RANGE
 * @param realUpper     REAL upper bound, with REAL_RANGE
 */
public record Constraints(
        int flags, int rangeBits, long lowerBound, long upperBound, long lowerU64, long upperU64,
        int sizeRangeBits, long sizeLower, long sizeUpper, char[] encodeTable, int alphabetBits,
        byte[] alphabet, int alphabetSize, Constraints element, double realLower, double realUpper) {

    /** lowerBound..upperBound is a finite range. */
    public static final int CONSTRAINED = 1;
    /** Only the lower value bound is set. */
    public static final int SEMI_CONSTRAINED = 2;
    /** The constraint has an extension marker. */
    public static final int EXTENSIBLE = 4;
    /** sizeLower..sizeUpper is a finite range. */
    public static final int SIZE_CONSTRAINED = 8;
    /** BIT STRING with a NamedBitList (X.680 §22.7). */
    public static final int NAMED_BITS = 16;
    /** REAL value range realLower..realUpper (X.680 §47.4). */
    public static final int REAL_RANGE = 32;
    /** realLower itself is excluded. */
    public static final int REAL_LOWER_OPEN = 64;
    /** realUpper itself is excluded. */
    public static final int REAL_UPPER_OPEN = 128;
    /** The JER-visible base constraint admits only base 10 (X.697 §23.1.4). */
    public static final int REAL_BASE_10 = 256;

    public static final Constraints UNCONSTRAINED =
            new Constraints(0, 0, 0, 0, 0, 0, 0, 0, 0, null, 0, null, 0, null, 0.0, 0.0);

    /**
     * {@code c} with a permitted alphabet (X.680 §51.7): {@code alphabet}
     * holds the sorted characters, each written as its index in
     * {@code bits} bits under PER (X.691 §30.5.2); the character-to-index
     * table is built from it.
     */
    public static Constraints withAlphabet(Constraints c, int bits, byte[] alphabet) {
        char[] table = new char[256];
        java.util.Arrays.fill(table, (char) 0xFFFF);
        for (int i = 0; i < alphabet.length; i++) {
            table[alphabet[i] & 0xFF] = (char) i;
        }
        return new Constraints(c.flags, c.rangeBits, c.lowerBound, c.upperBound, c.lowerU64, c.upperU64,
                c.sizeRangeBits, c.sizeLower, c.sizeUpper, table, bits, alphabet, alphabet.length, c.element,
                c.realLower, c.realUpper);
    }

    /** {@code c} with {@code element} as a SEQUENCE OF / SET OF element's own constraints. */
    public static Constraints withElement(Constraints c, Constraints element) {
        return new Constraints(c.flags, c.rangeBits, c.lowerBound, c.upperBound, c.lowerU64, c.upperU64,
                c.sizeRangeBits, c.sizeLower, c.sizeUpper, c.encodeTable, c.alphabetBits, c.alphabet,
                c.alphabetSize, element, c.realLower, c.realUpper);
    }
}
