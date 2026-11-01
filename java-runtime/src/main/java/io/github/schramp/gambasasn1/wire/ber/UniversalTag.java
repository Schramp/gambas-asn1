package io.github.schramp.gambasasn1.wire.ber;

/** Universal tag numbers of the builtin types (X.680 §8.6, Table 1). */
public final class UniversalTag {
    public static final int BOOLEAN = 1;
    public static final int INTEGER = 2;
    public static final int BIT_STRING = 3;
    public static final int OCTET_STRING = 4;
    public static final int NULL = 5;
    public static final int OBJECT_IDENTIFIER = 6;
    public static final int OBJECT_DESCRIPTOR = 7;
    public static final int REAL = 9;
    public static final int ENUMERATED = 10;
    public static final int UTF8_STRING = 12;
    public static final int RELATIVE_OID = 13;
    public static final int SEQUENCE = 16;
    public static final int SET = 17;
    public static final int NUMERIC_STRING = 18;
    public static final int PRINTABLE_STRING = 19;
    public static final int T61_STRING = 20;
    public static final int VIDEOTEX_STRING = 21;
    public static final int IA5_STRING = 22;
    public static final int UTC_TIME = 23;
    public static final int GENERALIZED_TIME = 24;
    public static final int GRAPHIC_STRING = 25;
    public static final int VISIBLE_STRING = 26;
    public static final int GENERAL_STRING = 27;
    public static final int UNIVERSAL_STRING = 28;
    public static final int BMP_STRING = 30;

    private UniversalTag() {
    }
}
