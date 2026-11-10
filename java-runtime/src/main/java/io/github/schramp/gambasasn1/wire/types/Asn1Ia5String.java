package io.github.schramp.gambasasn1.wire.types;

import io.github.schramp.gambasasn1.wire.ber.UniversalTag;
import java.nio.charset.Charset;

/**
 * IA5String: the ISO 646 (ASCII) repertoire.
 *
 * <p>{@link #get()} maps each octet to the character of the same code (ISO 8859-1).
 */
public final class Asn1Ia5String extends Asn1CharString {

    public Asn1Ia5String() {
    }

    public Asn1Ia5String(String value) {
        set(value);
    }

    /** IA5String (X.680 §41.4): the 128 characters of ISO 646 IRV, 0x00..0x7F. */
    @Override
    public boolean inOwnAlphabet(int cp) {
        return cp >= 0 && cp <= 0x7F;
    }

    @Override
    public int universalTagNumber() {
        return UniversalTag.IA5_STRING;
    }

    @Override
    protected Charset charset() {
        return java.nio.charset.StandardCharsets.ISO_8859_1;
    }

    @Override
    public String xerElementName() {
        return "IA5String";
    }
}
