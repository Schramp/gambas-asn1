package io.github.schramp.gambasasn1.wire.types;

import io.github.schramp.gambasasn1.wire.ber.UniversalTag;
import java.nio.charset.Charset;

/**
 * VisibleString: printing ASCII and space.
 *
 * <p>{@link #get()} maps each octet to the character of the same code (ISO 8859-1).
 */
public final class Asn1VisibleString extends Asn1CharString {

    public Asn1VisibleString() {
    }

    public Asn1VisibleString(String value) {
        set(value);
    }

    @Override
    public int universalTagNumber() {
        return UniversalTag.VISIBLE_STRING;
    }

    @Override
    protected Charset charset() {
        return java.nio.charset.StandardCharsets.ISO_8859_1;
    }

    @Override
    public String xerElementName() {
        return "VisibleString";
    }
}
