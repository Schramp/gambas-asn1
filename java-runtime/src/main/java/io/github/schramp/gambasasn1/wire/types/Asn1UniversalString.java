package io.github.schramp.gambasasn1.wire.types;

import io.github.schramp.gambasasn1.wire.ber.UniversalTag;
import java.nio.charset.Charset;

/**
 * UniversalString: four octets per character, big-endian (X.690 §8.23.7).
 */
public final class Asn1UniversalString extends Asn1CharString {
    private static final Charset CHARSET = java.nio.charset.Charset.forName("UTF-32BE");

    public Asn1UniversalString() {
    }

    public Asn1UniversalString(String value) {
        set(value);
    }

    @Override
    public int universalTagNumber() {
        return UniversalTag.UNIVERSAL_STRING;
    }

    @Override
    protected Charset charset() {
        return CHARSET;
    }

    @Override
    public String xerElementName() {
        return "UniversalString";
    }
}
