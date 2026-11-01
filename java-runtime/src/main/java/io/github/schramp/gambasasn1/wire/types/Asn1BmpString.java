package io.github.schramp.gambasasn1.wire.types;

import io.github.schramp.gambasasn1.wire.ber.UniversalTag;
import java.nio.charset.Charset;

/**
 * BMPString: two octets per character, big-endian (X.690 §8.23.8).
 */
public final class Asn1BmpString extends Asn1CharString {

    public Asn1BmpString() {
    }

    public Asn1BmpString(String value) {
        set(value);
    }

    @Override
    public int universalTagNumber() {
        return UniversalTag.BMP_STRING;
    }

    @Override
    protected Charset charset() {
        return java.nio.charset.StandardCharsets.UTF_16BE;
    }

    @Override
    public String xerElementName() {
        return "BMPString";
    }
}
