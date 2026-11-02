package io.github.schramp.gambasasn1.wire.types;

import io.github.schramp.gambasasn1.wire.ber.UniversalTag;
import java.nio.charset.Charset;

/**
 * UTF8String: UTF-8 (ISO/IEC 10646 Annex D).
 */
public final class Asn1Utf8String extends Asn1CharString {

    public Asn1Utf8String() {
    }

    public Asn1Utf8String(String value) {
        set(value);
    }

    @Override
    public int universalTagNumber() {
        return UniversalTag.UTF8_STRING;
    }

    @Override
    protected Charset charset() {
        return java.nio.charset.StandardCharsets.UTF_8;
    }

    @Override
    public String xerElementName() {
        return "UTF8String";
    }
}
