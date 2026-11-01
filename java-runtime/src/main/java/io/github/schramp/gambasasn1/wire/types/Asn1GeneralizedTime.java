package io.github.schramp.gambasasn1.wire.types;

import io.github.schramp.gambasasn1.wire.ber.UniversalTag;
import java.nio.charset.Charset;

/**
 * GeneralizedTime (X.680 §46): a VisibleString with its own universal tag, held as the
 * time text itself, for example {@code 20240115143000.5Z}; the text is not checked against
 * the time format.
 *
 * <p>{@link #get()} maps each octet to the character of the same code (ISO 8859-1).
 */
public final class Asn1GeneralizedTime extends Asn1CharString {

    public Asn1GeneralizedTime() {
    }

    public Asn1GeneralizedTime(String value) {
        set(value);
    }

    @Override
    public int universalTagNumber() {
        return UniversalTag.GENERALIZED_TIME;
    }

    @Override
    protected Charset charset() {
        return java.nio.charset.StandardCharsets.ISO_8859_1;
    }

    @Override
    public String xerElementName() {
        return "GeneralizedTime";
    }
}
