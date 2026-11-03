package io.github.schramp.gambasasn1.wire.types;

import io.github.schramp.gambasasn1.wire.ber.UniversalTag;
import java.nio.charset.Charset;

/**
 * UTCTime (X.680 §47): a VisibleString with its own universal tag, held as the
 * time text itself, for example {@code 240115143000Z}; the text is not checked against
 * the time format; {@link #parse()} reads it.
 *
 * <p>{@link #get()} maps each octet to the character of the same code (ISO 8859-1).
 */
public final class Asn1UtcTime extends Asn1CharString {

    public Asn1UtcTime() {
    }

    public Asn1UtcTime(String value) {
        set(value);
    }

    @Override
    public int universalTagNumber() {
        return UniversalTag.UTC_TIME;
    }

    @Override
    protected Charset charset() {
        return java.nio.charset.StandardCharsets.ISO_8859_1;
    }

    /**
     * Reads the text as a time: its fields, how it relates to UTC and, for
     * a UTC or offset time, its instant. Malformed text gives a
     * {@link TimeParse.Malformed} that says why; the text stays the value
     * either way.
     */
    public TimeParse parse() {
        return TimeText.utc(get());
    }

    @Override
    public String xerElementName() {
        return "UTCTime";
    }
}
