package io.github.schramp.gambasasn1.wire.types;

import java.nio.charset.Charset;
import java.util.Arrays;
import java.util.Objects;

/**
 * A restricted character string (X.680 §41): one subclass per string kind, each with
 * its own universal tag and X.693 element name. The value is stored as its
 * contents octets (X.690 §8.23.3: an OCTET STRING under the kind's tag), so any octets a peer sends survive a
 * decode and re-encode unchanged; {@link #get()} and {@link #set(String)}
 * convert through the kind's character encoding.
 */
public abstract sealed class Asn1CharString implements Asn1Primitive
        permits Asn1Utf8String, Asn1NumericString, Asn1PrintableString, Asn1T61String, Asn1VideotexString,
        Asn1Ia5String, Asn1GraphicString, Asn1VisibleString, Asn1GeneralString, Asn1ObjectDescriptor,
        Asn1BmpString, Asn1UniversalString {
    private static final byte[] EMPTY = new byte[0];
    private byte[] octets = EMPTY;

    /** The kind's universal tag number (X.680 §8, Table 1). */
    public abstract int universalTagNumber();

    /** How characters map to contents octets for this kind. */
    protected abstract Charset charset();

    /** The contents octets themselves, not a copy. */
    public byte[] octets() {
        return octets;
    }

    /** Takes {@code octets} as is, without copying or checking them. */
    public void setOctets(byte[] octets) {
        this.octets = Objects.requireNonNull(octets);
    }

    /** The value as text, decoded with the kind's character encoding. */
    public String get() {
        return new String(octets, charset());
    }

    /** Stores {@code value} encoded with the kind's character encoding. */
    public void set(String value) {
        octets = value.getBytes(charset());
    }

    @Override
    public boolean equals(Object o) {
        return o != null && o.getClass() == getClass() && Arrays.equals(((Asn1CharString) o).octets, octets);
    }

    @Override
    public int hashCode() {
        return Arrays.hashCode(octets) * 31 + universalTagNumber();
    }

    @Override
    public String toString() {
        return get();
    }
}
