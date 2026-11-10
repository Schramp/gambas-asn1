package io.github.schramp.gambasasn1.wire.types;

import java.io.ByteArrayOutputStream;
import java.nio.charset.Charset;
import java.nio.charset.StandardCharsets;
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
        Asn1BmpString, Asn1UniversalString, Asn1UtcTime, Asn1GeneralizedTime {
    private static final byte[] EMPTY = new byte[0];
    private byte[] octets = EMPTY;

    /** The kind's universal tag number (X.680 §8, Table 1). */
    public abstract int universalTagNumber();

    /**
     * Whether code point {@code cp} is in the kind's own character set, the
     * set its values are drawn from without a FROM constraint (X.680 §41).
     * True for every code point unless the kind has a fixed set
     * (NumericString, PrintableString, IA5String, VisibleString).
     */
    public boolean inOwnAlphabet(int cp) {
        return true;
    }

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

    /**
     * The value's characters as code points, read from the contents octets
     * in the kind's own form (X.690 §8.23): UTF-8 for UTF8String, 2 octets
     * per character for BMPString, 4 for UniversalString, one octet
     * otherwise. A malformed UTF-8 octet counts as one character; trailing
     * octets of an incomplete wide character are not a character. SIZE and
     * FROM constraints count these (X.680 §51.5, §51.7).
     */
    public int[] codePoints() {
        return codePoints(octets, universalTagNumber());
    }

    /** {@link #codePoints()} of {@code octets} stored as the kind with universal tag {@code tag}. */
    public static int[] codePoints(byte[] octets, int tag) {
        int n = octets.length;
        if (tag == 30 || tag == 28) {
            int w = tag == 30 ? 2 : 4;
            int[] cps = new int[n / w];
            for (int c = 0; c < cps.length; c++) {
                int cp = 0;
                for (int k = 0; k < w; k++) {
                    cp = cp << 8 | (octets[c * w + k] & 0xFF);
                }
                cps[c] = cp;
            }
            return cps;
        }
        if (tag != 12) {
            int[] cps = new int[n];
            for (int i = 0; i < n; i++) {
                cps[i] = octets[i] & 0xFF;
            }
            return cps;
        }
        int[] cps = new int[n];
        int c = 0;
        for (int i = 0; i < n;) {
            int lead = octets[i] & 0xFF;
            int len = lead < 0x80 ? 1 : (lead >> 5) == 0x6 ? 2 : (lead >> 4) == 0xE ? 3 : (lead >> 3) == 0x1E ? 4 : 1;
            if (i + len > n) {
                len = 1;
            }
            for (int k = 1; k < len; k++) {
                if ((octets[i + k] & 0xC0) != 0x80) {
                    len = 1;
                    break;
                }
            }
            int cp = len == 1 ? lead : lead & (0x7F >> len);
            for (int k = 1; k < len; k++) {
                cp = cp << 6 | (octets[i + k] & 0x3F);
            }
            cps[c++] = cp;
            i += len;
        }
        return Arrays.copyOf(cps, c);
    }

    /** BMPString / UniversalString octets (big-endian, {@code width} per character) as UTF-8. */
    public static byte[] wideToUtf8(byte[] octets, int width) {
        StringBuilder s = new StringBuilder();
        for (int i = 0; i + width <= octets.length; i += width) {
            int cp = 0;
            for (int k = 0; k < width; k++) {
                cp = cp << 8 | (octets[i + k] & 0xFF);
            }
            s.appendCodePoint(Character.isValidCodePoint(cp) ? cp : 0xFFFD);
        }
        return s.toString().getBytes(StandardCharsets.UTF_8);
    }

    /** The reverse of {@link #wideToUtf8}: each character as {@code width} big-endian octets. */
    public static byte[] utf8ToWide(byte[] utf8, int width) {
        ByteArrayOutputStream out = new ByteArrayOutputStream();
        new String(utf8, StandardCharsets.UTF_8).codePoints().forEach(cp -> {
            for (int k = width - 1; k >= 0; k--) {
                out.write(cp >> (8 * k));
            }
        });
        return out.toByteArray();
    }
}
