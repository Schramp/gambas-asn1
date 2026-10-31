package io.github.schramp.gambasasn1.wire.xer;

import java.io.ByteArrayOutputStream;
import java.nio.charset.StandardCharsets;

/**
 * XER output: a UTF-8 byte document. Character string contents go out as
 * their octets with only {@code <}, {@code >} and {@code &} escaped
 * (X.693 §8.2), so the bytes a value holds reach the document unchanged,
 * as in asn1c.
 */
public final class XerWriter {
    private static final byte[] HEX = "0123456789ABCDEF".getBytes(StandardCharsets.US_ASCII);

    private final ByteArrayOutputStream out = new ByteArrayOutputStream();

    /** Appends ASCII markup or numbers. */
    public XerWriter ascii(String s) {
        for (int i = 0; i < s.length(); i++) {
            out.write(s.charAt(i));
        }
        return this;
    }

    /** Appends text, UTF-8 encoded and escaped. */
    public XerWriter text(String s) {
        return escaped(s.getBytes(StandardCharsets.UTF_8));
    }

    /** Appends octets with {@code <}, {@code >} and {@code &} escaped (X.693 §8.2). */
    public XerWriter escaped(byte[] bytes) {
        for (byte b : bytes) {
            switch (b) {
                case '<' -> ascii("&lt;");
                case '>' -> ascii("&gt;");
                case '&' -> ascii("&amp;");
                default -> out.write(b);
            }
        }
        return this;
    }

    /** Appends {@code bytes} as unspaced uppercase hex pairs. */
    public XerWriter hex(byte[] bytes) {
        for (byte b : bytes) {
            out.write(HEX[(b >> 4) & 0xF]);
            out.write(HEX[b & 0xF]);
        }
        return this;
    }

    /** Appends {@code 4 * depth} spaces, asn1c's indent unit. */
    public XerWriter indent(int depth) {
        for (int i = 0; i < 4 * depth; i++) {
            out.write(' ');
        }
        return this;
    }

    /** Appends {@code <name>}. */
    public XerWriter open(String name) {
        return ascii("<").name(name).ascii(">");
    }

    /** Appends {@code </name>}. */
    public XerWriter close(String name) {
        return ascii("</").name(name).ascii(">");
    }

    /** Appends {@code <name/>}. */
    public XerWriter empty(String name) {
        return ascii("<").name(name).ascii("/>");
    }

    private XerWriter name(String name) {
        out.writeBytes(name.getBytes(StandardCharsets.UTF_8));
        return this;
    }

    /** The document so far. */
    public byte[] toByteArray() {
        return out.toByteArray();
    }
}
