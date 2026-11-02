package io.github.schramp.gambasasn1.wire.jer;

import io.github.schramp.gambasasn1.wire.containing.ContainedOptions;
import java.io.ByteArrayOutputStream;
import java.nio.charset.StandardCharsets;

/**
 * JER output: one compact JSON text, UTF-8, no whitespace between tokens,
 * the layout of the C++ and Rust runtimes. String contents go out as their
 * octets with only {@code "}, {@code \} and the C0 controls escaped
 * (RFC 8259 §7), so the bytes a value holds reach the text unchanged.
 */
public final class JerWriter {
    private static final byte[] HEX = "0123456789ABCDEF".getBytes(StandardCharsets.US_ASCII);

    private final ByteArrayOutputStream out = new ByteArrayOutputStream();
    private ContainedOptions contained;

    /** Contained-value settings of this encode; null for the defaults. */
    public ContainedOptions contained() {
        return contained;
    }

    /** Sets the contained-value settings of this encode. */
    public JerWriter withContained(ContainedOptions options) {
        contained = options;
        return this;
    }

    /** Appends JSON punctuation, literals or numbers. */
    public JerWriter ascii(String s) {
        for (int i = 0; i < s.length(); i++) {
            out.write(s.charAt(i));
        }
        return this;
    }

    /** Appends {@code s} as a JSON string. */
    public JerWriter string(String s) {
        return string(s.getBytes(StandardCharsets.UTF_8));
    }

    /**
     * Appends {@code utf8} as a JSON string: {@code "} and {@code \} escaped
     * with a backslash, characters below U+0020 as a six-character {@code u00XX} escape.
     */
    public JerWriter string(byte[] utf8) {
        out.write('"');
        for (byte b : utf8) {
            if (b == '"' || b == '\\') {
                out.write('\\');
                out.write(b);
            } else if (b >= 0 && b < 0x20) {
                ascii("\\u00").hexByte(b);
            } else {
                out.write(b);
            }
        }
        out.write('"');
        return this;
    }

    /** Appends {@code bytes} as a JSON string of unspaced uppercase hex pairs. */
    public JerWriter hexString(byte[] bytes) {
        out.write('"');
        for (byte b : bytes) {
            hexByte(b);
        }
        out.write('"');
        return this;
    }

    private JerWriter hexByte(byte b) {
        out.write(HEX[(b >> 4) & 0xF]);
        out.write(HEX[b & 0xF]);
        return this;
    }

    /** The text so far. */
    public byte[] toByteArray() {
        return out.toByteArray();
    }
}
