package io.github.schramp.gambasasn1.wire.jer;

import io.github.schramp.gambasasn1.wire.containing.ContainedOptions;
import io.github.schramp.gambasasn1.wire.io.DecodeException;
import io.github.schramp.gambasasn1.wire.io.Nesting;
import java.io.ByteArrayOutputStream;
import java.nio.charset.StandardCharsets;

/**
 * Cursor over an in-memory JER text: the JSON scanner of the C++ and Rust
 * runtimes. Whitespace is allowed between any two tokens (RFC 8259 §2);
 * strings come back unescaped as UTF-8 octets.
 */
public final class JerReader {
    private final byte[] buf;
    private int pos;
    private int depth;
    private ContainedOptions contained;

    public JerReader(byte[] buf) {
        this.buf = buf;
    }

    /** Contained-value settings of this decode; null for the defaults. */
    public ContainedOptions contained() {
        return contained;
    }

    /** Sets the contained-value settings of this decode. */
    public JerReader withContained(ContainedOptions options) {
        contained = options;
        return this;
    }

    /** Byte offset of the cursor. */
    public int position() {
        return pos;
    }

    /** Whether only whitespace is left. */
    public boolean atEnd() {
        skipWhitespace();
        return pos >= buf.length;
    }

    /** Counts one more nesting level; fails past {@link Nesting#MAX_DECODE_DEPTH}. */
    public void enterLevel() {
        if (++depth > Nesting.MAX_DECODE_DEPTH) {
            throw new DecodeException(Nesting.tooDeep(), pos);
        }
    }

    public void leaveLevel() {
        depth--;
    }

    /** The constructed levels this decode is inside. */
    int depth() {
        return depth;
    }

    /** Skips JSON whitespace at the cursor. */
    public void skipWhitespace() {
        while (pos < buf.length && (buf[pos] == ' ' || buf[pos] == '\t' || buf[pos] == '\n' || buf[pos] == '\r')) {
            pos++;
        }
    }

    /** The next non-whitespace byte, not consumed; 0 at the end. */
    public int peek() {
        skipWhitespace();
        return pos < buf.length ? buf[pos] & 0xFF : 0;
    }

    /** Consumes {@code c} after optional whitespace. */
    public void expect(char c) {
        if (peek() != c) {
            throw new DecodeException("JER: expected '" + c + "'", pos);
        }
        pos++;
    }

    /** Consumes {@code c} when it is next; returns whether it was. */
    public boolean consumeIf(char c) {
        if (peek() != c) {
            return false;
        }
        pos++;
        return true;
    }

    /**
     * Reads one JSON string and unescapes it (RFC 8259 §7); X.697 §23.4 NOTE
     * allows escapes in every JER string, member names included. A
     * {@code \}{@code u} escape is a UTF-16 code unit; a surrogate pair
     * combines into one code point. A lone surrogate, a short escape or an
     * unknown escape character is a decode error.
     */
    public byte[] readString() {
        if (peek() != '"') {
            throw new DecodeException("JER: expected '\"'", pos);
        }
        pos++;
        ByteArrayOutputStream out = new ByteArrayOutputStream();
        while (pos < buf.length) {
            byte c = buf[pos++];
            if (c == '"') {
                return out.toByteArray();
            }
            if (c != '\\') {
                out.write(c);
                continue;
            }
            if (pos >= buf.length) {
                break;
            }
            byte e = buf[pos++];
            switch (e) {
                case '"', '\\', '/' -> out.write(e);
                case 'b' -> out.write('\b');
                case 'f' -> out.write('\f');
                case 'n' -> out.write('\n');
                case 'r' -> out.write('\r');
                case 't' -> out.write('\t');
                case 'u' -> {
                    int cu = hex4();
                    if (cu >= 0xDC00 && cu <= 0xDFFF) {
                        throw new DecodeException("JER: lone low surrogate in \\u escape", pos);
                    }
                    if (cu >= 0xD800 && cu <= 0xDBFF) {
                        if (pos + 1 >= buf.length || buf[pos] != '\\' || buf[pos + 1] != 'u') {
                            throw new DecodeException("JER: lone high surrogate in \\u escape", pos);
                        }
                        pos += 2;
                        int lo = hex4();
                        if (lo < 0xDC00 || lo > 0xDFFF) {
                            throw new DecodeException("JER: lone high surrogate in \\u escape", pos);
                        }
                        cu = 0x10000 + ((cu - 0xD800) << 10) + (lo - 0xDC00);
                    }
                    out.writeBytes(new String(Character.toChars(cu)).getBytes(StandardCharsets.UTF_8));
                }
                default -> throw new DecodeException("JER: invalid escape in string", pos);
            }
        }
        throw new DecodeException("JER: unterminated string", pos);
    }

    /** {@link #readString} as text. */
    public String readStringText() {
        return new String(readString(), StandardCharsets.UTF_8);
    }

    private int hex4() {
        if (pos + 4 > buf.length) {
            throw new DecodeException("JER: malformed \\u escape", pos);
        }
        int v = 0;
        for (int i = 0; i < 4; i++) {
            int d = Character.digit(buf[pos + i], 16);
            if (d < 0) {
                throw new DecodeException("JER: malformed \\u escape", pos);
            }
            v = v << 4 | d;
        }
        pos += 4;
        return v;
    }

    /** Reads a number, {@code true}, {@code false} or {@code null} as its raw text. */
    public String readToken() {
        skipWhitespace();
        int start = pos;
        while (pos < buf.length) {
            byte c = buf[pos];
            if (c == ',' || c == '}' || c == ']' || c == ' ' || c == '\t' || c == '\n' || c == '\r') {
                break;
            }
            pos++;
        }
        if (pos == start) {
            throw new DecodeException("JER: expected value token", pos);
        }
        return new String(buf, start, pos - start, StandardCharsets.UTF_8);
    }

    /** Skips one JSON value of any kind, nested objects and arrays included. */
    public void skipValue() {
        int c = peek();
        if (c == 0) {
            throw new DecodeException("JER: unexpected end in value", pos);
        }
        if (c == '"') {
            readString();
            return;
        }
        if (c == '{' || c == '[') {
            int level = 0;
            boolean inString = false;
            boolean escape = false;
            while (pos < buf.length) {
                byte b = buf[pos++];
                if (escape) {
                    escape = false;
                } else if (inString) {
                    if (b == '\\') {
                        escape = true;
                    } else if (b == '"') {
                        inString = false;
                    }
                } else if (b == '"') {
                    inString = true;
                } else if (b == '{' || b == '[') {
                    level++;
                } else if ((b == '}' || b == ']') && --level == 0) {
                    return;
                }
            }
            throw new DecodeException("JER: unterminated value", pos);
        }
        readToken();
    }
}
