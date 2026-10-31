package io.github.schramp.gambasasn1.wire.xer;

import io.github.schramp.gambasasn1.wire.containing.ContainedOptions;
import io.github.schramp.gambasasn1.wire.io.DecodeException;
import io.github.schramp.gambasasn1.wire.io.Nesting;
import java.io.ByteArrayOutputStream;
import java.nio.charset.StandardCharsets;

/**
 * Cursor over an in-memory XER document: the whitespace-tolerant tag
 * grammar and entity decoding of the C++ and Rust runtimes. Text comes
 * back as raw octets, so character strings keep the bytes the document
 * holds.
 */
public final class XerReader {

    /**
     * One element tag: its name, whether it closes ({@code </name>}) and
     * whether it is empty ({@code <name/>}). An empty name means no tag.
     */
    public record TagInfo(String name, boolean closing, boolean selfClosing) {
        static final TagInfo NONE = new TagInfo("", false, false);
    }

    private final byte[] buf;
    private int pos;
    private final boolean lenient;
    private int depth;
    private ContainedOptions contained;

    /** A strict reader: BASIC-XER only (X.693 §8). */
    public XerReader(byte[] buf) {
        this(buf, false);
    }

    /**
     * @param lenient also accept asn1c's non-standard forms: BOOLEAN as text
     *                {@code true}/{@code false} (EXTENDED-XER §10), BIT STRING
     *                as hex pairs
     */
    public XerReader(byte[] buf, boolean lenient) {
        this.buf = buf;
        this.lenient = lenient;
    }

    public boolean lenient() {
        return lenient;
    }

    /** Contained-value settings of this decode; null for the defaults. */
    public ContainedOptions contained() {
        return contained;
    }

    /** Sets the contained-value settings of this decode. */
    public XerReader withContained(ContainedOptions options) {
        contained = options;
        return this;
    }

    /** Byte offset of the cursor. */
    public int position() {
        return pos;
    }

    /** Whether only whitespace is left. */
    public boolean atEnd() {
        return skipWs(pos) >= buf.length;
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

    private static boolean isWs(byte c) {
        return c == ' ' || c == '\t' || c == '\n' || c == '\r';
    }

    private int skipWs(int p) {
        while (p < buf.length && isWs(buf[p])) {
            p++;
        }
        return p;
    }

    /** Skips whitespace at the cursor. */
    public void skipWhitespace() {
        pos = skipWs(pos);
    }

    /** Parses the tag at the cursor; returns it and the offset after it. */
    private TagInfo parseTag(int[] end) {
        int p = skipWs(pos);
        if (p >= buf.length || buf[p] != '<') {
            end[0] = pos;
            return TagInfo.NONE;
        }
        p++;
        boolean closing = p < buf.length && buf[p] == '/';
        if (closing) {
            p++;
        }
        int nameStart = p;
        while (p < buf.length && buf[p] != '>' && buf[p] != '/' && !isWs(buf[p])) {
            p++;
        }
        String name = new String(buf, nameStart, p - nameStart, StandardCharsets.UTF_8);
        p = skipWs(p);
        boolean selfClosing = p < buf.length && buf[p] == '/';
        if (selfClosing) {
            p++;
        }
        if (p < buf.length && buf[p] == '>') {
            p++;
        }
        end[0] = p;
        return new TagInfo(name, closing, selfClosing);
    }

    /** The next tag, without consuming it. */
    public TagInfo peekTag() {
        return parseTag(new int[1]);
    }

    /** Consumes and returns the next tag. */
    public TagInfo consumeTag() {
        int[] end = new int[1];
        TagInfo t = parseTag(end);
        pos = end[0];
        return t;
    }

    /** Consumes {@code <name>}; anything else is an error. */
    public void consumeOpenTag(String name) {
        int at = pos;
        TagInfo t = consumeTag();
        if (!t.name().equals(name) || t.closing() || t.selfClosing()) {
            throw new DecodeException("XER: expected <" + name + ">", at);
        }
    }

    /**
     * Consumes {@code <name>} or {@code <name/>}.
     *
     * @return true for the empty form, which has no content and no closing tag
     */
    public boolean consumeOpenOrEmptyTag(String name) {
        int at = pos;
        TagInfo t = consumeTag();
        if (!t.name().equals(name) || t.closing()) {
            throw new DecodeException("XER: expected <" + name + ">", at);
        }
        return t.selfClosing();
    }

    /** Consumes {@code </name>}; anything else is an error. */
    public void consumeCloseTag(String name) {
        int at = pos;
        TagInfo t = consumeTag();
        if (!t.closing() || !t.name().equals(name)) {
            throw new DecodeException("XER: expected </" + name + ">", at);
        }
    }

    /** Consumes the raw, still escaped octets up to the next {@code <}. */
    public byte[] readRawText() {
        int start = pos;
        while (pos < buf.length && buf[pos] != '<') {
            pos++;
        }
        return java.util.Arrays.copyOfRange(buf, start, pos);
    }

    /** Consumes the text up to the next {@code <}, unescaped, as octets. */
    public byte[] readText() {
        return unescape(readRawText());
    }

    /** Consumes the text up to the next {@code <}, unescaped and trimmed, as a string. */
    public String readTrimmedText() {
        return new String(readText(), StandardCharsets.UTF_8).strip();
    }

    /**
     * Consumes an XML comment ({@code <!-- ... -->}) at the cursor.
     *
     * @return its trimmed text, or null (nothing consumed) when the next
     *         markup is not a comment
     */
    public String takeComment() {
        int p = skipWs(pos);
        if (!startsWith(p, "<!--")) {
            return null;
        }
        for (int e = p + 4; e + 3 <= buf.length; e++) {
            if (buf[e] == '-' && buf[e + 1] == '-' && buf[e + 2] == '>') {
                String text = new String(buf, p + 4, e - p - 4, StandardCharsets.UTF_8).strip();
                pos = e + 3;
                return text;
            }
        }
        return null;
    }

    private boolean startsWith(int p, String s) {
        if (p + s.length() > buf.length) {
            return false;
        }
        for (int i = 0; i < s.length(); i++) {
            if (buf[p + i] != s.charAt(i)) {
                return false;
            }
        }
        return true;
    }

    /**
     * Decodes the entities XER text may hold: {@code &lt;}, {@code &gt;},
     * {@code &amp;}, {@code &quot;}, {@code &apos;} and numeric references
     * ({@code &#NN;}, {@code &#xNN;}, written as UTF-8). An unknown
     * {@code &...;} passes through unchanged.
     */
    public static byte[] unescape(byte[] in) {
        ByteArrayOutputStream out = new ByteArrayOutputStream(in.length);
        int i = 0;
        while (i < in.length) {
            if (in[i] != '&') {
                out.write(in[i++]);
                continue;
            }
            int end = i + 1;
            while (end < in.length && end - i < 12 && in[end] != ';') {
                end++;
            }
            int cp = end < in.length && in[end] == ';' ? entity(new String(in, i + 1, end - i - 1, StandardCharsets.US_ASCII)) : -1;
            if (cp < 0) {
                out.write(in[i++]);
                continue;
            }
            out.writeBytes(new String(Character.toChars(cp)).getBytes(StandardCharsets.UTF_8));
            i = end + 1;
        }
        return out.toByteArray();
    }

    private static int entity(String e) {
        switch (e) {
            case "lt":
                return '<';
            case "gt":
                return '>';
            case "amp":
                return '&';
            case "quot":
                return '"';
            case "apos":
                return '\'';
            default:
                break;
        }
        if (!e.startsWith("#") || e.length() < 2) {
            return -1;
        }
        boolean hex = e.charAt(1) == 'x' || e.charAt(1) == 'X';
        try {
            int cp = Integer.parseInt(e.substring(hex ? 2 : 1), hex ? 16 : 10);
            return Character.isValidCodePoint(cp) ? cp : -1;
        } catch (NumberFormatException x) {
            return -1;
        }
    }
}
