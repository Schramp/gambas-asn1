package io.github.schramp.gambasasn1.wire.print;

import io.github.schramp.gambasasn1.wire.spec.AltMeta;
import io.github.schramp.gambasasn1.wire.spec.AsMemberRef;
import io.github.schramp.gambasasn1.wire.spec.Asn1Choice;
import io.github.schramp.gambasasn1.wire.spec.Asn1Contained;
import io.github.schramp.gambasasn1.wire.spec.Asn1Seq;
import io.github.schramp.gambasasn1.wire.spec.Asn1SeqOf;
import io.github.schramp.gambasasn1.wire.spec.ContainedStatus;
import io.github.schramp.gambasasn1.wire.spec.Containing;
import io.github.schramp.gambasasn1.wire.spec.EnumEntry;
import io.github.schramp.gambasasn1.wire.spec.EnumSlot;
import io.github.schramp.gambasasn1.wire.spec.EnumSpec;
import io.github.schramp.gambasasn1.wire.spec.MemberMeta;
import io.github.schramp.gambasasn1.wire.spec.MemberRef;
import io.github.schramp.gambasasn1.wire.types.Asn1Any;
import io.github.schramp.gambasasn1.wire.types.Asn1Arcs;
import io.github.schramp.gambasasn1.wire.types.Asn1BitString;
import io.github.schramp.gambasasn1.wire.types.Asn1Boolean;
import io.github.schramp.gambasasn1.wire.types.Asn1CharString;
import io.github.schramp.gambasasn1.wire.types.Asn1Integer;
import io.github.schramp.gambasasn1.wire.types.Asn1Null;
import io.github.schramp.gambasasn1.wire.types.Asn1OctetString;
import io.github.schramp.gambasasn1.wire.types.Asn1Primitive;
import io.github.schramp.gambasasn1.wire.types.Asn1Real;
import io.github.schramp.gambasasn1.wire.types.Asn1UInteger;
import io.github.schramp.gambasasn1.wire.xer.XerPrimitive;
import java.util.HexFormat;

/**
 * Renders a generated value as text for people to read, in the layout of
 * ASN.1 value notation (X.680 §16-§35). It is for display only and is not
 * parsed back. The layout is stable enough to compare in tests.
 *
 * <ul>
 * <li>A SEQUENCE or SET is {@code { name value, ... }}, one member per line,
 *     with an absent OPTIONAL member as a {@code -- name absent} line.
 * <li>A CHOICE is {@code alternative : value} (X.680 §29.11).
 * <li>A SEQUENCE OF lists each element on its own line after a
 *     {@code /* [i] *}{@code /} comment.
 * <li>BOOLEAN, NULL, INTEGER and REAL use their value notation, REAL as XER
 *     writes it. ENUMERATED shows its identifier, and an OBJECT IDENTIFIER
 *     shows its arcs in braces.
 * <li>A character string or time is shown in quotes, its quote characters
 *     doubled and its control characters shown as {@code .}.
 * <li>OCTET STRING, ANY and a long BIT STRING are shown as {@code '..'H}, and
 *     a short BIT STRING as {@code '..'B}.
 * <li>A contained value that was decoded is shown as {@code CONTAINING value};
 *     otherwise its octets are shown, with its status.
 * </ul>
 *
 * Octet and character strings longer than the printer's limits are cut off,
 * and a comment gives their full size.
 */
public final class ValuePrinter {
    private static final ValuePrinter DEFAULT = new ValuePrinter(32, 128);
    private static final String INDENT = "  ";

    private final int maxOctets;
    private final int maxChars;

    /**
     * @param maxOctets octets of an OCTET STRING, ANY or BIT STRING shown before cutting it off
     * @param maxChars  characters of a character string shown before cutting it off
     */
    public ValuePrinter(int maxOctets, int maxChars) {
        this.maxOctets = maxOctets;
        this.maxChars = maxChars;
    }

    /** {@code v} as text under the default limits (32 octets, 128 characters). */
    public static String print(AsMemberRef v) {
        return DEFAULT.format(v);
    }

    /** {@code v} as text under this printer's limits. */
    public String format(AsMemberRef v) {
        StringBuilder sb = new StringBuilder();
        value(v.asMemberRef(), 0, sb);
        return sb.toString();
    }

    private void value(MemberRef m, int depth, StringBuilder sb) {
        switch (m) {
            case MemberRef.Primitive(var p) -> primitive(p, sb);
            case MemberRef.Enumerated(var slot, var spec) -> enumerated(slot, spec, sb);
            case MemberRef.Composite(var s) -> sequence(s, depth, sb);
            case MemberRef.Choice(var c) -> choice(c, depth, sb);
            case MemberRef.SeqOf(var q) -> seqOf(q, depth, sb);
            case MemberRef.Contained(var f, var spec) -> contained(f, depth, sb);
            case MemberRef.Absent a -> sb.append("-- absent");
            case MemberRef.Unsupported(String reason) -> sb.append("/* unsupported: ").append(reason).append(" */");
        }
    }

    private void sequence(Asn1Seq s, int depth, StringBuilder sb) {
        var rows = s.spec().members();
        int last = -1;
        for (int i = 0; i < rows.size(); i++) {
            if (!(s.getMember(i) instanceof MemberRef.Absent)) {
                last = i;
            }
        }
        if (rows.isEmpty()) {
            sb.append("{}");
            return;
        }
        sb.append("{\n");
        for (int i = 0; i < rows.size(); i++) {
            MemberMeta row = rows.get(i);
            MemberRef m = s.getMember(i);
            indent(depth + 1, sb);
            if (m instanceof MemberRef.Absent) {
                sb.append("-- ").append(row.name()).append(" absent\n");
                continue;
            }
            sb.append(row.name()).append(' ');
            value(m, depth + 1, sb);
            sb.append(i < last ? ",\n" : "\n");
        }
        indent(depth, sb);
        sb.append('}');
    }

    private void choice(Asn1Choice c, int depth, StringBuilder sb) {
        int i = c.activeIndex();
        if (i >= 0) {
            AltMeta row = c.spec().alternatives().get(i);
            sb.append(row.name()).append(" : ");
            value(c.getActive(), depth, sb);
            return;
        }
        Asn1Choice.UnknownExtension ext = c.unknownExtension();
        if (ext == null) {
            sb.append("/* no alternative selected */");
            return;
        }
        sb.append("/* unknown extension ").append(ext.tag()).append(" */ ");
        octets(ext.bytes(), sb);
    }

    private void seqOf(Asn1SeqOf q, int depth, StringBuilder sb) {
        if (q.size() == 0) {
            sb.append("{}");
            return;
        }
        sb.append("{\n");
        for (int i = 0; i < q.size(); i++) {
            indent(depth + 1, sb);
            sb.append("/* [").append(i).append("] */ ");
            value(q.get(i), depth + 1, sb);
            sb.append(i < q.size() - 1 ? ",\n" : "\n");
        }
        indent(depth, sb);
        sb.append('}');
    }

    private void contained(Asn1Contained f, int depth, StringBuilder sb) {
        AsMemberRef inner = f.value();
        if (inner != null && f.status() == ContainedStatus.DECODED) {
            sb.append("CONTAINING ");
            value(inner.asMemberRef(), depth, sb);
            return;
        }
        octets(f.rawOctets(), sb);
        sb.append(" /* contained, ").append(f.status().name().toLowerCase(java.util.Locale.ROOT).replace('_', ' '));
        if (f instanceof Containing<?> c && !c.error().isEmpty()) {
            sb.append(": ").append(c.error());
        }
        sb.append(" */");
    }

    private static void enumerated(EnumSlot slot, EnumSpec spec, StringBuilder sb) {
        long v = slot.enumGet();
        for (EnumEntry e : spec.entries()) {
            if (e.value() == v) {
                sb.append(e.name());
                return;
            }
        }
        sb.append(v).append(" /* not in ").append(spec.name()).append(" */");
    }

    private void primitive(Asn1Primitive p, StringBuilder sb) {
        switch (p) {
            case Asn1Boolean b -> sb.append(b.get() ? "TRUE" : "FALSE");
            case Asn1Null n -> sb.append("NULL");
            case Asn1Integer i -> sb.append(i.get());
            case Asn1UInteger u -> sb.append(Long.toUnsignedString(u.get()));
            case Asn1Real r -> sb.append(XerPrimitive.realText(r));
            case Asn1OctetString o -> octets(o.get(), sb);
            case Asn1Any a -> {
                octets(a.get(), sb);
                sb.append(" /* ANY */");
            }
            case Asn1BitString b -> bits(b, sb);
            case Asn1Arcs a -> arcs(a.get(), sb);
            case Asn1CharString s -> chars(s.get(), sb);
            default -> sb.append("/* ").append(p.xerElementName()).append(" */");
        }
    }

    private static void arcs(long[] arcs, StringBuilder sb) {
        sb.append('{');
        for (long a : arcs) {
            sb.append(' ').append(a);
        }
        sb.append(" }");
    }

    private void octets(byte[] o, StringBuilder sb) {
        int shown = Math.min(o.length, maxOctets);
        sb.append('\'').append(HexFormat.of().withUpperCase().formatHex(o, 0, shown));
        if (shown < o.length) {
            sb.append("...'H /* ").append(o.length).append(" octets */");
            return;
        }
        sb.append("'H");
        if (o.length >= 2 && printable(o)) {
            sb.append(" /* \"").append(new String(o, java.nio.charset.StandardCharsets.US_ASCII)
                    .replace("*/", "*\\/")).append("\" */");
        }
    }

    private static boolean printable(byte[] o) {
        for (byte b : o) {
            if (b < 0x20 || b > 0x7E) {
                return false;
            }
        }
        return true;
    }

    /** At most 64 bits as binary digits; a longer BIT STRING as hex (X.680 §22.9 bstring, hstring). */
    private void bits(Asn1BitString b, StringBuilder sb) {
        int n = b.bitCount();
        byte[] bytes = b.bytes();
        if (n > 64) {
            octets(bytes, sb);
            sb.append(" /* ").append(n).append(" bits */");
            return;
        }
        sb.append('\'');
        for (int i = 0; i < n; i++) {
            sb.append((bytes[i / 8] & (0x80 >>> (i % 8))) != 0 ? '1' : '0');
        }
        sb.append("'B");
    }

    private void chars(String s, StringBuilder sb) {
        int count = s.codePointCount(0, s.length());
        sb.append('"');
        int[] cps = s.codePoints().limit(maxChars).toArray();
        for (int cp : cps) {
            if (cp == '"') {
                sb.append("\"\"");
            } else if (cp < 0x20 || cp == 0x7F) {
                sb.append('.');
            } else {
                sb.appendCodePoint(cp);
            }
        }
        sb.append('"');
        if (count > maxChars) {
            sb.append(" /* cut off, ").append(count).append(" characters */");
        }
    }

    private static void indent(int depth, StringBuilder sb) {
        sb.append(INDENT.repeat(depth));
    }
}
