package io.github.schramp.gambasasn1.wire.spec;

import io.github.schramp.gambasasn1.wire.ber.Tag;
import io.github.schramp.gambasasn1.wire.types.Asn1Primitive;
import java.util.ArrayList;
import java.util.Comparator;
import java.util.List;
import java.util.function.Supplier;

/**
 * Canonical descriptor-table dump, the cross-language table check. Every
 * runtime writes its own tables in one JSON format (doc/backend-guide.md,
 * Appendix A) and validation-tools/table_diff compares the dumps field by
 * field. The dump reads the tables only; it never encodes or decodes.
 *
 * <p>A field these tables do not carry is left out; the diff reports it as
 * "not carried", not as a mismatch.
 */
public final class TableDump {
    private TableDump() {
    }

    /**
     * One type's tables as one line of canonical JSON.
     *
     * @param factory makes a default value of the type; called more than once
     *                for a CHOICE, whose alternatives are inspected one at a time
     * @param name    the ASN.1 type name, for shapes whose tables carry none
     */
    public static String dump(Supplier<? extends AsMemberRef> factory, String name) {
        MemberRef m = factory.get().asMemberRef();
        StringBuilder out = new StringBuilder();
        switch (m) {
            case MemberRef.Composite(Asn1Seq s) -> {
                SequenceSpec sp = s.spec();
                List<String> rows = new ArrayList<>();
                for (int i = 0; i < sp.members().size(); i++) {
                    MemberMeta r = sp.members().get(i);
                    rows.add("{\"name\":" + jstr(r.name()) + "," + jtagging(r.ber(), r.tag(), isUntaggedChoice(s.getMember(i)))
                            + ",\"optional\":" + r.optional() + ",\"constraints\":" + jconstraints(r.constraints())
                            + ",\"xer_instruction\":\"" + r.xerInstruction().name() + "\",\"contained\":" + (r.contained() != null) + "}");
                }
                List<String> units = sp.extUnits().stream().map(u -> "{\"end\":" + u.end() + ",\"group\":" + u.group() + "}").toList();
                List<String> contained = sp.containedMembers().stream().map(String::valueOf).toList();
                out.append("{\"name\":").append(jstr(sp.name())).append(",\"kind\":\"").append(sp.isSet() ? "SET" : "SEQUENCE")
                        .append("\",\"tag\":").append(jtag(sp.tag())).append(",\"ext_at\":").append(sp.extAt())
                        .append(",\"roms_count\":").append(sp.romsCount()).append(",\"members\":[").append(String.join(",", rows))
                        .append("],\"ext_units\":[").append(String.join(",", units)).append("],\"contained_members\":[")
                        .append(String.join(",", contained)).append("]");
            }
            case MemberRef.Choice(Asn1Choice c) -> {
                ChoiceSpec sp = c.spec();
                List<String> rows = new ArrayList<>();
                for (int i = 0; i < sp.alternatives().size(); i++) {
                    AltMeta a = sp.alternatives().get(i);
                    MemberRef alt = choiceAlternative(factory, i);
                    Tag ownTag = alt instanceof MemberRef.Choice(Asn1Choice x) ? x.spec().ownTag() : null;
                    rows.add("{\"name\":" + jstr(a.name()) + "," + jtagging(a.ber(), ownTag, isUntaggedChoice(alt))
                            + ",\"optional\":false,\"constraints\":" + jconstraints(a.constraints())
                            + ",\"contained\":" + (a.contained() != null) + "}");
                }
                List<String> tags = sp.berTags().stream()
                        .sorted(Comparator.comparing(BerDispatch::tag, Tag.IDENTIFIER_ORDER))
                        .map(d -> "{\"tag\":" + jtag(d.tag()) + ",\"alt\":" + d.alt() + "}").toList();
                out.append("{\"name\":").append(jstr(sp.name())).append(",\"kind\":\"CHOICE\",\"tag\":")
                        .append(sp.ownTag() == null ? "null" : jtag(sp.ownTag())).append(",\"ext_at\":").append(sp.extAt())
                        .append(",\"range_bits\":").append(sp.rangeBits()).append(",\"alternatives\":[").append(String.join(",", rows))
                        .append("],\"ber_tags\":[").append(String.join(",", tags)).append("]");
            }
            case MemberRef.SeqOf(Asn1SeqOf q) -> {
                Tag tag = q.naturalTag();
                out.append("{\"name\":").append(jstr(q.ownXerName())).append(",\"kind\":\"")
                        .append(tag.number() == 17 ? "SET_OF" : "SEQUENCE_OF").append("\",\"tag\":").append(jtag(tag))
                        .append(",\"element_xer_tag\":").append(q.elemXerName() == null ? "null" : jstr(q.elemXerName()));
            }
            case MemberRef.Enumerated(EnumSlot ignored, EnumSpec e) -> {
                List<String> entries = e.entries().stream()
                        .map(x -> "{\"value\":" + x.value() + ",\"name\":" + jstr(x.name()) + "}").toList();
                out.append("{\"name\":").append(jstr(e.name())).append(",\"kind\":\"ENUMERATED\",\"extensible\":")
                        .append(e.extensible()).append(",\"root_count\":").append(e.rootCount()).append(",\"entries\":[")
                        .append(String.join(",", entries)).append("]");
            }
            // A builtin's tables carry no name of its own.
            case MemberRef.Primitive(Asn1Primitive p) -> out.append("{\"kind\":\"").append(primitiveKind(p)).append("\"");
            case MemberRef.Contained c -> out.append("{\"name\":").append(jstr(name)).append(",\"kind\":\"OCTET_STRING\"");
            case MemberRef.Absent a -> out.append("{\"name\":").append(jstr(name)).append(",\"kind\":\"UNSUPPORTED\"");
            case MemberRef.Unsupported u -> out.append("{\"name\":").append(jstr(name)).append(",\"kind\":\"UNSUPPORTED\"");
        }
        return out.append('}').toString();
    }

    static String jstr(String s) {
        StringBuilder out = new StringBuilder("\"");
        s.codePoints().forEach(c -> {
            if (c == '"' || c == '\\') {
                out.append('\\').appendCodePoint(c);
            } else if (c < 0x20) {
                out.append(String.format("\\u%04X", c));
            } else {
                out.appendCodePoint(c);
            }
        });
        return out.append('"').toString();
    }

    static String jtag(Tag t) {
        return "{\"class\":\"" + t.tagClass().name() + "\",\"number\":" + Integer.toUnsignedString(t.number())
                + ",\"constructed\":" + t.constructed() + "}";
    }

    /**
     * The constraint fields that carry meaning, so runtimes that leave
     * unused fields at different values still dump alike: the value bounds
     * of the INTEGER storage in use (the unsigned pair when set), only when
     * there is a bound; rangeBits only for a finite range (X.691 §10.5); the
     * upper SIZE bound only for a finite SIZE range; the alphabet only with
     * a FROM constraint (X.691 §27.5.4).
     */
    static String jconstraints(Constraints c) {
        boolean finite = (c.flags() & Constraints.CONSTRAINED) != 0;
        boolean bounded = finite || (c.flags() & Constraints.SEMI_CONSTRAINED) != 0;
        boolean u64 = c.lowerU64() != 0 || c.upperU64() != 0;
        String lower = !bounded ? "null" : u64 ? Long.toUnsignedString(c.lowerU64()) : Long.toString(c.lowerBound());
        String upper = !finite ? "null" : u64 ? Long.toUnsignedString(c.upperU64()) : Long.toString(c.upperBound());
        String rangeBits = finite ? Integer.toString(c.rangeBits()) : "null";
        String sizeUpper = (c.flags() & Constraints.SIZE_CONSTRAINED) != 0 ? Long.toString(c.sizeUpper()) : "null";
        StringBuilder alphabet = new StringBuilder();
        if (c.alphabetBits() != 0 && c.alphabet() != null) {
            for (byte b : c.alphabet()) {
                alphabet.append(String.format("%02X", b & 0xFF));
            }
        }
        return "{\"flags\":" + c.flags() + ",\"range_bits\":" + rangeBits + ",\"lower\":" + lower + ",\"upper\":" + upper
                + ",\"size_range_bits\":" + c.sizeRangeBits() + ",\"size_lower\":" + c.sizeLower() + ",\"size_upper\":"
                + sizeUpper + ",\"alphabet_bits\":" + c.alphabetBits() + ",\"alphabet\":\"" + alphabet + "\"}";
    }

    /**
     * The row's tag and framing: IMPLICIT and EXPLICIT carry the tag, a
     * delegating row or one pointing at its type's framing frames nothing
     * itself (NONE), and an untagged CHOICE has no tag at all
     * (UNTAGGED_CHOICE, X.680 §31.2.7).
     *
     * @param tag            the row's table tag, or null for a CHOICE alternative row
     * @param untaggedChoice whether a delegating row's value is an untagged CHOICE
     */
    static String jtagging(BerTagging ber, Tag tag, boolean untaggedChoice) {
        String tagging;
        Tag t;
        switch (ber) {
            case BerTagging.Implicit(Tag x) -> {
                tagging = "IMPLICIT";
                t = x;
            }
            case BerTagging.Explicit(Tag x) -> {
                tagging = "EXPLICIT";
                t = x;
            }
            case BerTagging.DelegateChoice d -> {
                tagging = "UNTAGGED_CHOICE";
                t = null;
            }
            case BerTagging.Delegate d -> {
                tagging = untaggedChoice ? "UNTAGGED_CHOICE" : "NONE";
                t = untaggedChoice ? null : tag;
            }
            case BerTagging.OfType(BerTagging f) -> {
                tagging = "NONE";
                t = tag != null ? tag : switch (f.resolve()) {
                    case BerTagging.Implicit(Tag x) -> x;
                    case BerTagging.Explicit(Tag x) -> x;
                    default -> null;
                };
            }
            case BerTagging.Unsupported u -> {
                tagging = "UNSUPPORTED";
                t = tag;
            }
        }
        return "\"tag\":" + (t == null ? "null" : jtag(t)) + ",\"tagging\":\"" + tagging + "\"";
    }

    /** Canonical kind name of a builtin: its X.693 element name, with ANY for the open type. */
    static String primitiveKind(Asn1Primitive p) {
        String n = p.xerElementName();
        return n.equals("Value") ? "ANY" : n;
    }

    private static boolean isUntaggedChoice(MemberRef m) {
        return m instanceof MemberRef.Choice(Asn1Choice c) && c.spec().ownTag() == null;
    }

    /**
     * Whether alternative {@code index}'s payload is itself an untagged
     * CHOICE. A value holds one alternative at a time, so it is selected on
     * a fresh value.
     */
    /**
     * Alternative {@code index} of a fresh value of a CHOICE type. A
     * {@code Delegate} row of a tagged CHOICE starts with that CHOICE's own
     * tag, which its row does not carry.
     */
    private static MemberRef choiceAlternative(Supplier<? extends AsMemberRef> factory, int index) {
        return factory.get().asMemberRef() instanceof MemberRef.Choice(Asn1Choice c) ? c.select(index) : MemberRef.ABSENT;
    }
}
