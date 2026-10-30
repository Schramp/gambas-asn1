package io.github.schramp.gambasasn1.wire.spec;

import static org.junit.jupiter.api.Assertions.assertEquals;

import io.github.schramp.gambasasn1.wire.ber.Tag;
import io.github.schramp.gambasasn1.wire.ber.UniversalTag;
import java.util.ArrayList;
import java.util.List;
import org.junit.jupiter.api.Test;

/**
 * The Java dump must be byte-identical to the other runtimes' dumps. Each
 * fixture below rebuilds by hand the tables of a type from tests/asn1, and
 * each expected line is the Rust runtime's dump of that same type.
 */
class TableDumpTest {

    private static final Constraints BYTE_RANGE =
            new Constraints(Constraints.CONSTRAINED, 8, 0, 255, 0, 0, 0, 0, 0, null, 0, null, 0, null, 0.0, 0.0);

    record TestInt(long value) implements Asn1Primitive {
        @Override
        public String xerElementName() {
            return "INTEGER";
        }
    }

    record TestBool(boolean value) implements Asn1Primitive {
        @Override
        public String xerElementName() {
            return "BOOLEAN";
        }
    }

    /** choice_test.asn1: {@code Alt2 ::= CHOICE { num MyByte, flag BOOLEAN }}. */
    static final class Alt2 implements AsMemberRef, Asn1Choice {
        static final ChoiceSpec SPEC = new ChoiceSpec("Alt2",
                List.of(new AltMeta("flag", new BerTagging.Implicit(Tag.universal(UniversalTag.BOOLEAN, false)), Constraints.UNCONSTRAINED, null),
                        new AltMeta("num", new BerTagging.Implicit(Tag.universal(UniversalTag.INTEGER, false)), BYTE_RANGE, null)),
                List.of(new BerDispatch(Tag.universal(UniversalTag.INTEGER, false), 1),
                        new BerDispatch(Tag.universal(UniversalTag.BOOLEAN, false), 0)),
                null, -1, 1, false);
        private int active = 0;
        private Asn1Primitive value = new TestBool(false);

        @Override public MemberRef asMemberRef() { return new MemberRef.Choice(this); }
        @Override public String ownElementXerName() { return "Alt2"; }
        @Override public ChoiceSpec spec() { return SPEC; }
        @Override public int activeIndex() { return active; }
        @Override public MemberRef getActive() { return value.asMemberRef(); }

        @Override
        public MemberRef select(int index) {
            active = index;
            value = index == 0 ? new TestBool(false) : new TestInt(0);
            return getActive();
        }

        @Override public void setUnknownExtension(UnknownExtension ext) { }
        @Override public UnknownExtension unknownExtension() { return null; }
    }

    /** A SEQUENCE whose members are all present, reached through {@code members}. */
    record TestSeq(SequenceSpec spec, List<MemberRef> members) implements AsMemberRef, Asn1Seq {
        @Override public MemberRef asMemberRef() { return new MemberRef.Composite(this); }
        @Override public String ownElementXerName() { return spec.name(); }
        @Override public MemberRef getMember(int index) { return members.get(index); }
        @Override public MemberRef presentMember(int index) { return members.get(index); }
        @Override public void setDefault(int index) { }
        @Override public boolean isDefaultEqual(int index) { return false; }
        @Override public long validate(int index) { return 0; }
    }

    private static SequenceSpec seq(String name, MemberMeta... members) {
        return new SequenceSpec(name, Tag.universal(UniversalTag.SEQUENCE, true), List.of(members), -1, 0, false,
                List.of(), List.of(), List.of());
    }

    /** enum_item_names_test.asn1: {@code EinEnum}. */
    record EinEnum(long v) implements AsMemberRef, EnumSlot {
        static final EnumSpec SPEC = new EnumSpec("EinEnum",
                List.of(new EnumEntry(0, "x"), new EnumEntry(1, "v"), new EnumEntry(2, "f"), new EnumEntry(3, "i"),
                        new EnumEntry(4, "s"), new EnumEntry(5, "value"), new EnumEntry(6, "self")),
                false, 7, 3);

        @Override public MemberRef asMemberRef() { return new MemberRef.Enumerated(this, SPEC); }
        @Override public String ownElementXerName() { return "EinEnum"; }
        @Override public long enumGet() { return v; }
        @Override public boolean enumSet(long value) { return false; }
    }

    /** enum_item_names_test.asn1: {@code EinRecList ::= SEQUENCE OF ...}. */
    static final class EinRecList implements AsMemberRef, Asn1SeqOf {
        private final List<EinEnum> elems = new ArrayList<>();

        @Override public MemberRef asMemberRef() { return new MemberRef.SeqOf(this); }
        @Override public String ownElementXerName() { return "EinRecList"; }
        @Override public Tag naturalTag() { return Tag.universal(UniversalTag.SEQUENCE, true); }
        @Override public String ownXerName() { return "EinRecList"; }
        @Override public int size() { return elems.size(); }
        @Override public MemberRef get(int index) { return elems.get(index).asMemberRef(); }

        @Override
        public MemberRef addDefault() {
            elems.add(new EinEnum(0));
            return get(elems.size() - 1);
        }

        @Override public String elemNaturalXerName(int index) { return "EinEnum"; }
        @Override public XerInstruction elemXerInstruction() { return XerInstruction.DEFAULT; }
    }

    private static final String NO_CONSTRAINTS = "{\"flags\":0,\"range_bits\":null,\"lower\":null,\"upper\":null,"
            + "\"size_range_bits\":0,\"size_lower\":0,\"size_upper\":null,\"alphabet_bits\":0,\"alphabet\":\"\"}";

    @Test
    void choice() {
        assertEquals("{\"name\":\"Alt2\",\"kind\":\"CHOICE\",\"tag\":null,\"ext_at\":-1,\"range_bits\":1,\"alternatives\":["
                + "{\"name\":\"flag\",\"tag\":{\"class\":\"UNIVERSAL\",\"number\":1,\"constructed\":false},\"tagging\":\"IMPLICIT\",\"optional\":false,\"constraints\":" + NO_CONSTRAINTS + ",\"contained\":false},"
                + "{\"name\":\"num\",\"tag\":{\"class\":\"UNIVERSAL\",\"number\":2,\"constructed\":false},\"tagging\":\"IMPLICIT\",\"optional\":false,\"constraints\":"
                + "{\"flags\":1,\"range_bits\":8,\"lower\":0,\"upper\":255,\"size_range_bits\":0,\"size_lower\":0,\"size_upper\":null,\"alphabet_bits\":0,\"alphabet\":\"\"},\"contained\":false}],"
                + "\"ber_tags\":[{\"tag\":{\"class\":\"UNIVERSAL\",\"number\":1,\"constructed\":false},\"alt\":0},"
                + "{\"tag\":{\"class\":\"UNIVERSAL\",\"number\":2,\"constructed\":false},\"alt\":1}]}",
                TableDump.dump(Alt2::new, "Alt2"));
    }

    @Test
    void sequenceWithUntaggedChoiceMember() {
        SequenceSpec spec = seq("HasAlt2", new MemberMeta("val", Tag.universal(UniversalTag.SEQUENCE, true), false,
                BerTagging.DELEGATE, Constraints.UNCONSTRAINED, XerInstruction.DEFAULT, null));
        assertEquals("{\"name\":\"HasAlt2\",\"kind\":\"SEQUENCE\",\"tag\":{\"class\":\"UNIVERSAL\",\"number\":16,\"constructed\":true},"
                + "\"ext_at\":-1,\"roms_count\":0,\"members\":[{\"name\":\"val\",\"tag\":null,\"tagging\":\"UNTAGGED_CHOICE\",\"optional\":false,"
                + "\"constraints\":" + NO_CONSTRAINTS + ",\"xer_instruction\":\"DEFAULT\",\"contained\":false}],\"ext_units\":[],\"contained_members\":[]}",
                TableDump.dump(() -> new TestSeq(spec, List.of(new Alt2().asMemberRef())), "HasAlt2"));
    }

    @Test
    void sequenceWithExplicitMember() {
        Tag ctx0 = Tag.context(0, true);
        SequenceSpec spec = seq("WithExplicitInt", new MemberMeta("num", ctx0, false, new BerTagging.Explicit(ctx0),
                Constraints.UNCONSTRAINED, XerInstruction.DEFAULT, null));
        assertEquals("{\"name\":\"WithExplicitInt\",\"kind\":\"SEQUENCE\",\"tag\":{\"class\":\"UNIVERSAL\",\"number\":16,\"constructed\":true},"
                + "\"ext_at\":-1,\"roms_count\":0,\"members\":[{\"name\":\"num\",\"tag\":{\"class\":\"CONTEXT\",\"number\":0,\"constructed\":true},"
                + "\"tagging\":\"EXPLICIT\",\"optional\":false,\"constraints\":" + NO_CONSTRAINTS + ",\"xer_instruction\":\"DEFAULT\",\"contained\":false}],"
                + "\"ext_units\":[],\"contained_members\":[]}",
                TableDump.dump(() -> new TestSeq(spec, List.of(new TestInt(0).asMemberRef())), "WithExplicitInt"));
    }

    @Test
    void memberFramedByItsType() {
        Tag app13 = new Tag(io.github.schramp.gambasasn1.wire.ber.TagClass.APPLICATION, 13, true);
        BerTagging typeFraming = new BerTagging.Explicit(app13);
        SequenceSpec spec = seq("Tagged", new MemberMeta("w", app13, false, new BerTagging.OfType(typeFraming),
                Constraints.UNCONSTRAINED, XerInstruction.DEFAULT, null));
        String line = TableDump.dump(() -> new TestSeq(spec, List.of(new TestInt(0).asMemberRef())), "Tagged");
        assertEquals(true, line.contains("\"tag\":{\"class\":\"APPLICATION\",\"number\":13,\"constructed\":true},\"tagging\":\"NONE\""), line);
    }

    @Test
    void enumerated() {
        assertEquals("{\"name\":\"EinEnum\",\"kind\":\"ENUMERATED\",\"extensible\":false,\"root_count\":7,\"entries\":["
                + "{\"value\":0,\"name\":\"x\"},{\"value\":1,\"name\":\"v\"},{\"value\":2,\"name\":\"f\"},{\"value\":3,\"name\":\"i\"},"
                + "{\"value\":4,\"name\":\"s\"},{\"value\":5,\"name\":\"value\"},{\"value\":6,\"name\":\"self\"}]}",
                TableDump.dump(() -> new EinEnum(0), "EinEnum"));
    }

    @Test
    void sequenceOf() {
        assertEquals("{\"name\":\"EinRecList\",\"kind\":\"SEQUENCE_OF\",\"tag\":{\"class\":\"UNIVERSAL\",\"number\":16,\"constructed\":true},"
                + "\"element_xer_tag\":null}", TableDump.dump(EinRecList::new, "EinRecList"));
    }

    @Test
    void builtinCarriesOnlyItsKind() {
        assertEquals("{\"kind\":\"INTEGER\"}", TableDump.dump(() -> new TestInt(0), "MyByte"));
    }

    @Test
    void jsonStringEscapes() {
        assertEquals("\"a\\\"b\\\\c\\u0001\"", TableDump.jstr("a\"b\\c\u0001"));
    }
}
