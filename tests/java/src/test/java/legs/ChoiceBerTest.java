package legs;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertThrows;

import gen.choice_ber.Auto;
import gen.choice_ber.Ext;
import gen.choice_ber.ExtRoot;
import gen.choice_ber.HoldsOwn;
import gen.choice_ber.Inner;
import gen.choice_ber.MyByte;
import gen.choice_ber.Nested;
import gen.choice_ber.Own;
import gen.choice_ber.Pick;
import gen.choice_ber.Plain;
import gen.choice_ber.Tagged;
import gen.choice_ber.Typed;
import io.github.schramp.gambasasn1.wire.ber.BerObject;
import io.github.schramp.gambasasn1.wire.ber.Tag;
import io.github.schramp.gambasasn1.wire.io.DecodeException;
import io.github.schramp.gambasasn1.wire.io.EncodeException;
import io.github.schramp.gambasasn1.wire.spec.AsMemberRef;
import io.github.schramp.gambasasn1.wire.spec.Asn1Choice;
import io.github.schramp.gambasasn1.wire.spec.Asn1Pdu;
import io.github.schramp.gambasasn1.wire.spec.ChoiceSpec;
import io.github.schramp.gambasasn1.wire.spec.MemberRef;
import io.github.schramp.gambasasn1.wire.types.Asn1Boolean;
import io.github.schramp.gambasasn1.wire.types.Asn1Ia5String;
import io.github.schramp.gambasasn1.wire.types.Asn1Integer;
import java.util.HexFormat;
import java.util.List;
import java.util.Map;
import java.util.function.Supplier;
import java.util.stream.Stream;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.MethodSource;

/**
 * CHOICE under BER (X.690 §8.13), against asn1c's DER for
 * tests/asn1/choice_ber_test.asn1: every vector decodes to the alternative
 * its XER names and re-encodes byte for byte.
 */
class ChoiceBerTest {
    static final Map<String, Supplier<Asn1Pdu>> TYPES = Map.ofEntries(
            Map.entry("Plain", Plain::new),
            Map.entry("Tagged", Tagged::new),
            Map.entry("Inner", Inner::new),
            Map.entry("Nested", Nested::new),
            Map.entry("Own", Own::new),
            Map.entry("HoldsOwn", HoldsOwn::new),
            Map.entry("Typed", Typed::new),
            Map.entry("Ext", Ext::new),
            Map.entry("ExtRoot", ExtRoot::new),
            Map.entry("Auto", Auto::new),
            Map.entry("Pick", Pick::new));

    static Stream<Vectors.Vector> vectors() {
        return Vectors.load("choice_ber_test.vectors").stream();
    }

    private static byte[] hex(String s) {
        return HexFormat.of().parseHex(s);
    }

    /** The alternative a vector's XER selects: the first element inside the type's own. */
    private static String xerAlternative(String xer) {
        int open = xer.indexOf('<', xer.indexOf('>') + 1) + 1;
        int end = open;
        while (Character.isLetterOrDigit(xer.charAt(end)) || xer.charAt(end) == '-') {
            end++;
        }
        return xer.substring(open, end);
    }

    @ParameterizedTest(name = "{0}")
    @MethodSource("vectors")
    void decodesAsn1cDerAndReencodesIt(Vectors.Vector vec) {
        Asn1Pdu v = TYPES.get(vec.type()).get();
        BerObject.decode(v, vec.der());
        Asn1Choice c = (Asn1Choice) v;
        assertEquals(xerAlternative(vec.xer()), c.spec().alternatives().get(c.activeIndex()).name());
        assertArrayEquals(vec.der(), BerObject.encode(v));
    }

    @Test
    void everyTypeHasAVector() {
        List<String> covered = vectors().map(Vectors.Vector::type).distinct().sorted().toList();
        assertEquals(TYPES.keySet().stream().sorted().toList(), covered);
    }

    @Test
    void alternativesSetByAccessorEncodeAsAsn1cDoes() {
        Plain p = new Plain();
        p.num(new Asn1Integer(5));
        assertArrayEquals(hex("020105"), BerObject.encode(p));

        Nested n = new Nested();
        Inner in = new Inner();
        in.s(new Asn1Ia5String("ab"));
        n.inner(in);
        assertArrayEquals(hex("16026162"), BerObject.encode(n));
        Inner w = new Inner();
        w.i(new Asn1Integer(300));
        n.wrapped(w);
        assertArrayEquals(hex("A3040202012C"), BerObject.encode(n));

        // [4] EXPLICIT around a tagged CHOICE keeps the CHOICE's own [5].
        HoldsOwn h = new HoldsOwn();
        Own o = new Own();
        o.y(new Asn1Boolean(false));
        h.tagged(o);
        assertArrayEquals(hex("A405A503010100"), BerObject.encode(h));
    }

    @Test
    void accessorsAnswerOnlyForTheSelectedAlternative() {
        Plain p = new Plain();
        BerObject.decode(p, hex("0101FF"));
        assertEquals(new Asn1Boolean(true), p.flag());
        assertNull(p.num());
        assertNull(p.text());
    }

    @Test
    void decodedValuesEqualConstructedOnes() {
        Typed t = new Typed();
        BerObject.decode(t, hex("020200FF"));
        Typed u = new Typed();
        MyByte b = new MyByte();
        b.value.set(255);
        u.byte_(b);
        assertEquals(u, t);
    }

    /** An extensible CHOICE keeps an alternative it does not know and replays it (X.680 §6). */
    @Test
    void unknownExtensionAlternativeIsKeptAndReplayed() {
        ExtRoot r = new ExtRoot();
        BerObject.decode(r, hex("0101FF"));
        assertEquals(-1, r.activeIndex());
        assertEquals(Tag.universal(1, false), r.unknownExtension().tag());
        assertArrayEquals(hex("FF"), r.unknownExtension().bytes());
        assertArrayEquals(hex("0101FF"), BerObject.encode(r));
    }

    @Test
    void malformedInputIsADecodeError() {
        // No alternative of a non-extensible CHOICE has this tag.
        assertThrows(DecodeException.class, () -> BerObject.decode(new Inner(), hex("0101FF")));
        // A tagged CHOICE without its own tag.
        assertThrows(DecodeException.class, () -> BerObject.decode(new Own(), hex("020101")));
        // Two values inside a tag that holds exactly one.
        assertThrows(DecodeException.class, () -> BerObject.decode(new Own(), hex("A506020101010100")));
        assertThrows(DecodeException.class, () -> BerObject.decode(new Plain(), new byte[0]));
    }

    @Test
    void anUnselectedValueIsAnEncodeError() {
        ExtRoot r = new ExtRoot();
        r.setUnknownExtension(new Asn1Choice.UnknownExtension(Tag.universal(1, false), hex("FF")));
        r.select(0);
        assertEquals(0, r.activeIndex());
        assertNull(r.unknownExtension());
        assertThrows(IllegalStateException.class,
                () -> new Plain().setUnknownExtension(new Asn1Choice.UnknownExtension(Tag.universal(1, false), hex("FF"))));
        Ext e = new Ext();
        e.setUnknownExtension(new Asn1Choice.UnknownExtension(Tag.universal(1, false), hex("FF")));
        e.a(new Asn1Integer(1));
        assertArrayEquals(hex("020101"), BerObject.encode(e));
        assertThrows(EncodeException.class, () -> BerObject.encode(new Unselected()));
    }

    /** A CHOICE value with nothing selected, as a decoder sees it before any input. */
    private static final class Unselected implements Asn1Choice, AsMemberRef {
        @Override
        public ChoiceSpec spec() {
            return Plain.SPEC;
        }

        @Override
        public int activeIndex() {
            return -1;
        }

        @Override
        public MemberRef getActive() {
            throw new AssertionError();
        }

        @Override
        public MemberRef select(int index) {
            throw new AssertionError();
        }

        @Override
        public void setUnknownExtension(UnknownExtension ext) {
        }

        @Override
        public UnknownExtension unknownExtension() {
            return null;
        }

        @Override
        public MemberRef asMemberRef() {
            return new MemberRef.Choice(this);
        }

        @Override
        public String ownElementXerName() {
            return "Plain";
        }
    }
}
