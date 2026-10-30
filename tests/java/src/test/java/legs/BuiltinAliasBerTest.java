package legs;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;

import gen.builtin_alias_ber.Anything;
import gen.builtin_alias_ber.Big;
import gen.builtin_alias_ber.Bits;
import gen.builtin_alias_ber.Bmp;
import gen.builtin_alias_ber.Byte;
import gen.builtin_alias_ber.Color;
import gen.builtin_alias_ber.Counter;
import gen.builtin_alias_ber.Descriptor;
import gen.builtin_alias_ber.ExplicitAny;
import gen.builtin_alias_ber.ExplicitBits;
import gen.builtin_alias_ber.ExplicitColor;
import gen.builtin_alias_ber.ExplicitFlag;
import gen.builtin_alias_ber.ExplicitGenTime;
import gen.builtin_alias_ber.ExplicitNothing;
import gen.builtin_alias_ber.ExplicitNum;
import gen.builtin_alias_ber.ExplicitOctets;
import gen.builtin_alias_ber.ExplicitOid;
import gen.builtin_alias_ber.ExplicitReal;
import gen.builtin_alias_ber.ExplicitRelOid;
import gen.builtin_alias_ber.ExplicitUtf8;
import gen.builtin_alias_ber.ExtColor;
import gen.builtin_alias_ber.FixedOctets;
import gen.builtin_alias_ber.Flag;
import gen.builtin_alias_ber.GenTime;
import gen.builtin_alias_ber.General;
import gen.builtin_alias_ber.Graphic;
import gen.builtin_alias_ber.Hyphen_Flag;
import gen.builtin_alias_ber.Ia5;
import gen.builtin_alias_ber.ImplicitBits;
import gen.builtin_alias_ber.ImplicitColor;
import gen.builtin_alias_ber.ImplicitCounter;
import gen.builtin_alias_ber.ImplicitFlag;
import gen.builtin_alias_ber.ImplicitIa5;
import gen.builtin_alias_ber.ImplicitNothing;
import gen.builtin_alias_ber.ImplicitNum;
import gen.builtin_alias_ber.ImplicitOctets;
import gen.builtin_alias_ber.ImplicitOid;
import gen.builtin_alias_ber.ImplicitReal;
import gen.builtin_alias_ber.ImplicitRelOid;
import gen.builtin_alias_ber.ImplicitUtc;
import gen.builtin_alias_ber.Named;
import gen.builtin_alias_ber.NamedBits;
import gen.builtin_alias_ber.NegColor;
import gen.builtin_alias_ber.Nothing;
import gen.builtin_alias_ber.Num;
import gen.builtin_alias_ber.Numeric;
import gen.builtin_alias_ber.Octets;
import gen.builtin_alias_ber.Oid;
import gen.builtin_alias_ber.Printable;
import gen.builtin_alias_ber.Real;
import gen.builtin_alias_ber.RelOid;
import gen.builtin_alias_ber.SizedBits;
import gen.builtin_alias_ber.SizedOctets;
import gen.builtin_alias_ber.T61;
import gen.builtin_alias_ber.Teletex;
import gen.builtin_alias_ber.Universal;
import gen.builtin_alias_ber.Utc;
import gen.builtin_alias_ber.Utf8;
import gen.builtin_alias_ber.Videotex;
import gen.builtin_alias_ber.Visible;
import io.github.schramp.gambasasn1.wire.ber.BerObject;
import io.github.schramp.gambasasn1.wire.io.DecodeException;
import io.github.schramp.gambasasn1.wire.spec.AsMemberRef;
import io.github.schramp.gambasasn1.wire.spec.EnumEntry;
import io.github.schramp.gambasasn1.wire.spec.EnumSlot;
import io.github.schramp.gambasasn1.wire.spec.MemberRef;
import io.github.schramp.gambasasn1.wire.types.Asn1Any;
import io.github.schramp.gambasasn1.wire.types.Asn1Arcs;
import io.github.schramp.gambasasn1.wire.types.Asn1BitString;
import io.github.schramp.gambasasn1.wire.types.Asn1Boolean;
import io.github.schramp.gambasasn1.wire.types.Asn1CharString;
import io.github.schramp.gambasasn1.wire.types.Asn1GeneralString;
import io.github.schramp.gambasasn1.wire.types.Asn1GraphicString;
import io.github.schramp.gambasasn1.wire.types.Asn1Integer;
import io.github.schramp.gambasasn1.wire.types.Asn1OctetString;
import io.github.schramp.gambasasn1.wire.types.Asn1Real;
import io.github.schramp.gambasasn1.wire.types.Asn1T61String;
import io.github.schramp.gambasasn1.wire.types.Asn1UInteger;
import io.github.schramp.gambasasn1.wire.types.Asn1VideotexString;
import java.util.HexFormat;
import java.util.List;
import java.util.Map;
import java.util.function.Supplier;
import java.util.stream.Stream;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.MethodSource;

/**
 * Java leg of builtin_alias_ber_test.asn1: every generated type assignment
 * (BOOLEAN, NULL, INTEGER, ENUMERATED, OCTET STRING, BIT STRING, character strings) encodes asn1c's DER byte for byte and
 * decodes it back, under its natural tag, IMPLICIT and EXPLICIT (X.690 §8.14).
 */
class BuiltinAliasBerTest {
    private static final Map<String, Supplier<AsMemberRef>> TYPES = Map.ofEntries(
            Map.entry("Flag", Flag::new),
            Map.entry("ImplicitFlag", ImplicitFlag::new),
            Map.entry("ExplicitFlag", ExplicitFlag::new),
            Map.entry("Hyphen-Flag", Hyphen_Flag::new),
            Map.entry("Nothing", Nothing::new),
            Map.entry("ImplicitNothing", ImplicitNothing::new),
            Map.entry("ExplicitNothing", ExplicitNothing::new),
            Map.entry("Num", Num::new),
            Map.entry("Byte", Byte::new),
            Map.entry("Named", Named::new),
            Map.entry("ImplicitNum", ImplicitNum::new),
            Map.entry("ExplicitNum", ExplicitNum::new),
            Map.entry("Color", Color::new),
            Map.entry("ExtColor", ExtColor::new),
            Map.entry("NegColor", NegColor::new),
            Map.entry("ImplicitColor", ImplicitColor::new),
            Map.entry("ExplicitColor", ExplicitColor::new),
            Map.entry("Octets", Octets::new),
            Map.entry("SizedOctets", SizedOctets::new),
            Map.entry("FixedOctets", FixedOctets::new),
            Map.entry("ImplicitOctets", ImplicitOctets::new),
            Map.entry("ExplicitOctets", ExplicitOctets::new),
            Map.entry("Bits", Bits::new),
            Map.entry("SizedBits", SizedBits::new),
            Map.entry("NamedBits", NamedBits::new),
            Map.entry("ImplicitBits", ImplicitBits::new),
            Map.entry("ExplicitBits", ExplicitBits::new),
            Map.entry("Utf8", Utf8::new),
            Map.entry("Numeric", Numeric::new),
            Map.entry("Printable", Printable::new),
            Map.entry("Teletex", Teletex::new),
            Map.entry("T61", T61::new),
            Map.entry("Videotex", Videotex::new),
            Map.entry("Ia5", Ia5::new),
            Map.entry("Graphic", Graphic::new),
            Map.entry("Visible", Visible::new),
            Map.entry("General", General::new),
            Map.entry("Descriptor", Descriptor::new),
            Map.entry("Bmp", Bmp::new),
            Map.entry("Universal", Universal::new),
            Map.entry("ImplicitIa5", ImplicitIa5::new),
            Map.entry("ExplicitUtf8", ExplicitUtf8::new),
            Map.entry("Oid", Oid::new),
            Map.entry("ImplicitOid", ImplicitOid::new),
            Map.entry("ExplicitOid", ExplicitOid::new),
            Map.entry("RelOid", RelOid::new),
            Map.entry("ImplicitRelOid", ImplicitRelOid::new),
            Map.entry("ExplicitRelOid", ExplicitRelOid::new),
            Map.entry("Utc", Utc::new),
            Map.entry("ImplicitUtc", ImplicitUtc::new),
            Map.entry("GenTime", GenTime::new),
            Map.entry("ExplicitGenTime", ExplicitGenTime::new),
            Map.entry("Real", Real::new),
            Map.entry("ImplicitReal", ImplicitReal::new),
            Map.entry("ExplicitReal", ExplicitReal::new),
            Map.entry("Counter", Counter::new),
            Map.entry("Big", Big::new),
            Map.entry("ImplicitCounter", ImplicitCounter::new),
            Map.entry("Anything", Anything::new));

    static Stream<Vectors.Vector> vectors() {
        return Vectors.load("builtin_alias_ber_test.vectors").stream();
    }

    /**
     * Sets {@code v} to the value a vector's XER names (X.693): BOOLEAN's
     * {@code <true/>}, an INTEGER's number, an ENUMERATED item's empty element,
     * OCTET STRING hex digits, BIT STRING binary digits, character string text,
     * OBJECT IDENTIFIER and RELATIVE-OID dotted arcs, a REAL number or special-value element,
     * ANY as the hex digits of its encoding.
     */
    private static void setFromXer(AsMemberRef v, String xer) {
        if (xer.endsWith("/>") && xer.indexOf('>') == xer.length() - 1) {
            return;  // an empty element: NULL
        }
        String inner = xer.substring(xer.indexOf('>') + 1, xer.lastIndexOf('<'));
        switch (v.asMemberRef()) {
            case MemberRef.Primitive(Asn1Boolean b) -> b.set(inner.equals("<true/>"));
            case MemberRef.Primitive(Asn1Integer i) -> i.set(Long.parseLong(inner));
            case MemberRef.Primitive(Asn1UInteger u) -> u.set(Long.parseUnsignedLong(inner));
            case MemberRef.Primitive(Asn1Any any) -> any.set(HexFormat.of().parseHex(inner));
            case MemberRef.Primitive(Asn1OctetString o) -> o.set(HexFormat.of().parseHex(inner));
            // asn1c writes these kinds' XER as hex digits, like an OCTET STRING.
            case MemberRef.Primitive(Asn1CharString c) when c instanceof Asn1T61String || c instanceof Asn1VideotexString
                    || c instanceof Asn1GraphicString || c instanceof Asn1GeneralString ->
                c.setOctets(HexFormat.of().parseHex(inner));
            case MemberRef.Primitive(Asn1CharString c) -> c.set(inner);
            case MemberRef.Primitive(Asn1Real r) -> r.set(switch (inner) {
                case "<PLUS-INFINITY/>" -> Double.POSITIVE_INFINITY;
                case "<MINUS-INFINITY/>" -> Double.NEGATIVE_INFINITY;
                case "<NOT-A-NUMBER/>" -> Double.NaN;
                default -> Double.parseDouble(inner);
            });
            case MemberRef.Primitive(Asn1Arcs a) ->
                a.set(java.util.Arrays.stream(inner.split("\\.")).mapToLong(Long::parseLong).toArray());
            case MemberRef.Primitive(Asn1BitString b) -> {
                byte[] packed = new byte[(inner.length() + 7) / 8];
                for (int k = 0; k < inner.length(); k++) {
                    if (inner.charAt(k) == '1') {
                        packed[k / 8] |= (byte) (0x80 >>> (k % 8));
                    }
                }
                b.set(packed, packed.length * 8 - inner.length());
            }
            case MemberRef.Enumerated(EnumSlot slot, var spec) -> {
                String item = inner.substring(1, inner.length() - 2);
                long code = spec.entries().stream().filter(e -> e.name().equals(item)).mapToLong(EnumEntry::value)
                        .findFirst().orElseThrow();
                assertEquals(true, slot.enumSet(code));
            }
            default -> {
            }
        }
    }

    @ParameterizedTest(name = "{0}")
    @MethodSource("vectors")
    void encodesAsAsn1cDoes(Vectors.Vector vec) {
        AsMemberRef v = TYPES.get(vec.type()).get();
        setFromXer(v, vec.xer());
        assertArrayEquals(vec.der(), BerObject.encode(v));
    }

    @ParameterizedTest(name = "{0}")
    @MethodSource("vectors")
    void decodesAsn1cDer(Vectors.Vector vec) {
        AsMemberRef v = TYPES.get(vec.type()).get();
        BerObject.decode(v, vec.der());
        AsMemberRef expected = TYPES.get(vec.type()).get();
        setFromXer(expected, vec.xer());
        assertEquals(expected.asMemberRef(), v.asMemberRef());
        assertArrayEquals(vec.der(), BerObject.encode(v));
    }

    @Test
    void everyTypeHasAVector() {
        List<String> covered = vectors().map(Vectors.Vector::type).distinct().sorted().toList();
        assertEquals(TYPES.keySet().stream().sorted().toList(), covered);
    }

    /**
     * {@code [21] EXPLICIT ANY}: asn1c drops the EXPLICIT tag of a tagged ANY
     * type assignment, so this type has no asn1c vector. X.690 §8.14 wraps
     * the captured encoding, as the C++ runtime does.
     */
    @Test
    void explicitAnyWrapsTheCapturedEncoding() {
        ExplicitAny v = new ExplicitAny();
        v.value.set(HexFormat.of().parseHex("0101FF"));
        byte[] der = HexFormat.of().parseHex("B5030101FF");
        assertArrayEquals(der, BerObject.encode(v));
        ExplicitAny back = new ExplicitAny();
        BerObject.decode(back, der);
        assertEquals(v.asMemberRef(), back.asMemberRef());
    }

    @Test
    void ownXerNameIsTheAsn1Name() {
        assertEquals("Hyphen-Flag", new Hyphen_Flag().ownElementXerName());
        assertEquals("ImplicitNothing", new ImplicitNothing().ownElementXerName());
    }

    @Test
    void namedNumbersAndItems() {
        assertEquals(-1L, Named.minus_one);
        Color c = new Color();
        assertEquals(Color.Value.red, c.get());
        c.set(Color.Value.blue);
        assertEquals(5L, c.enumGet());
        assertEquals(false, c.enumSet(2));
        assertEquals(Color.Value.blue, c.get());
    }

    @Test
    void stringTypesCarryTheirSizeTable() {
        assertEquals(2L, SizedOctets.CONSTRAINTS.sizeLower());
        assertEquals(4L, SizedOctets.CONSTRAINTS.sizeUpper());
        assertEquals(Long.MAX_VALUE, Octets.CONSTRAINTS.sizeUpper());
        assertEquals(true, (NamedBits.CONSTRAINTS.flags() & io.github.schramp.gambasasn1.wire.spec.Constraints.NAMED_BITS) != 0);
        assertEquals(true, (SizedBits.CONSTRAINTS.flags() & io.github.schramp.gambasasn1.wire.spec.Constraints.EXTENSIBLE) != 0);
    }

    @Test
    void charStringsAreText() {
        Bmp b = new Bmp();
        b.value.set("B\u00e9\u20ac");
        assertArrayEquals(HexFormat.of().parseHex("1E06004200E920AC"), BerObject.encode(b));
        assertEquals(8L, Printable.CONSTRAINTS.sizeUpper());
    }

    @Test
    void unknownEnumeratedValueIsRejected() {
        assertThrows(DecodeException.class, () -> BerObject.decode(new Color(), new byte[] {0x0A, 0x01, 0x02}));
        assertThrows(DecodeException.class, () -> BerObject.decode(new ExtColor(), new byte[] {0x0A, 0x01, 0x05}));
    }

    @Test
    void anotherTypesTagIsRejected() {
        byte[] flag = BerObject.encode(new Flag());
        assertThrows(DecodeException.class, () -> BerObject.decode(new ImplicitFlag(), flag));
        assertThrows(DecodeException.class, () -> BerObject.decode(new ExplicitFlag(), flag));
        assertThrows(DecodeException.class, () -> BerObject.decode(new ImplicitNothing(), BerObject.encode(new Nothing())));
        assertThrows(DecodeException.class, () -> BerObject.decode(new Color(), BerObject.encode(new Num())));
        assertThrows(DecodeException.class, () -> BerObject.decode(new ExplicitColor(), BerObject.encode(new Color())));
    }
}
