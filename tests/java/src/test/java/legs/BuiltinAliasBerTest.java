package legs;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;

import gen.builtin_alias_ber.Bits;
import gen.builtin_alias_ber.Byte;
import gen.builtin_alias_ber.Color;
import gen.builtin_alias_ber.ExplicitBits;
import gen.builtin_alias_ber.ExplicitColor;
import gen.builtin_alias_ber.ExplicitFlag;
import gen.builtin_alias_ber.ExplicitNothing;
import gen.builtin_alias_ber.ExplicitNum;
import gen.builtin_alias_ber.ExplicitOctets;
import gen.builtin_alias_ber.ExtColor;
import gen.builtin_alias_ber.FixedOctets;
import gen.builtin_alias_ber.Flag;
import gen.builtin_alias_ber.Hyphen_Flag;
import gen.builtin_alias_ber.ImplicitBits;
import gen.builtin_alias_ber.ImplicitColor;
import gen.builtin_alias_ber.ImplicitFlag;
import gen.builtin_alias_ber.ImplicitNothing;
import gen.builtin_alias_ber.ImplicitNum;
import gen.builtin_alias_ber.ImplicitOctets;
import gen.builtin_alias_ber.Named;
import gen.builtin_alias_ber.NamedBits;
import gen.builtin_alias_ber.NegColor;
import gen.builtin_alias_ber.Nothing;
import gen.builtin_alias_ber.Num;
import gen.builtin_alias_ber.Octets;
import gen.builtin_alias_ber.SizedBits;
import gen.builtin_alias_ber.SizedOctets;
import io.github.schramp.gambasasn1.wire.ber.BerObject;
import io.github.schramp.gambasasn1.wire.io.DecodeException;
import io.github.schramp.gambasasn1.wire.spec.AsMemberRef;
import io.github.schramp.gambasasn1.wire.spec.EnumEntry;
import io.github.schramp.gambasasn1.wire.spec.EnumSlot;
import io.github.schramp.gambasasn1.wire.spec.MemberRef;
import io.github.schramp.gambasasn1.wire.types.Asn1BitString;
import io.github.schramp.gambasasn1.wire.types.Asn1Boolean;
import io.github.schramp.gambasasn1.wire.types.Asn1Integer;
import io.github.schramp.gambasasn1.wire.types.Asn1OctetString;
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
 * (BOOLEAN, NULL, INTEGER, ENUMERATED, OCTET STRING, BIT STRING) encodes asn1c's DER byte for byte and
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
            Map.entry("ExplicitBits", ExplicitBits::new));

    static Stream<Vectors.Vector> vectors() {
        return Vectors.load("builtin_alias_ber_test.vectors").stream();
    }

    /**
     * Sets {@code v} to the value a vector's XER names (X.693): BOOLEAN's
     * {@code <true/>}, an INTEGER's number, an ENUMERATED item's empty element,
     * OCTET STRING hex digits, BIT STRING binary digits.
     */
    private static void setFromXer(AsMemberRef v, String xer) {
        if (xer.endsWith("/>") && xer.indexOf('>') == xer.length() - 1) {
            return;  // an empty element: NULL
        }
        String inner = xer.substring(xer.indexOf('>') + 1, xer.lastIndexOf('<'));
        switch (v.asMemberRef()) {
            case MemberRef.Primitive(Asn1Boolean b) -> b.set(inner.equals("<true/>"));
            case MemberRef.Primitive(Asn1Integer i) -> i.set(Long.parseLong(inner));
            case MemberRef.Primitive(Asn1OctetString o) -> o.set(HexFormat.of().parseHex(inner));
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
