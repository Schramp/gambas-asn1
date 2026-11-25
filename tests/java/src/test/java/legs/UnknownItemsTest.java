package legs;

import static java.nio.charset.StandardCharsets.UTF_8;
import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertThrows;

import gen.choice_unknown.MsgV1;
import gen.choice_unknown.MsgV2;
import gen.choice_unknown.MsgV2D;
import gen.enum_unknown.ColorV1;
import gen.enum_unknown.ColorV2;
import gen.enum_unknown.FixedColor;
import gen.enum_unknown.PaletteV1;
import io.github.schramp.gambasasn1.wire.ber.BerObject;
import io.github.schramp.gambasasn1.wire.io.DecodeException;
import io.github.schramp.gambasasn1.wire.io.EncodeException;
import io.github.schramp.gambasasn1.wire.jer.JerObject;
import io.github.schramp.gambasasn1.wire.per.PerObject;
import io.github.schramp.gambasasn1.wire.spec.Asn1Choice;
import io.github.schramp.gambasasn1.wire.spec.EnumUnknown;
import io.github.schramp.gambasasn1.wire.types.Asn1Boolean;
import io.github.schramp.gambasasn1.wire.types.Asn1Integer;
import io.github.schramp.gambasasn1.wire.xer.XerObject;
import org.junit.jupiter.api.Test;

/**
 * Items of a newer schema version (X.680 §52.1; enum_unknown_test.asn1,
 * choice_unknown_test.asn1): a version-2 value decoded with the version-1
 * type is kept, re-encodes unchanged in the codec it came from, and fails
 * to encode elsewhere with the same message as the C++ and Rust runtimes.
 */
class UnknownItemsTest {
    private static ColorV2 v2(ColorV2.Value item) {
        ColorV2 c = new ColorV2();
        c.set(item);
        return c;
    }

    @Test
    void perUnknownOrdinalIsKeptAndRelayed() throws DecodeException {
        byte[] wire = PerObject.encode(v2(ColorV2.Value.yellow));
        ColorV1 v1 = new ColorV1();
        PerObject.decode(v1, wire);
        assertEquals(EnumUnknown.ofOrdinal(2), v1.unknown());
        assertNull(v1.get());
        assertArrayEquals(wire, PerObject.encode(v1));
        assertEquals("ENUMERATED ColorV1: extension item #2 of a newer schema version has no BER encoding",
                assertThrows(EncodeException.class, () -> BerObject.encode(v1)).getMessage());
        assertThrows(EncodeException.class, () -> XerObject.encode(v1));
        assertThrows(EncodeException.class, () -> JerObject.encode(v1));
        v1.set(ColorV1.Value.green);
        assertNull(v1.unknown());
        assertEquals(ColorV1.Value.green, v1.get());
    }

    @Test
    void berUnknownValueIsKeptAndRelayed() throws DecodeException {
        byte[] wire = BerObject.encode(v2(ColorV2.Value.magenta));
        ColorV1 v1 = new ColorV1();
        BerObject.decode(v1, wire);
        assertEquals(EnumUnknown.ofValue(10), v1.unknown());
        assertArrayEquals(wire, BerObject.encode(v1));
        assertEquals("ENUMERATED ColorV1: value 10 of a newer schema version has no PER encoding",
                assertThrows(EncodeException.class, () -> PerObject.encode(v1)).getMessage());
        assertThrows(DecodeException.class, () -> BerObject.decode(new FixedColor(), wire));
    }

    @Test
    void xerAndJerUnknownIdentifierIsKept() throws DecodeException {
        PaletteV1 p = new PaletteV1();
        XerObject.decode(p, "<PaletteV1><red/><yellow/></PaletteV1>".getBytes(UTF_8));
        assertEquals(2, p.size());
        assertEquals(EnumUnknown.ofIdentifier(), p.items().get(1).unknown());
        assertEquals("ENUMERATED ColorV1: an unknown identifier of a newer schema version has no XER encoding",
                assertThrows(EncodeException.class, () -> XerObject.encode(p)).getMessage());
        ColorV1 j = new ColorV1();
        JerObject.decode(j, "\"yellow\"".getBytes(UTF_8));
        assertEquals(EnumUnknown.ofIdentifier(), j.unknown());
        assertThrows(DecodeException.class, () -> XerObject.decode(new FixedColor(), "<FixedColor><yellow/></FixedColor>".getBytes(UTF_8)));
        assertThrows(DecodeException.class, () -> JerObject.decode(new FixedColor(), "\"yellow\"".getBytes(UTF_8)));
    }

    private static MsgV2 v2d() {
        MsgV2D d = new MsgV2D();
        d.x(new Asn1Integer(300));
        d.y(new Asn1Boolean(true));
        MsgV2 m = new MsgV2();
        m.d(d);
        return m;
    }

    @Test
    void berUnknownAlternativeIsRelayed() throws DecodeException {
        byte[] wire = BerObject.encode(v2d());
        MsgV1 m = new MsgV1();
        BerObject.decode(m, wire);
        assertEquals(Asn1Choice.UnknownExtension.Origin.BER, m.unknownExtension().origin());
        assertArrayEquals(wire, BerObject.encode(m));
        assertEquals("CHOICE MsgV1: extension alternative of a newer schema version, read from BER, has no PER encoding",
                assertThrows(EncodeException.class, () -> PerObject.encode(m)).getMessage());
    }

    @Test
    void perUnknownAlternativeIsRelayed() throws DecodeException {
        byte[] wire = PerObject.encode(v2d());
        MsgV1 m = new MsgV1();
        PerObject.decode(m, wire);
        assertEquals(Asn1Choice.UnknownExtension.Origin.PER, m.unknownExtension().origin());
        assertEquals(1, m.unknownExtension().index());
        assertArrayEquals(wire, PerObject.encode(m));
        assertEquals("CHOICE MsgV1: extension alternative of a newer schema version, read from PER, has no BER encoding",
                assertThrows(EncodeException.class, () -> BerObject.encode(m)).getMessage());
    }
}
