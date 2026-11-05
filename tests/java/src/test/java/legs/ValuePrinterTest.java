package legs;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import gen.containing.Holder;
import gen.seqof_ber.Points;
import gen.sequence_ber.Opt;
import gen.sequence_ber.Refs;
import io.github.schramp.gambasasn1.wire.ber.BerObject;
import io.github.schramp.gambasasn1.wire.ber.BerReader;
import io.github.schramp.gambasasn1.wire.print.ValuePrinter;
import io.github.schramp.gambasasn1.wire.types.Asn1BitString;
import io.github.schramp.gambasasn1.wire.types.Asn1Ia5String;
import io.github.schramp.gambasasn1.wire.types.Asn1ObjectIdentifier;
import io.github.schramp.gambasasn1.wire.types.Asn1OctetString;
import io.github.schramp.gambasasn1.wire.types.Asn1Real;
import io.github.schramp.gambasasn1.wire.types.Asn1Utf8String;
import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.HexFormat;
import org.junit.jupiter.api.Test;
import org.opentest4j.AssertionFailedError;

/** The value printer's layout, over values decoded from asn1c's encodings. */
class ValuePrinterTest {
    private static byte[] hex(String s) {
        return HexFormat.of().parseHex(s);
    }

    @Test
    void sequenceChoiceAndEnumeratedLayout() {
        Refs v = new Refs();
        BerObject.decode(v, hex("30320A010202010061030101006D030201FB300602010302010416017AA5030101FFA403020109"
                + "160171A6083006020105020106"));
        assertEquals("""
                {
                  color blue,
                  byte 0,
                  tbool FALSE,
                  texp -5,
                  point {
                    x 3,
                    y 4
                  },
                  pick s : "z",
                  own y : TRUE,
                  tpick i : 9,
                  opick s : "q",
                  opoint {
                    x 5,
                    y 6
                  }
                }""", ValuePrinter.print(v));
        assertEquals(ValuePrinter.print(v), v.toString());
    }

    @Test
    void absentMembersAndSequenceOfElements() {
        Opt o = new Opt();
        BerObject.decode(o, BerObject.encode(o));
        assertEquals("""
                {
                  -- a absent
                  b FALSE
                  -- c absent
                }""", o.toString());
        Points p = new Points();
        BerObject.decode(p, hex("301030060201010201023006020103020104"));
        assertEquals("""
                {
                  /* [0] */ {
                    x 1,
                    y 2
                  },
                  /* [1] */ {
                    x 3,
                    y 4
                  }
                }""", p.toString());
        assertEquals("{}", new Points().toString());
    }

    @Test
    void containedValuesShowTheInnerValueOrTheirStatus() {
        Holder h = new Holder();
        BerObject.decode(h, hex("30218001028101FF8205300380010583030102038400850B30098002FED48103616263"));
        String s = h.toString();
        assertTrue(s.contains("  kind scrambled,\n"), s);
        assertTrue(s.contains("  viaConstraint 'FF'H /* contained, failed: "), s);
        assertTrue(s.contains("  viaAlias CONTAINING {\n    id 5\n    -- name absent\n  },\n"), s);
        assertTrue(s.contains("  viaConfig '010203'H /* contained, skipped"), s);
        assertTrue(s.contains("  raw ''H,\n"), s);
        assertTrue(s.contains("  viaSized CONTAINING {\n    id -300,\n    name \"abc\"\n  }\n"), s);
    }

    @Test
    void primitivesAndCutOffs() {
        ValuePrinter small = new ValuePrinter(4, 5);
        Asn1OctetString o = new Asn1OctetString();
        o.set(hex("0102030405"));
        assertEquals("'01020304...'H /* 5 octets */", small.format(o));
        o.set("AB".getBytes(java.nio.charset.StandardCharsets.US_ASCII));
        assertEquals("'4142'H /* \"AB\" */", small.format(o));
        Asn1Ia5String t = new Asn1Ia5String();
        t.set("say \"hi\"\n");
        assertEquals("\"say \"\"\" /* cut off, 9 characters */", small.format(t));
        assertEquals("\"say \"\"hi\"\".\"", ValuePrinter.print(t));
        Asn1Utf8String u = new Asn1Utf8String();
        u.set("é€");
        assertEquals("\"é€\"", ValuePrinter.print(u));
        assertEquals("'1010'B", ValuePrinter.print(new Asn1BitString(new byte[] {(byte) 0xA0}, 4)));
        assertEquals("{ 0 4 0 2 2 5 1 31 }", ValuePrinter.print(new Asn1ObjectIdentifier(0, 4, 0, 2, 2, 5, 1, 31)));
        assertEquals("2.5", ValuePrinter.print(new Asn1Real(2.5)));
        assertEquals("PLUS-INFINITY", ValuePrinter.print(new Asn1Real(Double.POSITIVE_INFINITY)));
    }

    @Test
    void everyEtsiSampleRecordPrints() throws IOException {
        BerReader r = new BerReader(Files.readAllBytes(Path.of(System.getProperty("etsi.sample"))));
        int n = 0;
        while (!r.atEnd()) {
            gen.etsi.LI_PS_PDU.PS_PDU pdu = new gen.etsi.LI_PS_PDU.PS_PDU();
            BerObject.decode(pdu, r);
            String s = pdu.toString();
            assertTrue(s.startsWith("{\n  pSHeader {\n"), s);
            assertTrue(s.endsWith("\n}"), s);
            n++;
        }
        assertTrue(n > 1);
    }

    @Test
    void aFailedAssertionShowsBothValues() {
        Points a = new Points();
        BerObject.decode(a, hex("301030060201010201023006020103020104"));
        Points b = new Points();
        AssertionFailedError e = assertThrows(AssertionFailedError.class, () -> assertEquals(a, b));
        assertTrue(e.getMessage().contains("/* [1] */ {"), e.getMessage());
    }
}
