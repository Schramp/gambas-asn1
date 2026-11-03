package legs;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertSame;
import static org.junit.jupiter.api.Assertions.assertTrue;

import gen.containing.Holder;
import gen.containing.Inner;
import gen.ext_ber.Outer2;
import gen.ext_ber.V2;
import gen.recursion_ber.List;
import gen.recursion_ber.Tree;
import gen.seqof_ber.Point;
import gen.seqof_ber.Points;
import gen.sequence_ber.Outer;
import io.github.schramp.gambasasn1.wire.ber.BerObject;
import io.github.schramp.gambasasn1.wire.ber.BerReader;
import io.github.schramp.gambasasn1.wire.query.Extract;
import io.github.schramp.gambasasn1.wire.query.ExtractPlan;
import io.github.schramp.gambasasn1.wire.query.Extraction;
import io.github.schramp.gambasasn1.wire.spec.AsMemberRef;
import io.github.schramp.gambasasn1.wire.spec.Asn1Choice;
import io.github.schramp.gambasasn1.wire.spec.Asn1Contained;
import io.github.schramp.gambasasn1.wire.spec.Asn1Seq;
import io.github.schramp.gambasasn1.wire.spec.Asn1SeqOf;
import io.github.schramp.gambasasn1.wire.spec.ContainedStatus;
import io.github.schramp.gambasasn1.wire.spec.Decoded;
import io.github.schramp.gambasasn1.wire.spec.MemberRef;
import io.github.schramp.gambasasn1.wire.spec.Positions;
import io.github.schramp.gambasasn1.wire.types.Asn1Boolean;
import io.github.schramp.gambasasn1.wire.types.Asn1Ia5String;
import io.github.schramp.gambasasn1.wire.types.Asn1Integer;
import io.github.schramp.gambasasn1.wire.types.Asn1OctetString;
import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.ArrayList;
import java.util.HexFormat;
import org.junit.jupiter.api.Test;

/**
 * Extraction by type: a plan compiled from the tables, run over decoded
 * values, finds exactly what a plain walk of the whole value finds.
 */
class ExtractTest {
    private static byte[] hex(String s) {
        return HexFormat.of().parseHex(s);
    }

    /** Every value below {@code m} that is a {@code target}, depth first, walking everything. */
    private static void walkAll(MemberRef m, Class<?> target, java.util.List<Object> out) {
        Object v = Positions.nodeOf(m);
        if (v == null) {
            return;
        }
        if (target.isInstance(v)) {
            out.add(v);
        }
        switch (m) {
            case MemberRef.Composite(Asn1Seq s) -> {
                for (int i = 0; i < s.spec().members().size(); i++) {
                    walkAll(s.getMember(i), target, out);
                }
            }
            case MemberRef.Choice(Asn1Choice c) -> {
                if (c.activeIndex() >= 0) {
                    walkAll(c.getActive(), target, out);
                }
            }
            case MemberRef.SeqOf(Asn1SeqOf s) -> {
                for (int i = 0; i < s.size(); i++) {
                    walkAll(s.get(i), target, out);
                }
            }
            case MemberRef.Contained(Asn1Contained c, var spec) -> {
                if (c.status() == ContainedStatus.DECODED && c.value() != null) {
                    walkAll(c.value().asMemberRef(), target, out);
                }
            }
            default -> {
            }
        }
    }

    private static java.util.List<Object> walkAll(AsMemberRef root, Class<?> target) {
        java.util.List<Object> out = new ArrayList<>();
        walkAll(root.asMemberRef(), target, out);
        return out;
    }

    private static void assertSameValues(java.util.List<?> want, java.util.List<?> got) {
        assertEquals(want.size(), got.size());
        for (int i = 0; i < want.size(); i++) {
            assertSame(want.get(i), got.get(i));
        }
    }

    @Test
    void etsiFusedPlanFindsWhatAWholeWalkFinds() throws IOException {
        byte[] file = Files.readAllBytes(Path.of(System.getProperty("etsi.sample")));
        java.util.List<Class<?>> targets = java.util.List.of(gen.etsi.EncryptedPayload.class,
                gen.etsi.Timestamp.class, gen.etsi.CCContents.class, gen.etsi.IRIContents.class,
                Asn1OctetString.class, Asn1Integer.class);
        ExtractPlan plan = ExtractPlan.of(gen.etsi.PS_PDU::new, targets);
        assertTrue(plan.canMatch());
        BerReader r = new BerReader(file);
        int pdus = 0;
        int payloads = 0;
        while (!r.atEnd()) {
            gen.etsi.PS_PDU pdu = new gen.etsi.PS_PDU();
            Decoded d = BerObject.decodeWithPositions(pdu, r);
            Extraction x = plan.run(pdu, d.positions());
            for (Class<?> t : targets) {
                java.util.List<Object> want = walkAll(pdu, t);
                assertSameValues(want, x.values(t));
                assertSameValues(want, Extract.all(pdu, t));
                for (Extraction.Hit<?> h : x.get(t)) {
                    assertEquals(d.positions().bitOffset(h.value()), h.bitOffset());
                }
            }
            payloads += x.values(gen.etsi.EncryptedPayload.class).size();
            pdus++;
        }
        assertTrue(pdus > 1);
        assertTrue(payloads > 0, "no decoded EncryptedPayload in the sample");
    }

    @Test
    void planIsCachedPerRootAndTargets() {
        assertSame(ExtractPlan.of(Outer::new, Asn1Boolean.class),
                ExtractPlan.of(Outer.class, java.util.List.of(Asn1Boolean.class)));
    }

    @Test
    void planKeepsOnlyBranchesThatLeadToATarget() {
        // Outer { inner Plain { num, flag, text, data, nul }, tail }: only flag is a BOOLEAN.
        ExtractPlan plan = ExtractPlan.of(Outer::new, Asn1Boolean.class);
        assertEquals("Outer\n  inner: Plain\n    flag: Asn1Boolean *Asn1Boolean\n", plan.toString());
        Outer v = new Outer();
        BerObject.decode(v, hex("3011300C0201010101000C0004000500020102"));
        Extraction x = plan.run(v);
        assertEquals(java.util.List.of(v.inner().flag()), x.values(Asn1Boolean.class));
        assertEquals(3, x.visited());
        assertFalse(ExtractPlan.of(Outer::new, Point.class).canMatch());
    }

    @Test
    void everyElementOfASequenceOfIsAHit() {
        Points v = new Points();
        BerObject.decode(v, hex("301030060201010201023006020103020104"));
        assertEquals(v.items(), Extract.all(v, Point.class));
        assertEquals(4, Extract.all(v, Asn1Integer.class).size());
        Point second = v.items().get(1);
        assertSameValues(java.util.List.of(second.x(), second.y()), Extract.all(second, Asn1Integer.class));
    }

    @Test
    void recursiveTypesAreFollowedAsDeepAsTheValueGoes() {
        List l = new List();
        Decoded d = BerObject.decodeWithPositions(l, hex("300D800101A108800102A103800103"), null);
        java.util.List<Extraction.Hit<List>> hits = Extract.all(l, d, List.class);
        assertEquals(java.util.List.of(0L, 5L, 10L), hits.stream().map(Extraction.Hit::byteOffset).toList());
        assertEquals(java.util.List.of(1L, 2L, 3L),
                Extract.all(l, Asn1Integer.class).stream().map(Asn1Integer::get).toList());
        Tree t = new Tree();
        BerObject.decode(t, hex("301A800172A1153005800161A100300C800162A1073005800163A100"));
        assertEquals(java.util.List.of("r", "a", "b", "c"),
                Extract.all(t, Asn1Ia5String.class).stream().map(Asn1Ia5String::get).toList());
        assertEquals(4, Extract.all(t, Tree.class).size());
    }

    @Test
    void extensionAdditionsAreSearchedAndAbsentMembersAreNot() {
        Outer2 o = new Outer2();
        // inner V2 { id 6, flag TRUE, [[ level 2 ]], extra 'AA'H }, tail 7; note and name absent.
        BerObject.decode(o, hex("3011A00C8001068201FF8301028501AA810107"));
        assertEquals(java.util.List.of(6L, 2L, 7L),
                Extract.all(o, Asn1Integer.class).stream().map(Asn1Integer::get).toList());
        assertEquals(java.util.List.of(), Extract.all(o, Asn1Ia5String.class));
        assertEquals(1, Extract.all(o, Asn1OctetString.class).size());
        assertEquals(java.util.List.of(o.inner()), Extract.all(o, V2.class));
    }

    @Test
    void onlyDecodedContainedValuesAreSearched() {
        java.util.List<Vectors.Vector> rows = Vectors.load("containing_test.vectors");
        Holder plain = new Holder();
        BerObject.decode(plain, rows.stream().filter(v -> v.type().equals("Holder") && v.xer().contains("<plain/>"))
                .findFirst().orElseThrow().der());
        assertEquals(4, Extract.all(plain, Inner.class).size());
        Holder scrambled = new Holder();
        BerObject.decode(scrambled, rows.stream()
                .filter(v -> v.type().equals("Holder") && v.xer().contains("<scrambled/>"))
                .findFirst().orElseThrow().der());
        java.util.List<Inner> found = Extract.all(scrambled, Inner.class);
        assertSameValues(walkAll(scrambled, Inner.class), found);
        assertTrue(found.size() < 4);
    }
}
