package io.github.schramp.gambasasn1.wire.containing;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertSame;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import io.github.schramp.gambasasn1.wire.ber.BerReader;
import io.github.schramp.gambasasn1.wire.ber.Tag;
import io.github.schramp.gambasasn1.wire.ber.TagClass;
import io.github.schramp.gambasasn1.wire.io.DecodeException;
import io.github.schramp.gambasasn1.wire.spec.Asn1Seq;
import io.github.schramp.gambasasn1.wire.spec.BerTagging;
import io.github.schramp.gambasasn1.wire.spec.Constraints;
import io.github.schramp.gambasasn1.wire.spec.ContainedEncoding;
import io.github.schramp.gambasasn1.wire.spec.ContainedResult;
import io.github.schramp.gambasasn1.wire.spec.ContainedSpec;
import io.github.schramp.gambasasn1.wire.spec.ContainedStatus;
import io.github.schramp.gambasasn1.wire.spec.ContainedText;
import io.github.schramp.gambasasn1.wire.spec.Containing;
import io.github.schramp.gambasasn1.wire.spec.MemberMeta;
import io.github.schramp.gambasasn1.wire.spec.MemberRef;
import io.github.schramp.gambasasn1.wire.spec.SequenceSpec;
import io.github.schramp.gambasasn1.wire.spec.XerInstruction;
import io.github.schramp.gambasasn1.wire.types.Asn1Integer;
import java.util.HexFormat;
import java.util.List;
import org.junit.jupiter.api.Test;

/**
 * The status transitions of a contained field (X.682 §11), against a
 * hand-written table: what each setter of {@link Containing} resets, and
 * what the post-decode pass of {@link ContainedValues} does with each state.
 * These are the transitions of the C++ runtime's {@code ContainedBase}
 * ({@code set_raw_from_wire}, {@code set_raw_for_value}, {@code decode_one}).
 */
class ContainedStatusTest {
    /** INTEGER 5. */
    private static final byte[] FIVE = HexFormat.of().parseHex("020105");
    /** INTEGER 7. */
    private static final byte[] SEVEN = HexFormat.of().parseHex("020107");
    /** Not a BER encoding of an INTEGER. */
    private static final byte[] JUNK = HexFormat.of().parseHex("FF");

    private static ContainedSpec spec(boolean eager, int whenMember, boolean failOnError) {
        return new ContainedSpec(ContainedEncoding.OUTER, eager, "plain", whenMember, 1L, failOnError,
                ContainedText.HEX, ContainedText.HEX, 0);
    }

    private static final ContainedSpec PLAIN = spec(true, -1, false);

    /** {@code Holder ::= SEQUENCE { kind [0] INTEGER, payload [1] OCTET STRING (CONTAINING INTEGER) }}. */
    private static final class Holder implements Asn1Seq {
        final Asn1Integer kind = new Asn1Integer(1);
        final Containing<Asn1Integer> payload;
        private final SequenceSpec spec;

        Holder(ContainedSpec cs) {
            payload = new Containing<>(Asn1Integer::new, cs);
            Tag t0 = new Tag(TagClass.CONTEXT, 0, false);
            Tag t1 = new Tag(TagClass.CONTEXT, 1, false);
            spec = new SequenceSpec("Holder", new Tag(TagClass.UNIVERSAL, 16, true), List.of(
                    new MemberMeta("kind", t0, false, new BerTagging.Implicit(t0), Constraints.UNCONSTRAINED,
                            XerInstruction.DEFAULT, null),
                    new MemberMeta("payload", t1, false, new BerTagging.Implicit(t1), Constraints.UNCONSTRAINED,
                            XerInstruction.DEFAULT, cs)),
                    -1, 0, false, List.of(), List.of(), List.of(1));
        }

        @Override
        public SequenceSpec spec() {
            return spec;
        }

        @Override
        public MemberRef getMember(int i) {
            return i == 0 ? kind.asMemberRef() : payload.asMemberRef();
        }

        @Override
        public MemberRef presentMember(int i) {
            return getMember(i);
        }

        @Override
        public void setDefault(int i) {
        }

        @Override
        public boolean isDefaultEqual(int i) {
            return false;
        }

        @Override
        public long validate(int i) {
            return 0;
        }
    }

    private static void postDecode(Holder h, ContainedOptions opts) {
        ContainedValues.decodeMembers(h, ContainedEncoding.BER, new BerReader(new byte[0]).withContained(opts));
    }

    @Test
    void newFieldIsNotDecoded() {
        Containing<Asn1Integer> f = new Holder(PLAIN).payload;
        assertEquals(ContainedStatus.NOT_DECODED, f.status());
        assertNull(f.value());
        assertFalse(f.dirty());
        assertArrayEquals(new byte[0], f.rawOctets());
    }

    @Test
    void wireBytesDecodeInThePostDecodePass() {
        Holder h = new Holder(PLAIN);
        h.payload.setRawFromWire(FIVE, ContainedEncoding.BER);
        assertEquals(ContainedStatus.NOT_DECODED, h.payload.status());
        postDecode(h, null);
        assertEquals(ContainedStatus.DECODED, h.payload.status());
        assertEquals(5, h.payload.value().get());
        assertFalse(h.payload.dirty());
        assertArrayEquals(FIVE, h.payload.rawOctets());
    }

    /** Bytes from the wire replace a decoded, even a modified, value: the old value no longer matches them. */
    @Test
    void wireBytesDropTheInnerValueAndResetTheStatus() {
        Holder h = new Holder(PLAIN);
        h.payload.set(new Asn1Integer(9));
        assertTrue(h.payload.dirty());
        h.payload.setRawFromWire(SEVEN, ContainedEncoding.BER);
        assertEquals(ContainedStatus.NOT_DECODED, h.payload.status());
        assertNull(h.payload.value());
        assertFalse(h.payload.dirty());
        assertEquals("", h.payload.error());
        postDecode(h, null);
        assertEquals(7, h.payload.value().get());
    }

    /**
     * A value decoded from its inline XER/JER form is installed with its raw
     * bytes; the post-decode pass keeps it, even when those bytes are not the
     * value's own encoding (JER {@code raw}, XER raw comment).
     */
    @Test
    void inlineDecodedValueIsKeptByThePostDecodePass() {
        Holder h = new Holder(PLAIN);
        Asn1Integer inline = new Asn1Integer(5);
        h.payload.setRawFromWire(SEVEN, ContainedEncoding.BER);
        h.payload.install(ContainedResult.ok(), inline);
        postDecode(h, null);
        assertEquals(ContainedStatus.DECODED, h.payload.status());
        assertSame(inline, h.payload.value());
        assertArrayEquals(SEVEN, h.payload.rawOctets());
    }

    @Test
    void notEagerIsSkipped() {
        Holder h = new Holder(spec(false, -1, false));
        h.payload.setRawFromWire(FIVE, ContainedEncoding.BER);
        postDecode(h, null);
        assertEquals(ContainedStatus.SKIPPED, h.payload.status());
        assertNull(h.payload.value());
        assertArrayEquals(FIVE, h.payload.rawOctets());
    }

    @Test
    void decodingOffIsSkipped() {
        Holder h = new Holder(PLAIN);
        h.payload.setRawFromWire(FIVE, ContainedEncoding.BER);
        postDecode(h, new ContainedOptions(null, true));
        assertEquals(ContainedStatus.SKIPPED, h.payload.status());
        assertNull(h.payload.value());
    }

    @Test
    void whenMismatchIsSkippedWithTheReason() {
        Holder h = new Holder(spec(true, 0, false));
        h.kind.set(2);
        h.payload.setRawFromWire(FIVE, ContainedEncoding.BER);
        postDecode(h, null);
        assertEquals(ContainedStatus.SKIPPED, h.payload.status());
        assertTrue(h.payload.error().contains("'kind'"), h.payload.error());
        h.kind.set(1);
        h.payload.setRawFromWire(FIVE, ContainedEncoding.BER);
        postDecode(h, null);
        assertEquals(ContainedStatus.DECODED, h.payload.status());
    }

    @Test
    void badBytesFailAndAreKept() {
        Holder h = new Holder(PLAIN);
        h.payload.setRawFromWire(JUNK, ContainedEncoding.BER);
        postDecode(h, null);
        assertEquals(ContainedStatus.FAILED, h.payload.status());
        assertNull(h.payload.value());
        assertFalse(h.payload.error().isEmpty());
        assertArrayEquals(JUNK, h.payload.rawOctets());
    }

    @Test
    void failOnErrorFailsTheOuterDecode() {
        Holder h = new Holder(spec(true, -1, true));
        h.payload.setRawFromWire(JUNK, ContainedEncoding.BER);
        assertThrows(DecodeException.class, () -> postDecode(h, null));
    }

    /** A set or edited value is dirty: encode writes its encoding, not the raw bytes. */
    @Test
    void setAndEditMarkTheValueDirty() {
        Holder h = new Holder(PLAIN);
        h.payload.set(new Asn1Integer(7));
        assertEquals(ContainedStatus.DECODED, h.payload.status());
        assertTrue(h.payload.dirty());
        assertArrayEquals(SEVEN, ContainedValues.wireOctets(h.payload, PLAIN, ContainedEncoding.BER, null));

        h.payload.setRawFromWire(FIVE, ContainedEncoding.BER);
        postDecode(h, null);
        assertFalse(h.payload.dirty());
        assertArrayEquals(FIVE, ContainedValues.wireOctets(h.payload, PLAIN, ContainedEncoding.BER, null));
        h.payload.edit().set(7);
        assertTrue(h.payload.dirty());
        assertArrayEquals(SEVEN, ContainedValues.wireOctets(h.payload, PLAIN, ContainedEncoding.BER, null));
    }

    @Test
    void setBytesDropsTheInnerValue() {
        Holder h = new Holder(PLAIN);
        h.payload.set(new Asn1Integer(7));
        h.payload.setBytes(FIVE);
        assertEquals(ContainedStatus.NOT_DECODED, h.payload.status());
        assertNull(h.payload.value());
        assertFalse(h.payload.dirty());
        assertEquals(ContainedEncoding.OUTER, h.payload.rawEncoding());
    }
}
