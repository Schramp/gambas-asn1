package legs;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;

import gen.choice_ber.ExtRoot;
import io.github.schramp.gambasasn1.wire.ber.Tag;
import io.github.schramp.gambasasn1.wire.io.DecodeException;
import io.github.schramp.gambasasn1.wire.io.EncodeException;
import io.github.schramp.gambasasn1.wire.per.PerObject;
import java.util.HexFormat;
import java.util.Set;
import java.util.stream.Stream;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.MethodSource;

/**
 * Unaligned PER leg of CHOICE (X.691 §23): the root index in the fewest
 * bits, extension alternatives as open types, alternatives in the canonical
 * order of their tags, against asn1c's UPER; also the SEQUENCE and SET
 * vectors that hold a CHOICE.
 */
class ChoicePerTest {
    static Stream<Vectors.Vector> choice() {
        return PerLeg.withUper(ChoiceBerTest.vectors(), ChoiceBerTest.TYPES.keySet());
    }

    static Stream<Vectors.Vector> refs() {
        return PerLeg.withUper(SequenceBerTest.vectors(), Set.of("Refs"));
    }

    static Stream<Vectors.Vector> mixed() {
        return PerLeg.withUper(SetBerTest.vectors(), Set.of("Mixed"));
    }

    @ParameterizedTest(name = "{0}")
    @MethodSource("choice")
    void choiceSchema(Vectors.Vector vec) {
        PerLeg.check(vec, ChoiceBerTest.TYPES);
    }

    @ParameterizedTest(name = "{0}")
    @MethodSource("refs")
    void sequenceHoldingChoice(Vectors.Vector vec) {
        PerLeg.check(vec, SequenceBerTest.TYPES);
    }

    @ParameterizedTest(name = "{0}")
    @MethodSource("mixed")
    void setHoldingChoice(Vectors.Vector vec) {
        PerLeg.check(vec, SetBerTest.TYPES);
    }

    /**
     * X.691 §23.8: an earlier version keeps an extension alternative it does
     * not know (asn1c's Ext {@code b TRUE}) as its open-type contents.
     */
    @Test
    void earlierVersionKeepsUnknownAlternative() {
        ExtRoot v = new ExtRoot();
        PerObject.decode(v, HexFormat.of().parseHex("800180"));
        assertEquals(-1, v.activeIndex());
        assertEquals(Tag.context(0, false), v.unknownExtension().tag());
        assertArrayEquals(new byte[] {(byte) 0x80}, v.unknownExtension().bytes());
        assertThrows(EncodeException.class, () -> PerObject.encode(v));
    }

    @Test
    void rootIndexBeyondTheRootFails() {
        // Plain has 3 alternatives in 2 bits; index 3 is none of them.
        assertThrows(DecodeException.class, () -> PerObject.decode(new gen.choice_ber.Plain(), new byte[] {(byte) 0xC0}));
    }
}
