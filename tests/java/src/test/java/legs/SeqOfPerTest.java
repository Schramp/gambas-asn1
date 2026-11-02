package legs;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;

import gen.seqof_ber.IntSet;
import gen.seqof_ber.Ints;
import io.github.schramp.gambasasn1.wire.io.DecodeException;
import io.github.schramp.gambasasn1.wire.io.EncodeException;
import io.github.schramp.gambasasn1.wire.per.PerObject;
import io.github.schramp.gambasasn1.wire.spec.Constraints;
import java.util.HexFormat;
import java.util.stream.Stream;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.MethodSource;

/**
 * Unaligned PER leg of SEQUENCE OF and SET OF (X.691 §20, §22): the count
 * under the SIZE, element constraints, SET OF components in §22.1 order,
 * and recursive types, against asn1c's UPER.
 */
class SeqOfPerTest {
    private static byte[] hex(String s) {
        return HexFormat.of().parseHex(s);
    }

    static Stream<Vectors.Vector> seqof() {
        return PerLeg.withUper(SeqOfBerTest.vectors(), SeqOfBerTest.TYPES.keySet());
    }

    static Stream<Vectors.Vector> constraints() {
        return PerLeg.withUper(ConstraintsBerTest.vectors(), ConstraintsBerTest.TYPES.keySet());
    }

    static Stream<Vectors.Vector> recursion() {
        return PerLeg.withUper(RecursionBerTest.vectors(), RecursionBerTest.TYPES.keySet());
    }

    @ParameterizedTest(name = "{0}")
    @MethodSource("seqof")
    void seqOfSchema(Vectors.Vector vec) {
        PerLeg.check(vec, SeqOfBerTest.TYPES);
    }

    @ParameterizedTest(name = "{0}")
    @MethodSource("constraints")
    void sizeAndElementConstraints(Vectors.Vector vec) {
        PerLeg.check(vec, ConstraintsBerTest.TYPES);
    }

    @ParameterizedTest(name = "{0}")
    @MethodSource("recursion")
    void recursiveTypes(Vectors.Vector vec) {
        PerLeg.check(vec, RecursionBerTest.TYPES);
    }

    /**
     * X.691 §22.1: the decoder takes a SET OF in any order and the encoder
     * writes it sorted; asn1c's {5, -1, 300, 2} with its components reversed.
     */
    @Test
    void setOfIsWrittenSorted() {
        IntSet v = new IntSet();
        PerObject.decode(v, hex("0402012C01FF01050102"));
        assertArrayEquals(hex("040102010501FF02012C"), PerObject.encode(v));
    }

    @Test
    void countOutsideTheSizeFails() {
        // SIZE (1..3) in 2 bits: offset 3 is a count of 4.
        Constraints size = new Constraints(Constraints.SIZE_CONSTRAINED, 0, 0, 0, 0, 0, 2, 1, 3, null, 0, null, 0,
                null, 0.0, 0.0);
        assertThrows(DecodeException.class, () -> PerObject.decode(new Ints(), hex("C0"), size));
        assertThrows(EncodeException.class, () -> PerObject.encode(new Ints(), size));
    }
}
