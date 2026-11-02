package legs;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;

import io.github.schramp.gambasasn1.wire.ber.BerObject;
import io.github.schramp.gambasasn1.wire.per.PerObject;
import io.github.schramp.gambasasn1.wire.spec.AsMemberRef;
import io.github.schramp.gambasasn1.wire.spec.MemberRef;
import java.util.Arrays;
import java.util.HexFormat;
import java.util.Set;
import java.util.stream.Stream;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.MethodSource;

/**
 * Java unaligned PER leg of builtin_alias_ber_test.asn1: every type
 * assignment whose PER field is written encodes asn1c's UPER byte for byte
 * and decodes it back to the value of the DER (X.691). Tags play no part in
 * PER (X.691 §10.6.3), so IMPLICIT and EXPLICIT variants encode as their
 * underlying type.
 */
class BuiltinAliasPerTest {

    /** Every builtin and ENUMERATED type assignment has its PER field. */
    private static boolean hasPerField(AsMemberRef v) {
        return v.asMemberRef() instanceof MemberRef.Primitive || v.asMemberRef() instanceof MemberRef.Enumerated;
    }

    /**
     * Types whose asn1c UPER is not X.691: for a type assignment that only
     * renames a builtin, asn1c drops the builtin's PER constraints, so it
     * writes UTCTime and GeneralizedTime with 8 bits a character (X.691
     * §10.6.5: VisibleString, 7 bits) and an unconstrained NumericString's
     * digits unmapped (§30.5.4: space 0, '0'..'9' 1..10). As a SEQUENCE
     * member asn1c writes the X.691 encoding; {@link #asn1cDeviations}
     * checks these types against those bytes.
     */
    private static final Set<String> ASN1C_DEVIATES = Set.of("Numeric", "Utc", "ImplicitUtc", "GenTime", "ExplicitGenTime");

    static Stream<Vectors.Vector> vectors() {
        return BuiltinAliasBerTest.vectors()
                .filter(vec -> vec.asn1cUper() != null && !ASN1C_DEVIATES.contains(vec.type())
                        && hasPerField(BuiltinAliasBerTest.TYPES.get(vec.type()).get()));
    }

    private static AsMemberRef fromDer(Vectors.Vector vec) {
        AsMemberRef v = BuiltinAliasBerTest.TYPES.get(vec.type()).get();
        BerObject.decode(v, vec.der());
        return v;
    }

    @ParameterizedTest(name = "{0}")
    @MethodSource("vectors")
    void encodesAsAsn1cDoes(Vectors.Vector vec) {
        AsMemberRef v = fromDer(vec);
        assertArrayEquals(vec.asn1cUper(), PerObject.encode(v, BuiltinAliasJerTest.constraints(v)));
    }

    @ParameterizedTest(name = "{0}")
    @MethodSource("vectors")
    void decodesAsn1cUper(Vectors.Vector vec) {
        AsMemberRef v = BuiltinAliasBerTest.TYPES.get(vec.type()).get();
        PerObject.decode(v, vec.asn1cUper(), BuiltinAliasJerTest.constraints(v));
        assertEquals(fromDer(vec).asMemberRef(), v.asMemberRef());
        assertArrayEquals(vec.der(), BerObject.encode(v));
    }

    /** Expected bytes: asn1c's UPER of the same value as a SEQUENCE member, without the member's preamble. */
    @Test
    void asn1cDeviations() {
        String[][] cases = {
            {"Numeric", "0801230456", "0812340567"},
            {"Utc", "0D3234303131353134333030305A", "0D64D183162D58B466C1830B40"},
            {"GenTime", "1332303234303131353134333030302E3132335A", "1364C193460C58B562D19B060C173164CED0"},
        };
        for (String[] c : cases) {
            Vectors.Vector vec = BuiltinAliasBerTest.vectors()
                    .filter(v -> v.type().equals(c[0]) && Arrays.equals(v.asn1cUper(), HexFormat.of().parseHex(c[1])))
                    .findFirst().orElseThrow();
            AsMemberRef v = fromDer(vec);
            byte[] uper = HexFormat.of().parseHex(c[2]);
            assertArrayEquals(uper, PerObject.encode(v, BuiltinAliasJerTest.constraints(v)), c[0]);
            AsMemberRef back = BuiltinAliasBerTest.TYPES.get(vec.type()).get();
            PerObject.decode(back, uper, BuiltinAliasJerTest.constraints(back));
            assertEquals(v.asMemberRef(), back.asMemberRef());
        }
    }
}
