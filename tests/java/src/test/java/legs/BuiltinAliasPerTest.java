package legs;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;

import io.github.schramp.gambasasn1.wire.ber.BerObject;
import io.github.schramp.gambasasn1.wire.per.PerObject;
import io.github.schramp.gambasasn1.wire.spec.AsMemberRef;
import io.github.schramp.gambasasn1.wire.spec.MemberRef;
import io.github.schramp.gambasasn1.wire.types.Asn1BitString;
import io.github.schramp.gambasasn1.wire.types.Asn1Boolean;
import io.github.schramp.gambasasn1.wire.types.Asn1Integer;
import io.github.schramp.gambasasn1.wire.types.Asn1Null;
import io.github.schramp.gambasasn1.wire.types.Asn1OctetString;
import io.github.schramp.gambasasn1.wire.types.Asn1UInteger;
import java.util.stream.Stream;
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

    /** Kinds the PER walker writes so far. */
    private static boolean hasPerField(AsMemberRef v) {
        return switch (v.asMemberRef()) {
            case MemberRef.Primitive(Asn1Boolean b) -> true;
            case MemberRef.Primitive(Asn1Null n) -> true;
            case MemberRef.Primitive(Asn1Integer i) -> true;
            case MemberRef.Primitive(Asn1UInteger u) -> true;
            case MemberRef.Enumerated e -> true;
            case MemberRef.Primitive(Asn1OctetString o) -> true;
            case MemberRef.Primitive(Asn1BitString b) -> true;
            default -> false;
        };
    }

    static Stream<Vectors.Vector> vectors() {
        return BuiltinAliasBerTest.vectors()
                .filter(vec -> vec.asn1cUper() != null && hasPerField(BuiltinAliasBerTest.TYPES.get(vec.type()).get()));
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
}
