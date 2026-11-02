package legs;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;

import io.github.schramp.gambasasn1.wire.ber.BerObject;
import io.github.schramp.gambasasn1.wire.per.PerObject;
import io.github.schramp.gambasasn1.wire.spec.AsMemberRef;
import java.util.Map;
import java.util.Set;
import java.util.function.Supplier;
import java.util.stream.Stream;

/**
 * The checks every unaligned PER leg makes on a vector with asn1c UPER: the
 * DER value encodes to asn1c's UPER byte for byte, and asn1c's UPER decodes
 * to a value that re-encodes to the DER.
 */
final class PerLeg {
    private PerLeg() {
    }

    /** The vectors of {@code types} that asn1c could encode in PER. */
    static Stream<Vectors.Vector> withUper(Stream<Vectors.Vector> vectors, Set<String> types) {
        return vectors.filter(v -> v.asn1cUper() != null && types.contains(v.type()));
    }

    static void check(Vectors.Vector vec, Map<String, ? extends Supplier<? extends AsMemberRef>> types) {
        AsMemberRef v = types.get(vec.type()).get();
        BerObject.decode(v, vec.der());
        assertArrayEquals(vec.asn1cUper(), PerObject.encode(v), "encode " + vec.xer());
        AsMemberRef back = types.get(vec.type()).get();
        PerObject.decode(back, vec.asn1cUper());
        assertArrayEquals(vec.der(), BerObject.encode(back), "decode " + vec.xer());
    }
}
