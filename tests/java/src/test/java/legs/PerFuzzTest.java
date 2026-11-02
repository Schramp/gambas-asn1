package legs;

import static org.junit.jupiter.api.Assertions.assertTrue;

import io.github.schramp.gambasasn1.wire.io.DecodeException;
import io.github.schramp.gambasasn1.wire.io.EncodeException;
import io.github.schramp.gambasasn1.wire.per.PerObject;
import io.github.schramp.gambasasn1.wire.spec.AsMemberRef;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;
import java.util.Map;
import java.util.Random;
import java.util.function.Supplier;
import java.util.stream.Stream;
import org.junit.jupiter.api.Test;

/**
 * Fuzz smoke test of the PER decoder: byte-level mutations of every asn1c
 * UPER vector (a flipped bit, an overwritten byte, a truncation, inserted or
 * deleted bytes) end in a {@link DecodeException} or decode to a value that
 * encodes or fails with an {@link EncodeException}; nothing else is thrown.
 * A length read from the input (X.691 §11.9) is checked against the input
 * left before anything is allocated for it.
 */
class PerFuzzTest {
    private static final int MUTATIONS = 64;

    private record Source(Stream<Vectors.Vector> vectors, Map<String, ? extends Supplier<? extends AsMemberRef>> types) {
    }

    private static List<Source> sources() {
        return List.of(
                new Source(BuiltinAliasBerTest.vectors(), BuiltinAliasBerTest.TYPES),
                new Source(ChoiceBerTest.vectors(), ChoiceBerTest.TYPES),
                new Source(SequenceBerTest.vectors(), SequenceBerTest.TYPES),
                new Source(SeqOfBerTest.vectors(), SeqOfBerTest.TYPES),
                new Source(ConstraintsBerTest.vectors(), ConstraintsBerTest.TYPES),
                new Source(SetBerTest.vectors(), SetBerTest.TYPES),
                new Source(TaggingBerTest.vectors(), TaggingBerTest.TYPES),
                new Source(DefaultBerTest.vectors(), DefaultBerTest.TYPES),
                new Source(ExtBerTest.vectors(), ExtBerTest.TYPES),
                new Source(RecursionBerTest.vectors(), RecursionBerTest.TYPES),
                new Source(ContainingTest.vectors(), ContainingTest.TYPES));
    }

    private static byte[] mutate(byte[] data, Random rng) {
        if (data.length == 0) {
            return new byte[] {(byte) rng.nextInt(256)};
        }
        int i = rng.nextInt(data.length);
        switch (rng.nextInt(5)) {
            case 0 -> {
                byte[] b = data.clone();
                b[i] ^= (byte) (1 << rng.nextInt(8));
                return b;
            }
            case 1 -> {
                byte[] b = data.clone();
                int[] picks = {0x00, 0xFF, 0x7F, 0x80, rng.nextInt(256)};
                b[i] = (byte) picks[rng.nextInt(picks.length)];
                return b;
            }
            case 2 -> {
                return Arrays.copyOf(data, i);
            }
            case 3 -> {
                byte[] ins = new byte[1 + rng.nextInt(8)];
                rng.nextBytes(ins);
                byte[] b = new byte[data.length + ins.length];
                System.arraycopy(data, 0, b, 0, i);
                System.arraycopy(ins, 0, b, i, ins.length);
                System.arraycopy(data, i, b, i + ins.length, data.length - i);
                return b;
            }
            default -> {
                int n = Math.min(1 + rng.nextInt(8), data.length - i);
                byte[] b = new byte[data.length - n];
                System.arraycopy(data, 0, b, 0, i);
                System.arraycopy(data, i + n, b, i, data.length - i - n);
                return b;
            }
        }
    }

    @Test
    void mutatedPerNeverCrashes() {
        Random rng = new Random(42);
        List<String> crashes = new ArrayList<>();
        int runs = 0;
        for (Source src : sources()) {
            for (Vectors.Vector vec : PerLeg.withUper(src.vectors(), src.types().keySet()).toList()) {
                for (int m = 0; m < MUTATIONS; m++) {
                    byte[] data = mutate(vec.asn1cUper(), rng);
                    AsMemberRef v = src.types().get(vec.type()).get();
                    runs++;
                    try {
                        PerObject.decode(v, data);
                        PerObject.encode(v);
                    } catch (DecodeException | EncodeException e) {
                        // malformed input rejected: the expected outcome
                    } catch (RuntimeException | StackOverflowError e) {
                        crashes.add(vec.type() + " " + java.util.HexFormat.of().formatHex(data) + ": " + e);
                    }
                }
            }
        }
        assertTrue(runs > 1000, "only " + runs + " decoder runs");
        assertTrue(crashes.isEmpty(), crashes.size() + " crash(es):\n" + String.join("\n", crashes));
    }
}
