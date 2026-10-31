package xvalharness;

import io.github.schramp.gambasasn1.wire.ber.BerObject;
import io.github.schramp.gambasasn1.wire.ber.BerReader;
import io.github.schramp.gambasasn1.wire.io.DecodeException;
import io.github.schramp.gambasasn1.wire.io.EncodeException;
import io.github.schramp.gambasasn1.wire.spec.Asn1Pdu;
import java.io.ByteArrayOutputStream;
import java.nio.file.Files;
import java.nio.file.Path;

/**
 * xval_sweep's Java leg.
 *
 * <p>{@code BerRoundtrip CLASS IN OUT}: decodes the back-to-back BER
 * records of IN as CLASS and writes their re-encodings to OUT. A record
 * that fails to decode stops the run with exit 1 and its index on stderr.
 *
 * <p>{@code BerRoundtrip --fuzz CLASS FILE...}: decodes and re-encodes
 * each file's records until the first error. A {@link DecodeException} or
 * {@link EncodeException} is the expected outcome for malformed input;
 * any other throwable is a crash, printed as {@code CRASH FILE: ...},
 * and makes the exit code 3.
 */
public final class BerRoundtrip {
    private BerRoundtrip() {
    }

    public static void main(String[] args) throws Exception {
        if (args.length >= 2 && args[0].equals("--fuzz")) {
            System.exit(fuzz(args));
        }
        if (args.length != 3) {
            System.err.println("usage: BerRoundtrip CLASS IN OUT | --fuzz CLASS FILE...");
            System.exit(2);
        }
        Class<? extends Asn1Pdu> type = Class.forName(args[0]).asSubclass(Asn1Pdu.class);
        BerReader r = new BerReader(Files.readAllBytes(Path.of(args[1])));
        ByteArrayOutputStream out = new ByteArrayOutputStream();
        int n = 0;
        while (!r.atEnd()) {
            Asn1Pdu v = type.getDeclaredConstructor().newInstance();
            try {
                BerObject.decode(v, r);
            } catch (RuntimeException e) {
                System.err.println("record " + n + " at offset " + r.position() + ": " + e);
                Files.write(Path.of(args[2]), out.toByteArray());
                System.exit(1);
            }
            out.writeBytes(BerObject.encode(v));
            n++;
        }
        Files.write(Path.of(args[2]), out.toByteArray());
    }

    private static int fuzz(String[] args) throws Exception {
        Class<? extends Asn1Pdu> type = Class.forName(args[1]).asSubclass(Asn1Pdu.class);
        int crashes = 0;
        for (int i = 2; i < args.length; i++) {
            BerReader r = new BerReader(Files.readAllBytes(Path.of(args[i])));
            try {
                while (!r.atEnd()) {
                    Asn1Pdu v = type.getDeclaredConstructor().newInstance();
                    BerObject.decode(v, r);
                    BerObject.encode(v);
                }
            } catch (DecodeException | EncodeException e) {
                // malformed input rejected: the expected outcome
            } catch (Throwable t) {
                crashes++;
                StackTraceElement[] st = t.getStackTrace();
                System.out.println("CRASH " + args[i] + ": " + t + (st.length > 0 ? " at " + st[0] : ""));
            }
        }
        return crashes > 0 ? 3 : 0;
    }
}
