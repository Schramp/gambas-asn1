package xvalharness;

import io.github.schramp.gambasasn1.wire.ber.BerObject;
import io.github.schramp.gambasasn1.wire.ber.BerReader;
import io.github.schramp.gambasasn1.wire.spec.Asn1Pdu;
import java.io.ByteArrayOutputStream;
import java.nio.file.Files;
import java.nio.file.Path;

/**
 * xval_sweep's Java leg: decodes the back-to-back BER records of IN as
 * CLASS and writes their re-encodings to OUT. A record that fails to
 * decode stops the run with exit 1 and its index on stderr.
 *
 * <p>Usage: {@code BerRoundtrip CLASS IN OUT}
 */
public final class BerRoundtrip {
    private BerRoundtrip() {
    }

    public static void main(String[] args) throws Exception {
        if (args.length != 3) {
            System.err.println("usage: BerRoundtrip CLASS IN OUT");
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
}
