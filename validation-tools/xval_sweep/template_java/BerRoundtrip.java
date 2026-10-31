package xvalharness;

import io.github.schramp.gambasasn1.wire.ber.BerObject;
import io.github.schramp.gambasasn1.wire.ber.BerReader;
import io.github.schramp.gambasasn1.wire.io.DecodeException;
import io.github.schramp.gambasasn1.wire.io.EncodeException;
import io.github.schramp.gambasasn1.wire.jer.JerObject;
import io.github.schramp.gambasasn1.wire.spec.Asn1Pdu;
import io.github.schramp.gambasasn1.wire.xer.XerObject;
import java.io.ByteArrayOutputStream;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.ArrayList;
import java.util.List;
import java.util.function.BiConsumer;
import java.util.function.Function;

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
 *
 * <p>{@code BerRoundtrip --b2x CLASS IN OUT}: decodes the BER records of IN
 * and writes each one's XER document to OUT, followed by an empty line, the
 * output of the C++ leg's ber-to-xer. The first BER decode error stops the
 * run; a record that fails to XER-encode is skipped.
 *
 * <p>{@code BerRoundtrip --x2b CLASS IN OUT}: splits IN into XER documents
 * (an open tag at column 0 starts one, a close tag at column 0 ends it) and
 * writes each one's BER encoding to OUT. A document that fails is skipped.
 *
 * <p>{@code BerRoundtrip --b2j CLASS IN OUT} and {@code --j2b CLASS IN OUT}
 * are the JER counterparts, the output of the C++ leg's ber-to-jer: one
 * compact JER text per line, each non-blank line one record.
 * All four text modes exit 1 when any record failed.
 */
public final class BerRoundtrip {
    private BerRoundtrip() {
    }

    public static void main(String[] args) throws Exception {
        if (args.length >= 2 && args[0].equals("--fuzz")) {
            System.exit(fuzz(args));
        }
        if (args.length == 4 && args[0].equals("--b2x")) {
            System.exit(berToText("XER", XerObject::encode, pduClass(args[1]), Path.of(args[2]), Path.of(args[3])));
        }
        if (args.length == 4 && args[0].equals("--x2b")) {
            String text = new String(Files.readAllBytes(Path.of(args[2])), StandardCharsets.UTF_8);
            List<byte[]> records = splitXerRecords(text).stream().map(t -> t.getBytes(StandardCharsets.UTF_8)).toList();
            System.exit(textToBer("XER", XerObject::decode, records, pduClass(args[1]), Path.of(args[3])));
        }
        if (args.length == 4 && args[0].equals("--b2j")) {
            System.exit(berToText("JER", JerObject::encode, pduClass(args[1]), Path.of(args[2]), Path.of(args[3])));
        }
        if (args.length == 4 && args[0].equals("--j2b")) {
            System.exit(textToBer("JER", JerObject::decode, splitLines(Files.readAllBytes(Path.of(args[2]))),
                    pduClass(args[1]), Path.of(args[3])));
        }
        if (args.length != 3) {
            System.err.println("usage: BerRoundtrip CLASS IN OUT | --fuzz CLASS FILE..."
                    + " | --b2x|--x2b|--b2j|--j2b CLASS IN OUT");
            System.exit(2);
        }
        Class<? extends Asn1Pdu> type = pduClass(args[0]);
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

    private static Class<? extends Asn1Pdu> pduClass(String name) throws ClassNotFoundException {
        return Class.forName(name).asSubclass(Asn1Pdu.class);
    }

    private static int berToText(String codec, Function<Asn1Pdu, byte[]> encode, Class<? extends Asn1Pdu> type,
            Path in, Path out) throws Exception {
        BerReader r = new BerReader(Files.readAllBytes(in));
        ByteArrayOutputStream text = new ByteArrayOutputStream();
        int n = 0;
        int errors = 0;
        while (!r.atEnd()) {
            Asn1Pdu v = type.getDeclaredConstructor().newInstance();
            int offset = r.position();
            try {
                BerObject.decode(v, r);
            } catch (RuntimeException e) {
                System.err.println("BER decode failed record #" + n + " at offset " + offset + ": " + e);
                errors++;
                break;
            }
            try {
                text.writeBytes(encode.apply(v));
                text.write('\n');
            } catch (RuntimeException e) {
                System.err.println(codec + " encode failed record #" + n + " at offset " + offset + ": " + e);
                errors++;
            }
            n++;
        }
        Files.write(out, text.toByteArray());
        return errors > 0 ? 1 : 0;
    }

    private static int textToBer(String codec, BiConsumer<Asn1Pdu, byte[]> decode, List<byte[]> records,
            Class<? extends Asn1Pdu> type, Path out) throws Exception {
        ByteArrayOutputStream ber = new ByteArrayOutputStream();
        int n = 0;
        int errors = 0;
        for (byte[] rec : records) {
            Asn1Pdu v = type.getDeclaredConstructor().newInstance();
            try {
                decode.accept(v, rec);
                ber.writeBytes(BerObject.encode(v));
            } catch (RuntimeException e) {
                System.err.println(codec + " record #" + n + ": " + e);
                errors++;
            }
            n++;
        }
        Files.write(out, ber.toByteArray());
        return errors > 0 ? 1 : 0;
    }

    /** The non-blank lines of {@code data}, as bytes: a JER text holds no raw newline. */
    private static List<byte[]> splitLines(byte[] data) {
        List<byte[]> lines = new ArrayList<>();
        int start = 0;
        for (int i = 0; i <= data.length; i++) {
            if (i == data.length || data[i] == '\n') {
                byte[] line = java.util.Arrays.copyOfRange(data, start, i);
                if (!new String(line, StandardCharsets.ISO_8859_1).isBlank()) {
                    lines.add(line);
                }
                start = i + 1;
            }
        }
        return lines;
    }

    private static List<String> splitXerRecords(String text) {
        List<String> records = new ArrayList<>();
        StringBuilder current = new StringBuilder();
        boolean inside = false;
        for (String line : text.split("\n", -1)) {
            boolean open = line.startsWith("<") && !line.startsWith("</");
            if (open && inside && !current.isEmpty()) {
                records.add(current.toString());
                current.setLength(0);
            }
            inside |= open;
            if (inside) {
                current.append(line).append('\n');
            }
            if (line.startsWith("</")) {
                records.add(current.toString());
                current.setLength(0);
                inside = false;
            }
        }
        if (!current.toString().isBlank()) {
            records.add(current.toString());
        }
        return records;
    }

    private static int fuzz(String[] args) throws Exception {
        Class<? extends Asn1Pdu> type = pduClass(args[1]);
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
