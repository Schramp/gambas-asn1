/*
 * Java port of nested-decoder/nested-decoder.cpp using asn1cpp-generated
 * types (--target=java).
 *
 * Reads a stream of BER-encoded PS-PDU records from a file and prints each
 * as XER. The types are generated with container_fields.json, so the outer
 * decode already decodes EncryptionContainer.encryptedPayload (encryptionType
 * `none`) as an EncryptedPayload with the zero_padding decoder.
 *
 * --xer-form hex (default) prints encryptedPayload as hex, then the inner
 * EncryptedPayload as a separate document after a "--- EncryptedPayload ---"
 * header: the same output as the C++ and asn1c nested decoders.
 * --xer-form inline / inline_raw prints the inner value inside the PS-PDU
 * (inline_raw adds the raw hex as a comment) and no separate document.
 *
 * Usage: java NestedDecoder [--xer-form hex|inline|inline_raw] <file.etsi>
 */

import etsi.EncryptedPayload;
import etsi.EncryptionContainer;
import etsi.PS_PDU;
import io.github.schramp.gambasasn1.wire.ber.BerObject;
import io.github.schramp.gambasasn1.wire.ber.BerReader;
import io.github.schramp.gambasasn1.wire.containing.ContainedOptions;
import io.github.schramp.gambasasn1.wire.io.DecodeException;
import io.github.schramp.gambasasn1.wire.spec.AsMemberRef;
import io.github.schramp.gambasasn1.wire.spec.ContainedStatus;
import io.github.schramp.gambasasn1.wire.spec.ContainedText;
import io.github.schramp.gambasasn1.wire.spec.Containing;
import io.github.schramp.gambasasn1.wire.xer.XerObject;
import java.io.BufferedOutputStream;
import java.io.FileDescriptor;
import java.io.FileOutputStream;
import java.io.IOException;
import java.io.PrintStream;
import java.nio.file.Files;
import java.nio.file.Path;

public final class NestedDecoder {
    private NestedDecoder() {
    }

    private static void xerPrint(PrintStream out, AsMemberRef value, ContainedOptions opts) {
        byte[] xer = XerObject.encode(value, opts);
        out.write(xer, 0, xer.length);
    }

    private static String statusName(ContainedStatus st) {
        return switch (st) {
            case NOT_DECODED -> "not decoded";
            case DECODED -> "decoded";
            case SKIPPED -> "skipped";
            case FAILED -> "failed";
        };
    }

    /** Reports an undecoded payload, or a decoder warning (non-zero padding), on stderr. */
    private static void reportInner(Containing<EncryptedPayload> ep) {
        if (ep.status() != ContainedStatus.DECODED) {
            System.err.printf("  inner: %s: %s%n", statusName(ep.status()), ep.error());
        } else if (!ep.error().isEmpty()) {
            System.err.printf("  inner: %s%n", ep.error());
        }
    }

    private static ContainedText parseForm(String s) {
        return switch (s) {
            case "hex" -> ContainedText.HEX;
            case "inline" -> ContainedText.INLINE;
            case "inline_raw" -> ContainedText.INLINE_RAW;
            default -> null;
        };
    }

    public static void main(String[] args) throws IOException {
        ContainedText form = ContainedText.HEX;
        String path = null;
        for (int i = 0; i < args.length; i++) {
            if (args[i].equals("--xer-form") && i + 1 < args.length) {
                form = parseForm(args[++i]);
                if (form == null) {
                    System.err.printf("--xer-form: expected hex, inline or inline_raw, got '%s'%n", args[i]);
                    System.exit(1);
                }
            } else if (path == null && !args[i].startsWith("-")) {
                path = args[i];
            } else {
                path = null;
                break;
            }
        }
        if (path == null) {
            System.err.println("Usage: java NestedDecoder [--xer-form hex|inline|inline_raw] <file.etsi>");
            System.exit(1);
        }

        ContainedOptions opts = new ContainedOptions(null, false, form, null);
        byte[] buf = Files.readAllBytes(Path.of(path));
        PrintStream out = new PrintStream(new BufferedOutputStream(new FileOutputStream(FileDescriptor.out)), false);
        BerReader reader = new BerReader(buf).withContained(opts);

        int pduNum = 0;
        int innerDecoded = 0;
        while (!reader.atEnd()) {
            int offset = reader.source().position();
            PS_PDU pdu = new PS_PDU();
            try {
                BerObject.decode(pdu, reader);
            } catch (DecodeException e) {
                System.err.printf("Outer BER decode failed at offset %d (PDU #%d): %s%n",
                        offset, pduNum + 1, e.getMessage());
                break;
            }
            ++pduNum;
            out.printf("=== PS-PDU #%d ===%n", pduNum);
            xerPrint(out, pdu, opts);

            EncryptionContainer ec = pdu.payload().encryptionContainer();
            if (ec == null) {
                continue;
            }
            Containing<EncryptedPayload> ep = ec.encryptedPayload();
            if (form == ContainedText.HEX) {
                byte[] data = ep.bytes();
                int stripped = data.length;
                while (stripped > 0 && data[stripped - 1] == 0) {
                    --stripped;
                }
                out.printf("--- EncryptedPayload (%d bytes, %d zero-padded) ---%n", stripped, data.length - stripped);
            }
            reportInner(ep);
            if (ep.value() == null) {
                continue;
            }
            ++innerDecoded;
            if (form == ContainedText.HEX) {
                xerPrint(out, ep.value(), opts);
            }
        }
        out.flush();
        System.err.printf("Decoded %d outer PS-PDUs, %d with inner EncryptedPayload%n", pduNum, innerDecoded);
    }
}
