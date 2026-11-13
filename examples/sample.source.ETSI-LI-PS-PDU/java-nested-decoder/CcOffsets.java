/*
 * Prints where the IP packets of the CC payloads (ETSI TS 102 232-3
 * IPCCContents.iPPackets) lie in a file of BER-encoded PS-PDU records.
 *
 * The file is read one record at a time (BerFrames). Each record is decoded
 * with positions, based at the record's offset in the file, so every offset is a file offset, also for a packet inside a decoded
 * EncryptionContainer.encryptedPayload (container_fields.json). For each
 * packet it prints the byte range of its contents octets and, when they hold
 * an IPv4 header whose total length matches, its addresses and protocol.
 * A packet sent in constructed form (segments) has no single range; it is
 * reported as such.
 * It checks that the record's bytes at that range are the decoded packet and
 * exits with status 1 when they are not.
 *
 * Usage: java CcOffsets <file.etsi>
 */

import etsi.IPAccessPDU.IPCCContents;
import etsi.LI_PS_PDU.PS_PDU;
import io.github.schramp.gambasasn1.wire.DecodeOptions;
import io.github.schramp.gambasasn1.wire.ber.BerFrames;
import io.github.schramp.gambasasn1.wire.ber.Frame;
import io.github.schramp.gambasasn1.wire.containing.ContainedOptions;
import io.github.schramp.gambasasn1.wire.io.DecodeException;
import io.github.schramp.gambasasn1.wire.query.Extract;
import io.github.schramp.gambasasn1.wire.query.Extraction;
import io.github.schramp.gambasasn1.wire.spec.ContainedText;
import io.github.schramp.gambasasn1.wire.spec.Decoded;
import io.github.schramp.gambasasn1.wire.spec.Positions;
import io.github.schramp.gambasasn1.wire.types.Asn1OctetString;
import java.io.BufferedInputStream;
import java.io.IOException;
import java.io.InputStream;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.Arrays;

public final class CcOffsets {
    private CcOffsets() {
    }

    /** "IPv4 a.b.c.d -> e.f.g.h proto N" when {@code p} is one whole IPv4 packet (RFC 791), else "not IPv4". */
    static String describe(byte[] p) {
        if (p.length < 20 || (p[0] & 0xF0) != 0x40 || (p[0] & 0x0F) < 5
                || ((p[2] & 0xFF) << 8 | (p[3] & 0xFF)) != p.length) {
            return "not IPv4";
        }
        return String.format("IPv4 %d.%d.%d.%d -> %d.%d.%d.%d proto %d",
                p[12] & 0xFF, p[13] & 0xFF, p[14] & 0xFF, p[15] & 0xFF,
                p[16] & 0xFF, p[17] & 0xFF, p[18] & 0xFF, p[19] & 0xFF, p[9] & 0xFF);
    }

    public static void main(String[] args) throws IOException {
        if (args.length != 1) {
            System.err.println("Usage: java CcOffsets <file.etsi>");
            System.exit(1);
        }
        DecodeOptions opts = DecodeOptions.DEFAULT
                .withContained(new ContainedOptions(null, false, ContainedText.HEX, null));
        InputStream in = new BufferedInputStream(Files.newInputStream(Path.of(args[0])));
        BerFrames frames = new BerFrames(in);
        int pduNum = 0;
        boolean ok = true;
        for (;;) {
            Frame frame;
            PS_PDU pdu = new PS_PDU();
            Decoded d;
            try {
                frame = frames.next();
                if (frame == null) {
                    break;
                }
                d = BerFrames.decodeWithPositions(pdu, frame, opts);
            } catch (DecodeException e) {
                System.err.printf("BER decode failed (PDU #%d): %s%n", pduNum + 1, e.getMessage());
                System.exit(1);
                return;
            }
            Positions p = d.positions();
            ++pduNum;
            for (Extraction.Hit<IPCCContents> hit : Extract.all(pdu, d, IPCCContents.class)) {
                Asn1OctetString packet = hit.value().iPPackets();
                if (packet == null) {
                    continue;
                }
                if (p.contentsBitOffset(packet) < 0) {
                    // Sent in constructed form (as CER does above 1000 octets): spread over segments.
                    System.out.printf("PS-PDU #%d  iPPackets  in segments, no single byte range (%d octets)  %s%n",
                            pduNum, packet.get().length, describe(packet.get()));
                    continue;
                }
                long from = p.contentsBitOffset(packet) / 8;
                long to = p.contentsEndBitOffset(packet) / 8;
                byte[] atRange = Arrays.copyOfRange(frame.bytes(),
                        (int) (from - frame.offset()), (int) (to - frame.offset()));
                boolean same = Arrays.equals(atRange, packet.get());
                ok &= same;
                System.out.printf("PS-PDU #%d  iPPackets  bytes %d..%d (%d octets)  %s%s%n",
                        pduNum, from, to, to - from, describe(atRange), same ? "" : "  MISMATCH");
            }
        }
        if (!ok) {
            System.err.println("CcOffsets: a file range differs from its decoded packet");
            System.exit(1);
        }
    }
}
