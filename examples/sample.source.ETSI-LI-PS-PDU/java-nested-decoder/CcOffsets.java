/*
 * Prints where the IP packets of the CC payloads (ETSI TS 102 232-3
 * IPCCContents.iPPackets) lie in a file of BER-encoded PS-PDU records.
 *
 * Each record is decoded with positions, based at the record's offset in the
 * file, so every offset is a file offset, also for a packet inside a decoded
 * EncryptionContainer.encryptedPayload (container_fields.json). For each
 * packet it prints the byte range of its contents octets and, when they hold
 * an IPv4 header whose total length matches, its addresses and protocol.
 * It checks that the file bytes at that range are the decoded packet and
 * exits with status 1 when they are not.
 *
 * Usage: java CcOffsets <file.etsi>
 */

import etsi.IPAccessPDU.IPCCContents;
import etsi.LI_PS_PDU.PS_PDU;
import io.github.schramp.gambasasn1.wire.ber.BerObject;
import io.github.schramp.gambasasn1.wire.ber.BerReader;
import io.github.schramp.gambasasn1.wire.containing.ContainedOptions;
import io.github.schramp.gambasasn1.wire.query.Extract;
import io.github.schramp.gambasasn1.wire.query.Extraction;
import io.github.schramp.gambasasn1.wire.spec.ContainedText;
import io.github.schramp.gambasasn1.wire.spec.Decoded;
import io.github.schramp.gambasasn1.wire.spec.Positions;
import io.github.schramp.gambasasn1.wire.types.Asn1OctetString;
import java.io.IOException;
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
        byte[] file = Files.readAllBytes(Path.of(args[0]));
        BerReader reader = new BerReader(file).withContained(new ContainedOptions(null, false, ContainedText.HEX, null));
        int pduNum = 0;
        boolean ok = true;
        while (!reader.atEnd()) {
            long base = 8L * reader.source().position();
            PS_PDU pdu = new PS_PDU();
            Decoded d = BerObject.decodeWithPositions(pdu, reader);
            Positions p = d.positions().withBase(base);
            ++pduNum;
            for (Extraction.Hit<IPCCContents> hit : Extract.all(pdu, d, IPCCContents.class)) {
                Asn1OctetString packet = hit.value().iPPackets();
                if (packet == null) {
                    continue;
                }
                int from = (int) (p.contentsBitOffset(packet) / 8);
                int to = (int) (p.contentsEndBitOffset(packet) / 8);
                byte[] atRange = Arrays.copyOfRange(file, from, to);
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
