package legs;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;

import gen.etsi.IPAccessPDU.IPCCContents;
import gen.etsi.LI_PS_PDU.EncryptedPayload;
import gen.etsi.LI_PS_PDU.PS_PDU;
import io.github.schramp.gambasasn1.wire.ber.BerObject;
import io.github.schramp.gambasasn1.wire.ber.BerReader;
import io.github.schramp.gambasasn1.wire.query.Extract;
import io.github.schramp.gambasasn1.wire.query.Extraction;
import io.github.schramp.gambasasn1.wire.spec.Containing;
import io.github.schramp.gambasasn1.wire.spec.Decoded;
import io.github.schramp.gambasasn1.wire.spec.Positions;
import io.github.schramp.gambasasn1.wire.types.Asn1OctetString;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;
import org.junit.jupiter.api.Test;

/**
 * File offsets of CC IP packets (ETSI TS 102 232-3 IPCCContents.iPPackets)
 * from decode positions: records decoded back to back, each based at its
 * offset in the file, give the byte range of every packet's contents octets,
 * also for a packet inside a decoded EncryptionContainer.encryptedPayload.
 * The file bytes at that range are the packet, and an IPv4 header's total
 * length (RFC 791) equals the range's length.
 */
class CcOffsetsTest {
    private static byte[] sample() throws IOException {
        return Files.readAllBytes(Path.of(System.getProperty("etsi.sample")));
    }

    private static List<PS_PDU> decodeAll(byte[] file) {
        List<PS_PDU> out = new ArrayList<>();
        BerReader r = new BerReader(file);
        while (!r.atEnd()) {
            PS_PDU pdu = new PS_PDU();
            BerObject.decode(pdu, r);
            out.add(pdu);
        }
        return out;
    }

    /** An IPv4 packet: a 20-octet header (no options) for {@code proto} from 10.0.0.{@code host}, then {@code payload} octets. */
    private static byte[] ipv4(int proto, int host, int payload) {
        byte[] p = new byte[20 + payload];
        p[0] = 0x45;
        p[2] = (byte) (p.length >> 8);
        p[3] = (byte) p.length;
        p[8] = 64;
        p[9] = (byte) proto;
        p[12] = 10;
        p[15] = (byte) host;
        p[16] = (byte) 192;
        p[17] = (byte) 168;
        p[19] = 1;
        for (int i = 20; i < p.length; i++) {
            p[i] = (byte) i;
        }
        return p;
    }

    private record Range(int from, int to, byte[] packet) {
    }

    /** Every iPPackets of every record in {@code file}, with its byte range in the file. */
    private static List<Range> packetRanges(byte[] file) {
        List<Range> out = new ArrayList<>();
        BerReader r = new BerReader(file);
        while (!r.atEnd()) {
            long base = 8L * r.position();
            PS_PDU pdu = new PS_PDU();
            Decoded d = BerObject.decodeWithPositions(pdu, r);
            Positions p = d.positions().withBase(base);
            for (Extraction.Hit<IPCCContents> hit : Extract.all(pdu, d, IPCCContents.class)) {
                Asn1OctetString packet = hit.value().iPPackets();
                if (packet != null) {
                    out.add(new Range((int) (p.contentsBitOffset(packet) / 8),
                            (int) (p.contentsEndBitOffset(packet) / 8), packet.get()));
                }
            }
        }
        return out;
    }

    @Test
    void sampleRangesHoldTheDecodedPackets() throws IOException {
        byte[] file = sample();
        List<Range> ranges = packetRanges(file);
        assertEquals(1, ranges.size());
        for (Range g : ranges) {
            assertArrayEquals(g.packet(), Arrays.copyOfRange(file, g.from(), g.to()));
        }
    }

    @Test
    void ipv4PacketsInEncryptedPayloadsAreFoundAtTheirFileOffsets() throws IOException {
        List<PS_PDU> records = decodeAll(sample());
        PS_PDU carrier = null;
        PS_PDU filler = null;
        for (PS_PDU pdu : records) {
            if (Extract.all(pdu, IPCCContents.class).isEmpty()) {
                filler = filler == null ? pdu : filler;
            } else if (pdu.payload().encryptionContainer() != null) {
                carrier = carrier == null ? pdu : carrier;
            }
        }
        assertNotNull(carrier, "the sample holds a CC IP packet inside an EncryptedPayload");
        assertNotNull(filler, "the sample holds a record without CC IP packets");

        // Each packet in its own carrier record, with a record without packets between them.
        List<byte[]> packets = List.of(ipv4(17, 1, 8), ipv4(6, 2, 300), ipv4(1, 3, 0));
        ByteArrayOutputStream file = new ByteArrayOutputStream();
        for (byte[] packet : packets) {
            Containing<EncryptedPayload> ep = carrier.payload().encryptionContainer().encryptedPayload();
            Extract.all(ep.edit(), IPCCContents.class).get(0).iPPackets().set(packet);
            file.writeBytes(BerObject.encode(carrier));
            file.writeBytes(BerObject.encode(filler));
        }
        byte[] all = file.toByteArray();

        List<Range> ranges = packetRanges(all);
        assertEquals(packets.size(), ranges.size());
        for (int i = 0; i < packets.size(); i++) {
            Range g = ranges.get(i);
            byte[] atRange = Arrays.copyOfRange(all, g.from(), g.to());
            assertArrayEquals(packets.get(i), atRange);
            assertArrayEquals(g.packet(), atRange);
            assertEquals(atRange.length, (atRange[2] & 0xFF) << 8 | (atRange[3] & 0xFF));
        }
    }
}
