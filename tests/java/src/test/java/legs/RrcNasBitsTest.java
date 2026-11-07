package legs;

import io.github.schramp.gambasasn1.wire.io.DecodeException;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;

import gen.rrc.CN_DomainIdentity;
import gen.rrc.DownlinkDirectTransfer;
import gen.rrc.NAS_Message;
import io.github.schramp.gambasasn1.wire.per.PerObject;
import io.github.schramp.gambasasn1.wire.spec.Positions;
import java.util.HexFormat;
import org.junit.jupiter.api.Test;

/**
 * Bit-exact positions in unaligned PER (X.691): the NAS message carried in an
 * RRC DownlinkDirectTransfer (3GPP TS 25.331) starts and ends off a byte
 * boundary, and its value bits read straight from the encoding are the
 * octets the decoder returned. The encoding is asn1c's UPER output for
 * r3 { rrc-TransactionIdentifier 2, cn-DomainIdentity ps-domain,
 * nas-Message '0508'H }.
 */
class RrcNasBitsTest {
    private static final byte[] UPER = HexFormat.of().parseHex("2800828400");

    /** {@code n} octets read from {@code data} starting at bit {@code bit}, most significant bit first. */
    private static byte[] bitsAt(byte[] data, long bit, int n) {
        byte[] out = new byte[n];
        for (int i = 0; i < 8 * n; i++) {
            long b = bit + i;
            int v = (data[(int) (b / 8)] >> (7 - (int) (b % 8))) & 1;
            out[i / 8] |= (byte) (v << (7 - i % 8));
        }
        return out;
    }

    @Test
    void nasMessageValueBitsAreTheDecodedOctets() throws DecodeException {
        DownlinkDirectTransfer msg = new DownlinkDirectTransfer();
        Positions p = PerObject.decodeWithPositions(msg, UPER, null).positions();
        var ies = msg.r3().downlinkDirectTransfer_r3();
        assertEquals(2, ies.rrc_TransactionIdentifier().value.get());
        assertEquals(CN_DomainIdentity.Value.ps_domain, ies.cn_DomainIdentity().get());
        NAS_Message nas = ies.nas_Message();
        assertArrayEquals(new byte[] {0x05, 0x08}, nas.value.get());

        // 1 bit CHOICE index, 1 bit preamble, 2 + 1 bits, then a 12-bit length.
        assertEquals(17, p.valueBitOffset(nas));
        assertEquals(33, p.valueEndBitOffset(nas));
        assertEquals(16, p.valueSizeBits(nas));
        assertEquals(33, p.endBitOffset(msg));
        assertArrayEquals(nas.value.get(), bitsAt(UPER, p.valueBitOffset(nas), (int) (p.valueSizeBits(nas) / 8)));

        assertArrayEquals(UPER, PerObject.encode(msg));
    }
}
