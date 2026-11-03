package legs;

import static org.junit.jupiter.api.Assertions.assertInstanceOf;
import static org.junit.jupiter.api.Assertions.assertTrue;

import io.github.schramp.gambasasn1.wire.ber.BerObject;
import io.github.schramp.gambasasn1.wire.ber.BerReader;
import io.github.schramp.gambasasn1.wire.query.ExtractPlan;
import io.github.schramp.gambasasn1.wire.query.Extraction;
import io.github.schramp.gambasasn1.wire.types.Asn1GeneralizedTime;
import io.github.schramp.gambasasn1.wire.types.Asn1UtcTime;
import io.github.schramp.gambasasn1.wire.types.TimeParse;
import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.List;
import org.junit.jupiter.api.Test;

/** Every time value in the ETSI sample reads as a time. */
class TimesTest {
    @Test
    void etsiSampleTimesParse() throws IOException {
        ExtractPlan plan = ExtractPlan.of(gen.etsi.LI_PS_PDU.PS_PDU::new,
                List.of(Asn1GeneralizedTime.class, Asn1UtcTime.class));
        BerReader r = new BerReader(Files.readAllBytes(Path.of(System.getProperty("etsi.sample"))));
        int n = 0;
        while (!r.atEnd()) {
            gen.etsi.LI_PS_PDU.PS_PDU pdu = new gen.etsi.LI_PS_PDU.PS_PDU();
            BerObject.decode(pdu, r);
            Extraction x = plan.run(pdu);
            for (Asn1GeneralizedTime t : x.values(Asn1GeneralizedTime.class)) {
                assertInstanceOf(TimeParse.Time.class, t.parse(), t.get());
                n++;
            }
            for (Asn1UtcTime t : x.values(Asn1UtcTime.class)) {
                assertInstanceOf(TimeParse.Time.class, t.parse(), t.get());
                n++;
            }
        }
        assertTrue(n > 0, "no time values in the sample");
    }
}
