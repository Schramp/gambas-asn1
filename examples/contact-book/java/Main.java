// contact-book example in Java — encode a Contact to BER, decode it back,
// print as XER. The same steps as ../main.cpp, on the types asn1cpp
// generates with --target=java from ../contact.asn1. If you change the
// schema or main.cpp, update this file too.

import contacts.Contact;
import contacts.PhoneNumber;
import io.github.schramp.gambasasn1.wire.ber.BerObject;
import io.github.schramp.gambasasn1.wire.io.DecodeException;
import io.github.schramp.gambasasn1.wire.types.Asn1Ia5String;
import io.github.schramp.gambasasn1.wire.types.Asn1Integer;
import io.github.schramp.gambasasn1.wire.types.Asn1NumericString;
import io.github.schramp.gambasasn1.wire.types.Asn1Utf8String;
import io.github.schramp.gambasasn1.wire.xer.XerObject;
import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;

public final class Main {
    private Main() {
    }

    private static void encodeExample(Path out) throws IOException {
        Contact c = new Contact();
        c.name(new Asn1Utf8String("Alice Example"));

        // OPTIONAL members are null until set.
        c.email(new Asn1Ia5String("alice@example.com"));

        PhoneNumber phone = new PhoneNumber();
        phone.countryCode(new Asn1Integer(31));
        phone.number(new Asn1NumericString("612345678"));
        c.phone(phone);

        byte[] ber = BerObject.encode(c);
        Files.write(out, ber);
        System.out.println("[encode] wrote " + ber.length + " bytes to " + out);
    }

    private static void decodeAndPrint(Path in) throws IOException {
        Contact c = new Contact();
        try {
            BerObject.decode(c, Files.readAllBytes(in));
        } catch (DecodeException e) {
            System.err.println("[decode] error: " + e.getMessage());
            return;
        }
        System.out.write(XerObject.encode(c));
        System.out.println();
    }

    public static void main(String[] args) throws IOException {
        Path ber = Path.of(args.length > 0 ? args[0] : "/tmp/contact.ber");
        encodeExample(ber);
        decodeAndPrint(ber);
    }
}
