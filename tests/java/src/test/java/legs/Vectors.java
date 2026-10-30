package legs;

import java.io.IOException;
import java.io.UncheckedIOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.HexFormat;
import java.util.List;

/** A tests/vectors/*.vectors file: asn1c's DER for each listed XER value. */
record Vectors(List<Vector> rows) {

    record Vector(String type, String xer, byte[] der) {
        @Override
        public String toString() {
            return type + " " + xer;
        }
    }

    static List<Vector> load(String name) {
        Path p = Path.of(System.getProperty("vectors.dir"), name);
        try {
            return Files.readAllLines(p).stream()
                    .filter(l -> !l.isEmpty() && !l.startsWith("#"))
                    .map(l -> l.split("\t", 3))
                    .map(f -> new Vector(f[0], f[1], HexFormat.of().parseHex(f[2])))
                    .toList();
        } catch (IOException e) {
            throw new UncheckedIOException(e);
        }
    }
}
