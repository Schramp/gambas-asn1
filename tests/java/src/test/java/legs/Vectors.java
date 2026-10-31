package legs;

import java.io.IOException;
import java.io.UncheckedIOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.HexFormat;
import java.util.List;

/**
 * A tests/vectors/*.vectors file: asn1c's DER for each listed XER value and,
 * where the file has them, asn1c's own XER and JER output for that DER.
 */
record Vectors(List<Vector> rows) {

    /** {@code asn1cXer} and {@code asn1cJer} are null for a file made before that column existed. */
    record Vector(String type, String xer, byte[] der, String asn1cXer, String asn1cJer) {
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
                    .map(l -> l.split("\t", 5))
                    .map(f -> new Vector(f[0], f[1], HexFormat.of().parseHex(f[2]),
                            f.length > 3 ? unescape(f[3]) : null, f.length > 4 ? unescape(f[4]) : null))
                    .toList();
        } catch (IOException e) {
            throw new UncheckedIOException(e);
        }
    }

    /** The reverse of make_ber_vectors.py's escape: {@code \\}, {@code \n}, {@code \t}. */
    private static String unescape(String s) {
        StringBuilder out = new StringBuilder(s.length());
        for (int i = 0; i < s.length(); i++) {
            char c = s.charAt(i);
            if (c == '\\' && i + 1 < s.length()) {
                char n = s.charAt(++i);
                out.append(n == 'n' ? '\n' : n == 't' ? '\t' : n);
            } else {
                out.append(c);
            }
        }
        return out.toString();
    }
}
