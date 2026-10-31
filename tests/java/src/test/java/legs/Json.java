package legs;

import java.math.BigDecimal;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

/**
 * A minimal JSON reader for comparing JER texts as values, the way the xval
 * sweep compares asn1c's indented JER with ours: objects become maps (member
 * order is not significant, X.697 §24.3), numbers become their value as a
 * {@link BigDecimal} (a number with a fraction or exponent through its
 * double, so {@code 0.1} equals {@code 1.00000000000000006E-1}).
 */
final class Json {
    private final String s;
    private int i;

    private Json(String s) {
        this.s = s;
    }

    static Object parse(String text) {
        Json j = new Json(text);
        Object v = j.value();
        j.ws();
        if (j.i != text.length()) {
            throw new IllegalArgumentException("trailing JSON text at " + j.i + ": " + text);
        }
        return v;
    }

    private void ws() {
        while (i < s.length() && " \t\n\r".indexOf(s.charAt(i)) >= 0) {
            i++;
        }
    }

    private Object value() {
        ws();
        char c = s.charAt(i);
        switch (c) {
            case '{' -> {
                i++;
                Map<String, Object> m = new HashMap<>();
                ws();
                if (s.charAt(i) == '}') {
                    i++;
                    return m;
                }
                do {
                    ws();
                    String k = string();
                    ws();
                    expect(':');
                    m.put(k, value());
                    ws();
                } while (s.charAt(i++) == ',');
                if (s.charAt(i - 1) != '}') {
                    throw new IllegalArgumentException("expected '}' at " + (i - 1));
                }
                return m;
            }
            case '[' -> {
                i++;
                List<Object> l = new ArrayList<>();
                ws();
                if (s.charAt(i) == ']') {
                    i++;
                    return l;
                }
                do {
                    l.add(value());
                    ws();
                } while (s.charAt(i++) == ',');
                if (s.charAt(i - 1) != ']') {
                    throw new IllegalArgumentException("expected ']' at " + (i - 1));
                }
                return l;
            }
            case '"' -> {
                return string();
            }
            default -> {
                int start = i;
                while (i < s.length() && ",}] \t\n\r".indexOf(s.charAt(i)) < 0) {
                    i++;
                }
                String t = s.substring(start, i);
                return switch (t) {
                    case "true" -> Boolean.TRUE;
                    case "false" -> Boolean.FALSE;
                    case "null" -> "<null>";
                    default -> number(t);
                };
            }
        }
    }

    private static BigDecimal number(String t) {
        BigDecimal b = t.matches("-?\\d+") ? new BigDecimal(t) : new BigDecimal(Double.parseDouble(t));
        return b.signum() == 0 ? BigDecimal.ZERO : b.stripTrailingZeros();
    }

    private void expect(char c) {
        if (s.charAt(i++) != c) {
            throw new IllegalArgumentException("expected '" + c + "' at " + (i - 1));
        }
    }

    private String string() {
        expect('"');
        StringBuilder out = new StringBuilder();
        while (true) {
            char c = s.charAt(i++);
            if (c == '"') {
                return out.toString();
            }
            if (c != '\\') {
                out.append(c);
                continue;
            }
            char e = s.charAt(i++);
            switch (e) {
                case 'b' -> out.append('\b');
                case 'f' -> out.append('\f');
                case 'n' -> out.append('\n');
                case 'r' -> out.append('\r');
                case 't' -> out.append('\t');
                case 'u' -> {
                    out.append((char) Integer.parseInt(s.substring(i, i + 4), 16));
                    i += 4;
                }
                default -> out.append(e);
            }
        }
    }
}
