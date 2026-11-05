package legs;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import gen.zero_width_items.Fives;
import gen.zero_width_items.Flags;
import gen.zero_width_items.Nulls;
import gen.zero_width_items.Rows;
import io.github.schramp.gambasasn1.wire.io.DecodeException;
import io.github.schramp.gambasasn1.wire.per.PerObject;
import io.github.schramp.gambasasn1.wire.spec.Asn1SeqOf;
import io.github.schramp.gambasasn1.wire.spec.AsMemberRef;
import java.util.HexFormat;
import java.util.function.Supplier;
import org.junit.jupiter.api.Test;

/**
 * PER SEQUENCE OF/SET OF elements encoded in zero bits (X.691 §18,
 * §11.9.3.8): a list counting more than {@code Nesting.MAX_ZERO_WIDTH_ITEMS}
 * items is refused once an element takes no input. Elements that take input,
 * and many short lists, are not limited. Same UPER vectors as the C++ and
 * Rust legs (tests/per/test_zero_width_items.cpp).
 */
class ZeroWidthItemsTest {
    private static byte[] hex(String s) {
        return HexFormat.of().parseHex(s);
    }

    private static <T extends AsMemberRef & Asn1SeqOf> void accepts(Supplier<T> type, String h, int count) {
        T v = type.get();
        PerObject.decode(v, hex(h));
        assertEquals(count, v.size());
    }

    private static void refuses(AsMemberRef v, String h) {
        DecodeException e = assertThrows(DecodeException.class, () -> PerObject.decode(v, hex(h)));
        assertTrue(e.reason().contains("items encoded in zero bits"), e.getMessage());
    }

    @Test
    void nullsUpToTheLimitDecode() {
        accepts(Nulls::new, "80c8", 200);
        refuses(new Nulls(), "80c9");
    }

    @Test
    void fragmentedNullBombIsRefused() {
        refuses(new Nulls(), "c4".repeat(100) + "00");
    }

    @Test
    void singleValueIntegersCountAsZeroWidth() {
        accepts(Fives::new, "00c8", 200);
        refuses(new Fives(), "ea60");
    }

    @Test
    void elementsThatTakeInputAreNotLimited() {
        accepts(Flags::new, "83e8" + "ff".repeat(125), 1000);
        accepts(Rows::new, "812c" + "80c8".repeat(300), 300);
        accepts(Rows::new, "80c9" + "00".repeat(201), 201);
    }
}
