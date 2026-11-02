package io.github.schramp.gambasasn1.wire.per;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;

import io.github.schramp.gambasasn1.wire.io.DecodeException;
import io.github.schramp.gambasasn1.wire.io.EncodeException;
import io.github.schramp.gambasasn1.wire.spec.AsMemberRef;
import io.github.schramp.gambasasn1.wire.spec.EnumEntry;
import io.github.schramp.gambasasn1.wire.spec.EnumSlot;
import io.github.schramp.gambasasn1.wire.spec.EnumSpec;
import io.github.schramp.gambasasn1.wire.spec.MemberRef;
import java.util.ArrayList;
import java.util.HexFormat;
import java.util.List;
import org.junit.jupiter.api.Test;

/**
 * ENUMERATED in unaligned PER (X.691 §14), on the table of
 * {@code ENUMERATED { r0, r1, ..., e0, ..., e69 }}. The expected bytes are
 * asn1c's UPER for that type.
 */
class PerEnumeratedTest {
    private static final EnumSpec BIG;

    static {
        List<EnumEntry> entries = new ArrayList<>();
        entries.add(new EnumEntry(0, "r0"));
        entries.add(new EnumEntry(1, "r1"));
        for (int i = 0; i < 70; i++) {
            entries.add(new EnumEntry(2 + i, "e" + i));
        }
        BIG = new EnumSpec("Big", List.copyOf(entries), true, 2, 1);
    }

    /** A hand-written ENUMERATED value over {@link #BIG}. */
    private static final class Big implements EnumSlot, AsMemberRef {
        long value;

        Big(long value) {
            this.value = value;
        }

        @Override
        public long enumGet() {
            return value;
        }

        @Override
        public boolean enumSet(long v) {
            if (v < 0 || v >= BIG.entries().size()) {
                return false;
            }
            value = v;
            return true;
        }

        @Override
        public MemberRef asMemberRef() {
            return new MemberRef.Enumerated(this, BIG);
        }

        @Override
        public String ownElementXerName() {
            return "Big";
        }
    }

    private static byte[] hex(String s) {
        return HexFormat.of().parseHex(s);
    }

    @Test
    void rootAndExtensionItemsMatchAsn1c() {
        long[] values = {0, 1, 2, 65, 66, 71};
        String[] uper = {"00", "40", "80", "BF", "C05000", "C05140"};
        for (int i = 0; i < values.length; i++) {
            assertArrayEquals(hex(uper[i]), PerObject.encode(new Big(values[i])), "value " + values[i]);
            Big back = new Big(-1);
            PerObject.decode(back, hex(uper[i]));
            assertEquals(values[i], back.value);
        }
    }

    @Test
    void unknownItemsFail() {
        assertThrows(EncodeException.class, () -> PerObject.encode(new Big(99)));
        // Extension index 70 is past e69.
        assertThrows(DecodeException.class, () -> PerObject.decode(new Big(0), hex("C05180")));
    }

    /** X.691 §14.2: a root index beyond the root items has no value. */
    @Test
    void rootIndexBeyondTheRootFails() {
        EnumSpec three = new EnumSpec("Three", List.of(new EnumEntry(0, "a"), new EnumEntry(1, "b"),
                new EnumEntry(2, "c")), false, 3, 2);
        EnumSlot slot = new EnumSlot() {
            long v;

            @Override
            public long enumGet() {
                return v;
            }

            @Override
            public boolean enumSet(long value) {
                v = value;
                return true;
            }
        };
        AsMemberRef ref = new AsMemberRef() {
            @Override
            public MemberRef asMemberRef() {
                return new MemberRef.Enumerated(slot, three);
            }

            @Override
            public String ownElementXerName() {
                return "Three";
            }
        };
        PerObject.decode(ref, hex("80"));
        assertEquals(2, slot.enumGet());
        assertThrows(DecodeException.class, () -> PerObject.decode(ref, hex("C0")));
    }
}
