package legs;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import gen.recursion_ber.A;
import gen.recursion_choice_ber.Expr;
import gen.recursion_ber.List;
import gen.recursion_ber.Tree;
import io.github.schramp.gambasasn1.wire.ber.BerObject;
import io.github.schramp.gambasasn1.wire.io.DecodeException;
import io.github.schramp.gambasasn1.wire.io.Nesting;
import io.github.schramp.gambasasn1.wire.spec.Asn1Pdu;
import java.util.Map;
import java.util.function.Supplier;
import java.util.stream.Stream;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.MethodSource;

/**
 * Recursive types under BER, against asn1c's DER for
 * tests/asn1/recursion_ber_test.asn1 and recursion_choice_ber_test.asn1, and the decode nesting limit
 * ({@link Nesting#MAX_DECODE_DEPTH}): each SEQUENCE, CHOICE and
 * SEQUENCE OF level counts one.
 */
class RecursionBerTest {
    static final Map<String, Supplier<Asn1Pdu>> TYPES = Map.ofEntries(
            Map.entry("List", List::new),
            Map.entry("Tree", Tree::new),
            Map.entry("A", A::new),
            Map.entry("Expr", Expr::new));

    static Stream<Vectors.Vector> vectors() {
        return Stream.concat(Vectors.load("recursion_ber_test.vectors").stream(),
                Vectors.load("recursion_choice_ber_test.vectors").stream());
    }

    @ParameterizedTest(name = "{0}")
    @MethodSource("vectors")
    void decodesAsn1cDerAndReencodesIt(Vectors.Vector vec) {
        Asn1Pdu v = TYPES.get(vec.type()).get();
        BerObject.decode(v, vec.der());
        assertArrayEquals(vec.der(), BerObject.encode(v));
    }

    /** A List of {@code n} elements: {@code n} SEQUENCE levels. */
    private static byte[] list(int n) {
        List head = new List();
        List cur = head;
        for (int i = 1; i < n; i++) {
            List next = new List();
            next.v().set(i);
            cur.next(next);
            cur = next;
        }
        return BerObject.encode(head);
    }

    /** An Expr of {@code n} CHOICE levels: {@code n - 1} negs around a num. */
    private static byte[] negs(int n) {
        Expr e = new Expr();
        e.num().set(1);
        for (int i = 1; i < n; i++) {
            Expr outer = new Expr();
            outer.neg(e);
            e = outer;
        }
        return BerObject.encode(e);
    }

    @Test
    void decodesUpToTheNestingLimit() {
        byte[] der = list(Nesting.MAX_DECODE_DEPTH);
        List v = new List();
        BerObject.decode(v, der);
        assertArrayEquals(der, BerObject.encode(v));

        byte[] choice = negs(Nesting.MAX_DECODE_DEPTH);
        Expr e = new Expr();
        BerObject.decode(e, choice);
        assertArrayEquals(choice, BerObject.encode(e));
    }

    @Test
    void rejectsNestingPastTheLimit() {
        DecodeException seq = assertThrows(DecodeException.class,
                () -> BerObject.decode(new List(), list(Nesting.MAX_DECODE_DEPTH + 1)));
        assertTrue(seq.getMessage().contains(Nesting.tooDeep()), seq.getMessage());
        DecodeException choice = assertThrows(DecodeException.class,
                () -> BerObject.decode(new Expr(), negs(Nesting.MAX_DECODE_DEPTH + 1)));
        assertTrue(choice.getMessage().contains(Nesting.tooDeep()), choice.getMessage());
    }

    @Test
    void depthIsCountedPerDecode() {
        byte[] der = list(Nesting.MAX_DECODE_DEPTH);
        for (int i = 0; i < 3; i++) {
            BerObject.decode(new List(), der);
        }
    }

    @Test
    void recursiveValuesCompareByValue() {
        Tree a = new Tree();
        Tree b = new Tree();
        Tree kid = new Tree();
        kid.label().set("k");
        a.kids().add(kid);
        assertTrue(!a.equals(b));
        Tree kid2 = new Tree();
        kid2.label().set("k");
        b.kids().add(kid2);
        assertEquals(a, b);
        assertEquals(a.hashCode(), b.hashCode());
    }
}
