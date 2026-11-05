package legs;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;

import gen.promoted_name_clash.Pick;
import gen.promoted_name_clash.PickList;
import gen.promoted_name_clash.PickList_2;
import gen.promoted_name_clash.Rec;
import gen.promoted_name_clash.RecParties;
import gen.promoted_name_clash.RecParties_2;
import io.github.schramp.gambasasn1.wire.ber.BerObject;
import io.github.schramp.gambasasn1.wire.spec.SeqOf;
import io.github.schramp.gambasasn1.wire.types.Asn1Integer;
import org.junit.jupiter.api.Test;

/**
 * Inline SEQUENCE OF members and alternatives whose promoted name is already
 * a type assignment (tests/asn1/promoted_name_clash_test.asn1): the member
 * is declared with the generated collection class (RecParties_2), never
 * with the user's own type of the plain name (RecParties ::= INTEGER).
 */
class PromotedNameClashTest {
    @Test
    void sequenceMemberUsesTheCollectionClass() throws Exception {
        assertEquals(RecParties_2.class, Rec.class.getMethod("parties").getReturnType());
        assertTrue(SeqOf.class.isAssignableFrom(RecParties_2.class));
        assertNotEquals(RecParties.class, RecParties_2.class);
    }

    @Test
    void choiceAlternativeUsesTheCollectionClass() throws Exception {
        assertEquals(PickList_2.class, Pick.class.getMethod("list").getReturnType());
        assertTrue(SeqOf.class.isAssignableFrom(PickList_2.class));
        assertNotEquals(PickList.class, PickList_2.class);
    }

    @Test
    void collectionMemberRoundTripsAsSequenceOf() {
        Rec r = new Rec();
        r.parties().add(new Asn1Integer(1));
        r.parties().add(new Asn1Integer(2));
        r.n(new Asn1Integer(5));
        Rec back = new Rec();
        BerObject.decode(back, BerObject.encode(r));
        assertEquals(2, back.parties().size());
        assertEquals(2, back.parties().items().get(1).get());
        assertEquals(5, back.n().get());
    }
}
