package io.github.schramp.gambasasn1.wire.spec;

import io.github.schramp.gambasasn1.wire.ber.Tag;
import java.util.List;

/**
 * Table of a CHOICE type (X.680 §29).
 *
 * @param name         ASN.1 type name
 * @param alternatives alternative rows, in declaration order
 * @param berTags      dispatch table, sorted by {@link Tag#IDENTIFIER_ORDER}
 * @param ownTag       the CHOICE type's own tag, or null when untagged
 * @param extAt        index of the first extension alternative, or -1
 * @param rangeBits    bits of the root alternative index (X.691 §22.6)
 * @param hasContained some alternative holds a contained value
 */
public record ChoiceSpec(String name, List<AltMeta> alternatives, List<BerDispatch> berTags, Tag ownTag,
        int extAt, int rangeBits, boolean hasContained) {
}
