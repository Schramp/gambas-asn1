package io.github.schramp.gambasasn1.wire.spec;

import io.github.schramp.gambasasn1.wire.ber.Tag;
import java.util.List;

/**
 * Table of a SEQUENCE or SET type (X.680 §25, §27).
 *
 * @param name                ASN.1 type name
 * @param tag                 the type's own tag
 * @param members             member rows, in declaration order
 * @param extAt               index of the first extension member, or -1
 * @param romsCount           OPTIONAL/DEFAULT root members: PER preamble width (X.691 §19.2)
 * @param isSet               a SET: members are in canonical tag order (X.680 §8.6), and BER decode
 *                            accepts the components in any order (X.690 §8.11.2)
 * @param extUnits            PER extension additions; empty means every extension member is its own unit
 * @param groupMemberOptional per member (table order): declared OPTIONAL/DEFAULT inside its extension
 *                            addition group; empty when there are no groups
 * @param containedMembers    indices of members that hold contained values
 */
public record SequenceSpec(String name, Tag tag, List<MemberMeta> members, int extAt, int romsCount, boolean isSet,
        List<ExtUnit> extUnits, List<Boolean> groupMemberOptional, List<Integer> containedMembers) {
}
