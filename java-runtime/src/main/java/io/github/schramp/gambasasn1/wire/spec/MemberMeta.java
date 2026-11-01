package io.github.schramp.gambasasn1.wire.spec;

import io.github.schramp.gambasasn1.wire.ber.Tag;

/**
 * One SEQUENCE/SET member row.
 *
 * @param name           ASN.1 identifier, verbatim
 * @param tag            the tag the member starts with on the wire
 * @param optional       OPTIONAL, DEFAULT or an extension member
 * @param ber            BER framing (X.690 §8.14)
 * @param constraints    the member's PER-visible constraints
 * @param xerInstruction X.693 §21 override
 * @param contained      contained-value settings, or null
 */
public record MemberMeta(String name, Tag tag, boolean optional, BerTagging ber, Constraints constraints,
        XerInstruction xerInstruction, ContainedSpec contained) {
}
