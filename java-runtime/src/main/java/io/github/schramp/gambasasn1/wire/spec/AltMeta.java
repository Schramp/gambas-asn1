package io.github.schramp.gambasasn1.wire.spec;

/**
 * One CHOICE alternative row.
 *
 * @param name           ASN.1 identifier, verbatim
 * @param ber            BER framing (X.690 §8.14)
 * @param constraints    the alternative's PER-visible constraints
 * @param xerInstruction X.693 §21 override
 * @param contained      contained-value settings, or null
 */
public record AltMeta(String name, BerTagging ber, Constraints constraints, XerInstruction xerInstruction,
        ContainedSpec contained) {
}
