package io.github.schramp.gambasasn1.wire.spec;

/**
 * An OCTET STRING that holds the encoding of another type (X.682 §11, or
 * configured with --container-config).
 *
 * @param decoder     name of the contained type's decoder
 * @param eager       decode the contained value together with the outer value
 * @param whenMember  index of the sibling member that selects the decoder, or -1
 * @param whenValue   value of that sibling for which this decoder applies
 * @param failOnError a contained value that does not decode fails the outer decode
 */
public record ContainedSpec(String decoder, boolean eager, int whenMember, long whenValue, boolean failOnError) {
}
