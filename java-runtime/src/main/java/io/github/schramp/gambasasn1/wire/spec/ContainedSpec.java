package io.github.schramp.gambasasn1.wire.spec;

/**
 * Table row of an OCTET STRING that holds the encoding of another type
 * (X.682 §11, or configured with --container-config). The inner type is the
 * field's own {@link Containing} parameter.
 *
 * @param encoding    encoding rules of the contained bytes
 * @param eager       decode the contained value together with the outer value
 * @param decoder     name of the contained value's decoder
 * @param whenMember  index of the sibling member that enables decoding, or -1 for always
 * @param whenValue   value of that sibling (enumeration number, integer, 0/1) that enables it
 * @param failOnError a contained value that does not decode fails the outer decode
 * @param xer         XER form
 * @param jer         JER form
 * @param builtin     index of {@code decoder} among the built-in decoders, or {@link #CUSTOM_DECODER}
 */
public record ContainedSpec(ContainedEncoding encoding, boolean eager, String decoder, int whenMember, long whenValue,
        boolean failOnError, ContainedText xer, ContainedText jer, int builtin) {
    /** Built-in decoder names, in {@code builtin} order. */
    public static final java.util.List<String> BUILTIN_DECODERS = java.util.List.of("plain", "zero_padding", "pkcs7", "none");
    /** {@code builtin} for a decoder that is not a built-in one. */
    public static final int CUSTOM_DECODER = 255;
}
