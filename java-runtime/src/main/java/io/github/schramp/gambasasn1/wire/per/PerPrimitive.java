package io.github.schramp.gambasasn1.wire.per;

import io.github.schramp.gambasasn1.wire.io.EncodeException;
import io.github.schramp.gambasasn1.wire.spec.Constraints;
import io.github.schramp.gambasasn1.wire.types.Asn1Boolean;
import io.github.schramp.gambasasn1.wire.types.Asn1Null;
import io.github.schramp.gambasasn1.wire.types.Asn1Primitive;

/**
 * Unaligned PER fields of the builtin leaf types: one switch over the
 * builtin wrappers, as in the C++ {@code PerCodec} and the Rust
 * {@code spec::primitive} dispatch. A value's own constraints pick its
 * field; a type with no PER field yet fails the encode or decode.
 */
public final class PerPrimitive {
    private PerPrimitive() {
    }

    /**
     * Appends {@code p}'s field.
     *
     * @param c its own PER-visible constraints
     */
    public static void encode(Asn1Primitive p, Constraints c, PerWriter w) {
        switch (p) {
            // X.691 §12: a single bit, 1 for TRUE.
            case Asn1Boolean b -> w.putBits(b.get() ? 1 : 0, 1);
            // X.691 §18: no field.
            case Asn1Null n -> {
            }
            default -> throw new EncodeException("PER: " + p.getClass().getSimpleName() + " is not supported yet");
        }
    }

    /**
     * Reads {@code p}'s field.
     *
     * @param c its own PER-visible constraints
     */
    public static void decode(Asn1Primitive p, Constraints c, PerReader r) {
        switch (p) {
            case Asn1Boolean b -> b.set(r.getBits(1) == 1);
            case Asn1Null n -> {
            }
            default -> throw r.error("PER: " + p.getClass().getSimpleName() + " is not supported yet");
        }
    }
}
