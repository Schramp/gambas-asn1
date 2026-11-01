package io.github.schramp.gambasasn1.wire.per;

import io.github.schramp.gambasasn1.wire.io.EncodeException;
import io.github.schramp.gambasasn1.wire.spec.AsMemberRef;
import io.github.schramp.gambasasn1.wire.spec.Asn1Pdu;
import io.github.schramp.gambasasn1.wire.spec.Constraints;
import io.github.schramp.gambasasn1.wire.spec.MemberRef;

/**
 * The unaligned PER walker (X.691): one complete encoding per value,
 * driven by the reflective {@link MemberRef} shape of the generated tables;
 * no type has PER code of its own. Constructs whose PER fields are not
 * written yet fail the encode or decode.
 */
public final class PerObject {
    private PerObject() {
    }

    /** Encodes {@code v} as one complete encoding, under its own PDU constraints when it is a PDU. */
    public static byte[] encode(AsMemberRef v) {
        return encode(v, rootConstraints(v));
    }

    /** {@link #encode(AsMemberRef)} under the constraints {@code c} of {@code v}'s type. */
    public static byte[] encode(AsMemberRef v, Constraints c) {
        PerWriter w = new PerWriter();
        encodeValue(v.asMemberRef(), c, w);
        return w.toByteArray();
    }

    /**
     * Decodes one complete encoding into {@code v}; only the padding of
     * X.691 §11.1.3.1 may follow it, or the one zero octet that stands for
     * an empty encoding.
     */
    public static void decode(AsMemberRef v, byte[] data) {
        decode(v, data, rootConstraints(v));
    }

    /** {@link #decode(AsMemberRef, byte[])} under the constraints {@code c} of {@code v}'s type. */
    public static void decode(AsMemberRef v, byte[] data, Constraints c) {
        PerReader r = new PerReader(data);
        decodeValue(v.asMemberRef(), c, r);
        boolean emptyEncoding = r.bitPos() == 0 && data.length == 1 && data[0] == 0;
        if (r.remaining() >= 8 && !emptyEncoding) {
            throw r.error("PER: trailing data after the value");
        }
    }

    private static Constraints rootConstraints(AsMemberRef v) {
        return v instanceof Asn1Pdu p ? p.pduConstraints() : Constraints.UNCONSTRAINED;
    }

    /**
     * Appends {@code m}'s fields.
     *
     * @param c the value's own constraints
     */
    static void encodeValue(MemberRef m, Constraints c, PerWriter w) {
        switch (m) {
            case MemberRef.Unsupported(String reason) -> throw new EncodeException(reason);
            case MemberRef.Primitive(var p) -> PerPrimitive.encode(p, c, w);
            default -> throw new EncodeException("PER: " + m.getClass().getSimpleName() + " is not supported yet");
        }
    }

    /** Decode counterpart of {@link #encodeValue}. */
    static void decodeValue(MemberRef m, Constraints c, PerReader r) {
        switch (m) {
            case MemberRef.Unsupported(String reason) -> throw r.error(reason);
            case MemberRef.Primitive(var p) -> PerPrimitive.decode(p, c, r);
            default -> throw r.error("PER: " + m.getClass().getSimpleName() + " is not supported yet");
        }
    }
}
