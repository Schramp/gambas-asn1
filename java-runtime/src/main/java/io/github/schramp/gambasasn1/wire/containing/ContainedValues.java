package io.github.schramp.gambasasn1.wire.containing;

import io.github.schramp.gambasasn1.wire.ber.BerReader;
import io.github.schramp.gambasasn1.wire.io.DecodeException;
import io.github.schramp.gambasasn1.wire.io.EncodeException;
import io.github.schramp.gambasasn1.wire.spec.AltMeta;
import io.github.schramp.gambasasn1.wire.spec.AsMemberRef;
import io.github.schramp.gambasasn1.wire.spec.Asn1Choice;
import io.github.schramp.gambasasn1.wire.spec.Asn1Contained;
import io.github.schramp.gambasasn1.wire.spec.Asn1Seq;
import io.github.schramp.gambasasn1.wire.spec.ContainedEncoding;
import io.github.schramp.gambasasn1.wire.spec.ContainedResult;
import io.github.schramp.gambasasn1.wire.spec.ContainedSpec;
import io.github.schramp.gambasasn1.wire.spec.ContainedStatus;
import io.github.schramp.gambasasn1.wire.spec.EnumSlot;
import io.github.schramp.gambasasn1.wire.spec.MemberMeta;
import io.github.schramp.gambasasn1.wire.spec.MemberRef;
import io.github.schramp.gambasasn1.wire.types.Asn1Boolean;
import io.github.schramp.gambasasn1.wire.types.Asn1Integer;
import io.github.schramp.gambasasn1.wire.types.Asn1UInteger;

/**
 * Contained values (X.682 §11 contents constraints, or a
 * {@code --container-config} entry) for the codec walkers. A walker sees a
 * contained field as {@code MemberRef.Contained} and treats it as an OCTET
 * STRING over {@link #wireOctets}; after a SEQUENCE/SET's members, or a
 * CHOICE's alternative, are decoded it decodes the inner values here, so a
 * {@code when} condition or an application decoder can read the siblings.
 */
public final class ContainedValues {
    private ContainedValues() {
    }

    private static ContainedEncoding resolve(ContainedEncoding field, ContainedEncoding outer) {
        return field == ContainedEncoding.OUTER ? outer : field;
    }

    /**
     * The bytes a contained field is written as under the outer encoding
     * {@code outer}: its raw bytes, or the inner value's encoding when the
     * value was modified, or when the raw bytes are in other rules than a
     * field following the outer encoding is written in (X.682 §11.4).
     *
     * @throws EncodeException when a modified value cannot be encoded
     */
    public static byte[] wireOctets(Asn1Contained field, ContainedSpec spec, ContainedEncoding outer, ContainedOptions opts) {
        AsMemberRef inner = field.value();
        if (inner == null) {
            return field.rawOctets();
        }
        boolean otherRules = spec.encoding() == ContainedEncoding.OUTER
                && field.rawEncoding() != ContainedEncoding.OUTER && field.rawEncoding() != outer;
        if (!field.dirty() && !otherRules) {
            return field.rawOctets();
        }
        ContainedDecoders reg = ContainedOptions.registry(opts);
        ContainedDecoders.Entry e = reg.resolve(spec);
        try {
            if (e == null || e.encode() == null) {
                throw new EncodeException("decoder '" + spec.decoder() + "' cannot encode");
            }
            return e.encode().encode(new ContainedEncodeArgs(inner, spec, resolve(spec.encoding(), outer), reg, opts));
        } catch (EncodeException ex) {
            // Modified bytes must not go out as their stale raw form; unmodified
            // ones in other rules are kept (a decoder without an encode side).
            if (field.dirty()) {
                throw new EncodeException("modified contained value cannot be encoded: " + ex.getMessage());
            }
            return field.rawOctets();
        }
    }

    /** A {@code when} sibling's number: ENUMERATED value, INTEGER, BOOLEAN as 0/1; null otherwise. */
    private static Long siblingValue(MemberRef m) {
        return switch (m) {
            case MemberRef.Enumerated(EnumSlot slot, var spec) -> slot.enumGet();
            case MemberRef.Primitive(Asn1Integer v) -> v.get();
            case MemberRef.Primitive(Asn1UInteger v) -> v.get();
            case MemberRef.Primitive(Asn1Boolean v) -> v.get() ? 1L : 0L;
            default -> null;
        };
    }

    /** Decodes one contained field and stores the outcome in it. */
    private static ContainedResult runOne(Asn1Contained field, ContainedSpec spec, Object outer,
            ContainedEncoding outerEncoding, BerReader parent, String whenFail) {
        ContainedOptions opts = parent.contained();
        ContainedResult r;
        AsMemberRef inner = null;
        if (!spec.eager() || (opts != null && opts.off())) {
            r = ContainedResult.skipped("contained decoding off");
        } else if (whenFail != null) {
            r = ContainedResult.skipped(whenFail);
        } else {
            ContainedDecoders reg = ContainedOptions.registry(opts);
            ContainedDecoders.Entry e = reg.resolve(spec);
            if (e == null) {
                r = ContainedResult.failed("unknown contained decoder '" + spec.decoder() + "'");
            } else {
                inner = field.newInner();
                r = e.decode().decode(new ContainedDecodeArgs(field.rawOctets(), spec, inner, outer,
                        resolve(spec.encoding(), outerEncoding), reg, parent));
            }
        }
        field.install(r, inner);
        return r;
    }

    /** {@code on_error: fail} turns a failed inner decode into a failed outer one. */
    private static void finish(String name, ContainedSpec spec, ContainedResult r, BerReader parent) {
        if (r.status() == ContainedStatus.FAILED && spec.failOnError()) {
            throw new DecodeException(name + ": " + r.message(), parent.position());
        }
    }

    /**
     * Decodes the contained members of a decoded SEQUENCE/SET value; every
     * member is in place, so {@code when} siblings can be read.
     *
     * @throws DecodeException for a failure on a field with {@code on_error: fail}
     * @see "X.682 §11.4"
     */
    public static void decodeMembers(Asn1Seq s, ContainedEncoding outerEncoding, BerReader parent) {
        for (int i : s.spec().containedMembers()) {
            MemberMeta meta = s.spec().members().get(i);
            ContainedSpec cs = meta.contained();
            if (cs == null || !(s.getMember(i) instanceof MemberRef.Contained(Asn1Contained field, var spec))) {
                continue;
            }
            String whenFail = null;
            if (cs.whenMember() >= 0) {
                Long v = siblingValue(s.getMember(cs.whenMember()));
                if (v == null || v != cs.whenValue()) {
                    whenFail = "'" + s.spec().members().get(cs.whenMember()).name() + "' does not select decoding";
                }
            }
            finish(meta.name(), cs, runOne(field, cs, s, outerEncoding, parent, whenFail), parent);
        }
    }

    /**
     * Decodes the active alternative of a decoded CHOICE value when it is a
     * contained field.
     *
     * @throws DecodeException for a failure on a field with {@code on_error: fail}
     */
    public static void decodeAlternative(Asn1Choice c, ContainedEncoding outerEncoding, BerReader parent) {
        int i = c.activeIndex();
        if (i < 0) {
            return;
        }
        AltMeta meta = c.spec().alternatives().get(i);
        ContainedSpec cs = meta.contained();
        if (cs == null || !(c.getActive() instanceof MemberRef.Contained(Asn1Contained field, var spec))) {
            return;
        }
        finish(meta.name(), cs, runOne(field, cs, c, outerEncoding, parent, null), parent);
    }
}
