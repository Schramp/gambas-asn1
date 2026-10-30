package io.github.schramp.gambasasn1.wire.spec;

/** A SEQUENCE or SET value, reached member by member through its table. */
public interface Asn1Seq {
    SequenceSpec spec();

    /** Member {@code index}, or {@link MemberRef#ABSENT} for a missing OPTIONAL member. */
    MemberRef getMember(int index);

    /** Makes member {@code index} present (allocating a default value when needed) and returns it. */
    MemberRef presentMember(int index);

    /** Sets member {@code index} to its DEFAULT, or to absent when it has none (X.680 §25.6). */
    void setDefault(int index);

    /** Whether member {@code index} equals its DEFAULT value, so DER leaves it out (X.690 §11.5). */
    boolean isDefaultEqual(int index);

    /** Constraint check of member {@code index}: 0 when valid, otherwise the signed distance to the bound. */
    long validate(int index);
}
