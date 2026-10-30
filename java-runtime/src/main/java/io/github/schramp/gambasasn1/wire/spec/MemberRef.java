package io.github.schramp.gambasasn1.wire.spec;

/**
 * A value seen by its reflective shape. Every codec walker is one closed
 * switch over these cases. Generated types only say which case they are;
 * they hold no codec code.
 */
public sealed interface MemberRef {

    /** An OPTIONAL member that is not present. */
    record Absent() implements MemberRef {
    }

    /** A value this runtime has no representation for yet. */
    record Unsupported(String reason) implements MemberRef {
    }

    /** A builtin leaf value. */
    record Primitive(Asn1Primitive value) implements MemberRef {
    }

    /** A SEQUENCE or SET. */
    record Composite(Asn1Seq value) implements MemberRef {
    }

    /** A CHOICE. */
    record Choice(Asn1Choice value) implements MemberRef {
    }

    /** A SEQUENCE OF or SET OF. */
    record SeqOf(Asn1SeqOf value) implements MemberRef {
    }

    /** An ENUMERATED value and its type's table. */
    record Enumerated(EnumSlot value, EnumSpec spec) implements MemberRef {
    }

    /** An OCTET STRING holding the encoding of another type (X.682 §11). */
    record Contained(Asn1Contained value, ContainedSpec spec) implements MemberRef {
    }

    MemberRef ABSENT = new Absent();
}
