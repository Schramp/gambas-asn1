package io.github.schramp.gambasasn1.wire.spec;

import io.github.schramp.gambasasn1.wire.types.Asn1Primitive;

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

    /**
     * A builtin leaf value. {@code owner} is the generated value that holds
     * it: a builtin alias class ({@code LIID ::= OCTET STRING}) whose
     * {@code value} field this is, or the builtin value itself when it has no
     * class of its own. The codecs work on {@code value}; finding nodes by
     * type and their positions also know {@code owner}.
     */
    record Primitive(Asn1Primitive value, AsMemberRef owner) implements MemberRef {
        /** A builtin value that is its own owner. */
        public Primitive(Asn1Primitive value) {
            this(value, value);
        }

        /** Equal to another reference to an equal builtin value, whichever object owns it. */
        @Override
        public boolean equals(Object o) {
            return o instanceof Primitive p && value.equals(p.value);
        }

        @Override
        public int hashCode() {
            return value.hashCode();
        }
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
