package io.github.schramp.gambasasn1.wire.types;

import io.github.schramp.gambasasn1.wire.spec.AsMemberRef;
import io.github.schramp.gambasasn1.wire.spec.MemberRef;

/** A builtin leaf value (BOOLEAN, INTEGER, OCTET STRING, ...). */
public interface Asn1Primitive extends AsMemberRef {

    /** The builtin's X.693 element name, for example {@code BOOLEAN} or {@code OCTET_STRING}. */
    String xerElementName();

    @Override
    default MemberRef asMemberRef() {
        return new MemberRef.Primitive(this);
    }

    @Override
    default String ownElementXerName() {
        return xerElementName();
    }
}
