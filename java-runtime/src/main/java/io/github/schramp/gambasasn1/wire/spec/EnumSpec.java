package io.github.schramp.gambasasn1.wire.spec;

import java.util.List;

/**
 * Table of an ENUMERATED type (X.680 §20).
 *
 * @param name       ASN.1 type name
 * @param entries    root items first, then extension items
 * @param extensible has an extension marker
 * @param rootCount  number of root items
 * @param rootBits   bits of the root index (X.691 §10.5.6)
 */
public record EnumSpec(String name, List<EnumEntry> entries, boolean extensible, int rootCount, int rootBits) {
}
