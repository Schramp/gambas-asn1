package io.github.schramp.gambasasn1.wire.spec;

import io.github.schramp.gambasasn1.wire.ber.Tag;

/** One CHOICE dispatch entry: a wire tag that selects {@code alternatives[alt]} (X.690 §8.13). */
public record BerDispatch(Tag tag, int alt) {
}
