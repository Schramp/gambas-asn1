package io.github.schramp.gambasasn1.wire.ber;

import io.github.schramp.gambasasn1.wire.io.ByteSource;

/**
 * One decoded TLV: its tag and a window over its contents octets.
 * For an indefinite-length value the window excludes the end-of-contents
 * octets (X.690 §8.1.5).
 */
public record Tlv(Tag tag, ByteSource value) {
}
