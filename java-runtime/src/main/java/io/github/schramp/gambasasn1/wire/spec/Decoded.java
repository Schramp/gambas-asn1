package io.github.schramp.gambasasn1.wire.spec;

/**
 * Result of a decode that records positions: the octets the value used
 * (exactly one PDU) and the start of every decoded node.
 *
 * @param bytesConsumed octets of the input the value occupied, from where the decode started
 * @param positions     node offsets in bits from where the decode started
 */
public record Decoded(int bytesConsumed, Positions positions) {
}
