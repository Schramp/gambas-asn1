package io.github.schramp.gambasasn1.wire.spec;

/**
 * One PER extension addition (X.691 §18.9): the extension members up to
 * {@code end}; {@code group} marks an extension addition group.
 */
public record ExtUnit(int end, boolean group) {
}
