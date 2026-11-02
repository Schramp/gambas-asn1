package io.github.schramp.gambasasn1.wire.spec;

/** One ENUMERATED item: its value and identifier (X.680 §20). */
public record EnumEntry(long value, String name) {
}
