package io.github.schramp.gambasasn1.wire.containing;

import io.github.schramp.gambasasn1.wire.ber.BerReader;
import io.github.schramp.gambasasn1.wire.spec.AsMemberRef;
import io.github.schramp.gambasasn1.wire.spec.ContainedEncoding;
import io.github.schramp.gambasasn1.wire.spec.ContainedSpec;

/**
 * What a contained-value decoder gets.
 *
 * @param raw      the field's raw bytes
 * @param spec     the field's table row
 * @param inner    a new default inner value to fill
 * @param outer    the enclosing value: an {@code Asn1Seq} or an {@code Asn1Choice}
 * @param encoding resolved encoding rules of {@code raw} (never {@code OUTER})
 * @param decoders the registry in use
 * @param parent   the outer decode's reader; a reader over the contained bytes starts at its
 *                 nesting depth and contained-value options
 */
public record ContainedDecodeArgs(byte[] raw, ContainedSpec spec, AsMemberRef inner, Object outer,
        ContainedEncoding encoding, ContainedDecoders decoders, BerReader parent) {
}
