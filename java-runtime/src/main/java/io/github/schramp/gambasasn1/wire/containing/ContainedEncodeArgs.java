package io.github.schramp.gambasasn1.wire.containing;

import io.github.schramp.gambasasn1.wire.spec.AsMemberRef;
import io.github.schramp.gambasasn1.wire.spec.ContainedEncoding;
import io.github.schramp.gambasasn1.wire.spec.ContainedSpec;

/**
 * What a contained-value encoder gets.
 *
 * @param inner    the inner value to encode
 * @param spec     the field's table row
 * @param encoding resolved encoding rules (never {@code OUTER})
 * @param decoders the registry in use
 * @param options  settings in use, passed on to the inner encode; may be null
 */
public record ContainedEncodeArgs(AsMemberRef inner, ContainedSpec spec, ContainedEncoding encoding,
        ContainedDecoders decoders, ContainedOptions options) {
}
