package io.github.schramp.gambasasn1.wire.containing;

import io.github.schramp.gambasasn1.wire.ber.BerObject;
import io.github.schramp.gambasasn1.wire.ber.BerReader;
import io.github.schramp.gambasasn1.wire.io.ByteSink;
import io.github.schramp.gambasasn1.wire.io.DecodeException;
import io.github.schramp.gambasasn1.wire.io.EncodeException;
import io.github.schramp.gambasasn1.wire.per.PerObject;
import io.github.schramp.gambasasn1.wire.per.PerReader;
import io.github.schramp.gambasasn1.wire.spec.ContainedResult;
import io.github.schramp.gambasasn1.wire.spec.ContainedSpec;
import io.github.schramp.gambasasn1.wire.spec.ContainedStatus;
import java.util.Arrays;
import java.util.HashMap;
import java.util.Map;

/**
 * Named contained-value decoders, as a field's {@code decoder} setting names
 * them. Pre-loaded with the built-ins {@code plain}, {@code zero_padding},
 * {@code pkcs7} and {@code none}, under the same rules as the C++ and Rust
 * runtimes.
 */
public final class ContainedDecoders {
    /** Fills {@code args.inner()} from {@code args.raw()}. */
    @FunctionalInterface
    public interface Decoder {
        ContainedResult decode(ContainedDecodeArgs args);
    }

    /** The field's bytes from {@code args.inner()}. */
    @FunctionalInterface
    public interface Encoder {
        byte[] encode(ContainedEncodeArgs args);
    }

    record Entry(Decoder decode, Encoder encode) {
    }

    private static final ContainedDecoders DEFAULTS = new ContainedDecoders();

    private final Entry[] builtin = new Entry[ContainedSpec.BUILTIN_DECODERS.size()];
    private final Map<String, Entry> entries = new HashMap<>();
    private int pkcs7BlockSize = 16;

    public ContainedDecoders() {
        add("plain", a -> decodeValue(a, null), ContainedDecoders::encodeValue);
        add("zero_padding", ContainedDecoders::decodeZeroPadding, ContainedDecoders::encodeValue);
        add("pkcs7", ContainedDecoders::decodePkcs7, ContainedDecoders::encodePkcs7);
        add("none", a -> ContainedResult.skipped("decoder 'none'"), null);
    }

    /** The built-in registry, used when no options are given. */
    public static ContainedDecoders defaults() {
        return DEFAULTS;
    }

    /** Registers or replaces the decoder {@code name}; {@code encode} may be null. */
    public void add(String name, Decoder decode, Encoder encode) {
        Entry e = new Entry(decode, encode);
        int i = ContainedSpec.BUILTIN_DECODERS.indexOf(name);
        if (i >= 0) {
            builtin[i] = e;
        } else {
            entries.put(name, e);
        }
    }

    /** Block size the {@code pkcs7} encoder pads to (default 16, AES). */
    public int pkcs7BlockSize() {
        return pkcs7BlockSize;
    }

    public void setPkcs7BlockSize(int n) {
        pkcs7BlockSize = n;
    }

    /** The entry a field's decoder resolves to: by index for a built-in name, by name otherwise. */
    Entry resolve(ContainedSpec spec) {
        if (spec.builtin() >= 0 && spec.builtin() < builtin.length) {
            return builtin[spec.builtin()];
        }
        return entries.get(spec.decoder());
    }

    /**
     * Decodes {@code bytes} under the args' encoding into {@code args.inner()},
     * for decoders that transformed the raw bytes first.
     *
     * @param consumed receives the octets the value used in element 0; when
     *                 null, the value must use all of {@code bytes}
     */
    public static ContainedResult decodeValueFrom(ContainedDecodeArgs args, byte[] bytes, int[] consumed) {
        int used;
        switch (args.encoding()) {
            case BER, CER, DER -> {
                BerReader r = args.parent().nested(bytes);
                try {
                    BerObject.decode(args.inner(), r);
                } catch (DecodeException e) {
                    return ContainedResult.failed(e.getMessage());
                }
                used = r.position();
            }
            case PER_UNALIGNED -> {
                PerReader r = new PerReader(bytes).withContained(args.parent().contained());
                try {
                    for (int i = 0; i < args.parent().depth(); i++) {
                        r.enterLevel();
                    }
                    used = PerObject.decodePrefix(args.inner(), r);
                } catch (DecodeException e) {
                    return ContainedResult.failed(e.getMessage());
                }
            }
            default -> {
                return ContainedResult.failed(args.encoding() + " contents are not supported");
            }
        }
        if (consumed != null) {
            consumed[0] = used;
        } else if (used < bytes.length) {
            return ContainedResult.failed((bytes.length - used) + " octets after the contained value");
        }
        return ContainedResult.ok();
    }

    /** {@code plain}: the raw bytes are exactly one value. */
    public static ContainedResult decodeValue(ContainedDecodeArgs args, int[] consumed) {
        return decodeValueFrom(args, args.raw(), consumed);
    }

    /** Encodes {@code args.inner()} under the args' encoding. */
    public static byte[] encodeValue(ContainedEncodeArgs args) {
        switch (args.encoding()) {
            case BER, CER, DER -> {
                ByteSink out = new ByteSink();
                BerObject.encodeMemberRef(args.inner().asMemberRef(), args.inner().berFraming(), out, args.options());
                return out.toByteArray();
            }
            case PER_UNALIGNED -> {
                return PerObject.encode(args.inner(), args.options());
            }
            default -> throw new EncodeException(args.encoding() + " contents are not supported");
        }
    }

    /**
     * {@code zero_padding}: one value, then only 0x00 octets (block-cipher
     * padding). The value is decoded from the whole buffer and the tail
     * checked afterwards, since a value may itself end in 0x00. A non-zero
     * tail keeps the value and reports it.
     */
    private static ContainedResult decodeZeroPadding(ContainedDecodeArgs args) {
        int[] used = new int[1];
        ContainedResult r = decodeValue(args, used);
        if (r.status() != ContainedStatus.DECODED) {
            return r;
        }
        byte[] raw = args.raw();
        for (int i = used[0]; i < raw.length; i++) {
            if (raw[i] != 0) {
                return new ContainedResult(ContainedStatus.DECODED,
                        "non-zero padding octet at offset " + i + " of " + raw.length);
            }
        }
        return r;
    }

    /**
     * {@code pkcs7}: strips RFC 5652 §6.3 padding (the last octet N, 1..255,
     * repeated N times), then decodes the rest as exactly one value.
     */
    private static ContainedResult decodePkcs7(ContainedDecodeArgs args) {
        byte[] raw = args.raw();
        if (raw.length == 0) {
            return ContainedResult.failed("PKCS#7: empty contents");
        }
        int n = raw[raw.length - 1] & 0xFF;
        if (n == 0 || n > raw.length) {
            return ContainedResult.failed("PKCS#7: bad padding length");
        }
        for (int i = raw.length - n; i < raw.length; i++) {
            if ((raw[i] & 0xFF) != n) {
                return ContainedResult.failed("PKCS#7: inconsistent padding octets");
            }
        }
        return decodeValueFrom(args, Arrays.copyOf(raw, raw.length - n), null);
    }

    private static byte[] encodePkcs7(ContainedEncodeArgs args) {
        byte[] value = encodeValue(args);
        int bs = args.decoders().pkcs7BlockSize;
        if (bs <= 0 || bs > 255) {
            throw new EncodeException("PKCS#7: block size must be 1..255");
        }
        int n = bs - value.length % bs;
        byte[] out = Arrays.copyOf(value, value.length + n);
        Arrays.fill(out, value.length, out.length, (byte) n);
        return out;
    }
}
