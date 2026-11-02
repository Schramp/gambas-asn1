package io.github.schramp.gambasasn1.wire.per;

import io.github.schramp.gambasasn1.wire.containing.ContainedOptions;
import java.io.ByteArrayOutputStream;

/**
 * Unaligned PER output: bit-fields concatenated without padding, the first
 * bit of each octet the most significant (X.691 §11.1.3), the layout of the
 * C++ {@code PerEncodeStream} and the Rust {@code per::Writer}.
 */
public final class PerWriter {
    private final ByteArrayOutputStream out = new ByteArrayOutputStream();
    private int current;
    private int bits;
    private ContainedOptions contained;

    /** Contained-value settings of this encode; null for the defaults. */
    public ContainedOptions contained() {
        return contained;
    }

    /** Sets the contained-value settings of this encode. */
    public PerWriter withContained(ContainedOptions options) {
        contained = options;
        return this;
    }

    /** Bits written so far. */
    public long bitPos() {
        return out.size() * 8L + bits;
    }

    /**
     * Appends the low {@code n} bits of {@code value}, most significant first.
     *
     * @param n 0 to 64; 0 appends nothing
     */
    public PerWriter putBits(long value, int n) {
        for (int i = n - 1; i >= 0; i--) {
            current |= (int) ((value >>> i) & 1) << (7 - bits);
            if (++bits == 8) {
                out.write(current);
                current = 0;
                bits = 0;
            }
        }
        return this;
    }

    /**
     * Appends the first {@code nbits} bits of {@code bytes}, most significant
     * first: a field another writer produced (an open type's contents, a
     * sorted SET OF component).
     */
    public PerWriter putBitString(byte[] bytes, long nbits) {
        int full = (int) (nbits / 8);
        for (int i = 0; i < full; i++) {
            putBits(bytes[i] & 0xFF, 8);
        }
        int rest = (int) (nbits % 8);
        if (rest > 0) {
            putBits((bytes[full] & 0xFF) >>> (8 - rest), rest);
        }
        return this;
    }

    /**
     * The complete encoding (X.691 §11.1.3.1): the bits so far padded with
     * zero bits to a whole number of octets, or one zero octet when nothing
     * was written. Leaves the writer as it was.
     */
    public byte[] toByteArray() {
        ByteArrayOutputStream done = new ByteArrayOutputStream(out.size() + 1);
        done.writeBytes(out.toByteArray());
        if (bits > 0 || out.size() == 0) {
            done.write(current);
        }
        return done.toByteArray();
    }
}
