package io.github.schramp.gambasasn1.wire.spec;

import java.util.Arrays;
import java.util.Objects;
import java.util.function.Supplier;

/**
 * An OCTET STRING whose bytes are the encoding of a {@code T} value
 * (X.682 §11). Keeps the raw bytes plus the inner value decoded with the
 * outer value.
 *
 * <p>The raw bytes stay authoritative for encoding, so a value that was
 * decoded and not modified re-encodes byte-exact. A value set with
 * {@link #set(AsMemberRef)} or reached through {@link #edit()} is dirty:
 * encode then writes its encoding instead. Equality compares the raw bytes;
 * the inner value is derived from them. The field carries its table row, so
 * it is its own {@link MemberRef.Contained}.
 *
 * @param <T> the contained type
 */
public final class Containing<T extends AsMemberRef> implements Asn1Contained, AsMemberRef {
    private static final byte[] EMPTY = new byte[0];

    private final Supplier<T> factory;
    private final ContainedSpec spec;
    private byte[] raw = EMPTY;
    private T inner;
    private ContainedStatus status = ContainedStatus.NOT_DECODED;
    private String error = "";
    private boolean dirty;
    private ContainedEncoding rawEncoding = ContainedEncoding.OUTER;

    /**
     * @param factory makes a default inner value
     * @param spec    the field's table row
     */
    public Containing(Supplier<T> factory, ContainedSpec spec) {
        this.factory = Objects.requireNonNull(factory);
        this.spec = Objects.requireNonNull(spec);
    }

    /** The field's table row. */
    public ContainedSpec spec() {
        return spec;
    }

    @Override
    public MemberRef asMemberRef() {
        return new MemberRef.Contained(this, spec);
    }

    /** The XER element of an OCTET STRING: a contents constraint keeps the type (X.682 §11). */
    @Override
    public String ownElementXerName() {
        return "OCTET_STRING";
    }

    /** The raw bytes, not a copy. */
    public byte[] bytes() {
        return raw;
    }

    /** Replaces the raw bytes, taken as is. Drops the inner value: it no longer matches them. */
    public void setBytes(byte[] raw) {
        this.raw = Objects.requireNonNull(raw);
        inner = null;
        status = ContainedStatus.NOT_DECODED;
        error = "";
        dirty = false;
        rawEncoding = ContainedEncoding.OUTER;
    }

    @Override
    public ContainedStatus status() {
        return status;
    }

    /** Reason of a {@code FAILED} or {@code SKIPPED} status; for {@code DECODED}, a warning. */
    public String error() {
        return error;
    }

    /** The decoded inner value, or null. Changing it needs {@link #edit()}. */
    @Override
    public T value() {
        return inner;
    }

    /** The inner value for changing it, or null; marks the value dirty. */
    public T edit() {
        if (inner != null) {
            dirty = true;
            status = ContainedStatus.DECODED;
            error = "";
        }
        return inner;
    }

    /** Replaces the inner value; encode derives the bytes from it. */
    public void set(T v) {
        inner = Objects.requireNonNull(v);
        dirty = true;
        status = ContainedStatus.DECODED;
        error = "";
    }

    @Override
    public byte[] rawOctets() {
        return raw;
    }

    @Override
    public boolean dirty() {
        return dirty;
    }

    @Override
    public ContainedEncoding rawEncoding() {
        return rawEncoding;
    }

    @Override
    public void setRawFromWire(byte[] raw, ContainedEncoding encoding) {
        setBytes(raw);
        rawEncoding = encoding;
    }

    @Override
    public AsMemberRef newInner() {
        return factory.get();
    }

    @Override
    @SuppressWarnings("unchecked")
    public void install(ContainedResult result, AsMemberRef v) {
        inner = result.status() == ContainedStatus.DECODED ? (T) v : null;
        status = result.status();
        error = result.message();
        dirty = false;
    }

    @Override
    public boolean equals(Object o) {
        return o instanceof Containing<?> c && Arrays.equals(c.raw, raw);
    }

    @Override
    public int hashCode() {
        return Arrays.hashCode(raw);
    }
}
