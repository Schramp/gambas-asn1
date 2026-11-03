package io.github.schramp.gambasasn1.wire.io;

import java.util.HexFormat;

/**
 * A malformed or unsupported input, reported with the byte offset where
 * decoding stopped. Decoders throw it instead of failing in any other way,
 * whatever the input. With rich errors on, it also names the path of the
 * value being decoded ({@code Type.member[index].member}) and shows the
 * input octets at the offset.
 */
public final class DecodeException extends RuntimeException {
    private static final long serialVersionUID = 1L;
    /** How many input octets an error with rich errors on shows. */
    public static final int CONTEXT_OCTETS = 8;

    private final String reason;
    private final int position;
    private final String path;
    private final String context;

    public DecodeException(String message, int position) {
        this(message, position, "", "");
    }

    private DecodeException(String reason, int position, String path, String context) {
        super(reason + (path.isEmpty() ? "" : " in " + path) + " at byte " + position
                + (context.isEmpty() ? "" : " (" + context + ")"));
        this.reason = reason;
        this.position = position;
        this.path = path;
        this.context = context;
        if (!path.isEmpty() || !context.isEmpty()) {
            setStackTrace(new StackTraceElement[0]);
        }
    }

    /** Byte offset in the input where decoding stopped. */
    public int position() {
        return position;
    }

    /** What went wrong, without the path or offset. */
    public String reason() {
        return reason;
    }

    /** The path of the value being decoded, outermost first; empty without rich errors. */
    public String path() {
        return path;
    }

    /**
     * This error one level further out: {@code segment} is the member or
     * alternative name ({@code ".name"}), element index ({@code "[i]"}) or
     * type name the failing value sits in.
     */
    public DecodeException within(String segment) {
        DecodeException e = new DecodeException(reason, position, segment + path, context);
        e.initCause(getCause() != null ? getCause() : this);
        return e;
    }

    /**
     * This error showing {@code octets}, the input from its offset on (up
     * to {@link #CONTEXT_OCTETS}; empty at the end of the input).
     */
    public DecodeException showing(byte[] octets) {
        if (!context.isEmpty()) {
            return this;
        }
        String shown = octets.length == 0 ? "end of input"
                : "input there: " + HexFormat.ofDelimiter(" ").formatHex(octets);
        DecodeException e = new DecodeException(reason, position, path, shown);
        e.initCause(getCause() != null ? getCause() : this);
        return e;
    }
}
