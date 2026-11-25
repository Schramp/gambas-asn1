package io.github.schramp.gambasasn1.wire.spec;

import io.github.schramp.gambasasn1.wire.ber.Tag;

/** A CHOICE value: one selected alternative, or an unknown extension kept as raw bytes. */
public interface Asn1Choice {

    /**
     * An alternative of a newer schema version (X.680 §52.1), kept as its
     * codec carried it so it can be relayed. BER carries the TLV: {@code tag}
     * and {@code bytes}, its contents octets. PER carries the extension index
     * past the known alternatives (X.691 §23.8) and the open-type octets. It
     * encodes again only in the codec it came from.
     *
     * @param origin codec it was read from
     * @param tag    BER: the TLV's tag
     * @param index  PER: extension index past the known alternatives
     * @param bytes  BER contents octets / PER open-type octets
     */
    record UnknownExtension(Origin origin, Tag tag, long index, byte[] bytes) {

        /** Codec an unknown alternative was read from. */
        public enum Origin { BER, PER }

        /** A BER alternative: its TLV's tag and contents octets. */
        public static UnknownExtension ber(Tag tag, byte[] bytes) {
            return new UnknownExtension(Origin.BER, tag, 0, bytes);
        }

        /** A PER alternative: its extension index and open-type octets. */
        public static UnknownExtension per(long index, byte[] bytes) {
            return new UnknownExtension(Origin.PER, Tag.context(0, false), index, bytes);
        }
    }

    /**
     * The encode error for a CHOICE {@code codec} cannot write: nothing
     * selected, or an alternative of a newer schema version read from another
     * codec.
     *
     * @param ch    the CHOICE
     * @param codec the encoding codec's name
     * @return the message
     */
    static String noAlternativeError(Asn1Choice ch, String codec) {
        UnknownExtension ext = ch.unknownExtension();
        if (ext == null) {
            return "CHOICE " + ch.spec().name() + ": no alternative selected";
        }
        return "CHOICE " + ch.spec().name() + ": extension alternative of a newer schema version, read from "
                + ext.origin() + ", has no " + codec + " encoding";
    }

    ChoiceSpec spec();

    /** Index of the selected alternative, or -1 when none is selected. */
    int activeIndex();

    /** The selected alternative's value. */
    MemberRef getActive();

    /** Selects alternative {@code index} with a default value and returns it. */
    MemberRef select(int index);

    /** Keeps an unknown extension alternative as raw bytes. */
    void setUnknownExtension(UnknownExtension ext);

    /** The unknown extension alternative this value holds, or null. */
    UnknownExtension unknownExtension();
}
