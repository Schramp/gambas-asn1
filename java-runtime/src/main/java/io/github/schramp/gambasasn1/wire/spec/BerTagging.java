package io.github.schramp.gambasasn1.wire.spec;

import io.github.schramp.gambasasn1.wire.ber.Tag;
import java.util.List;
import java.util.function.Supplier;

/**
 * How BER frames a member's or alternative's value (X.690 §8.14). The
 * framing belongs to whoever wrote the tag: a member with its own
 * {@code [n]} carries it here, a reference to a tagged type points at
 * that type's framing ({@link OfType}).
 */
public sealed interface BerTagging {

    /** The tag replaces the value's natural tag (IMPLICIT, or the natural tag itself). */
    record Implicit(Tag tag) implements BerTagging {
    }

    /** The value is wrapped in an outer TLV with this tag (EXPLICIT). */
    record Explicit(Tag tag) implements BerTagging {
    }

    /** The value frames itself: an untagged CHOICE (X.680 §28) or a composite with its own tag. */
    record Delegate() implements BerTagging {
    }

    /**
     * {@link Delegate} for an OPTIONAL member whose type is an untagged
     * CHOICE: the member is present when the next tag is one of the
     * CHOICE's alternative tags.
     */
    record DelegateChoice(Supplier<List<BerDispatch>> tags) implements BerTagging {
    }

    /**
     * The referenced type's own framing: a member with no tag of its own
     * whose type assignment carries one (X.680 §31.2).
     */
    record OfType(BerTagging framing) implements BerTagging {
    }

    /** No support for this member yet; reaching it is an encode or decode error. */
    record Unsupported(String reason) implements BerTagging {
    }

    BerTagging DELEGATE = new Delegate();

    /** The framing a BER walker applies: {@link OfType} replaced by the type's own. */
    default BerTagging resolve() {
        return this instanceof OfType o ? o.framing().resolve() : this;
    }

    /**
     * Whether a member with this framing and table tag {@code tag} starts
     * with wire tag {@code t}. Used to detect an OPTIONAL member.
     */
    default boolean startsWith(Tag tag, Tag t) {
        if (this instanceof DelegateChoice d) {
            return d.tags().get().stream().anyMatch(e -> e.tag().matchesIdentifier(t));
        }
        return tag.equals(t);
    }
}
