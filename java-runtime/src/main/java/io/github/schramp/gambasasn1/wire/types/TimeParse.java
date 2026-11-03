package io.github.schramp.gambasasn1.wire.types;

import java.time.Instant;
import java.time.LocalDateTime;
import java.time.OffsetDateTime;
import java.time.ZoneOffset;
import java.util.Optional;

/**
 * The outcome of reading the text of a UTCTime (X.680 §47) or
 * GeneralizedTime (X.680 §46): the time it gives, or why the text is not
 * one. The text itself stays the value; this is a reading of it.
 */
public sealed interface TimeParse {

    /** How the text relates its time to UTC. */
    enum Zone {
        /** No indicator: a local time whose difference to UTC is unknown (X.680 §46.3 a)). */
        LOCAL,
        /** {@code Z}: the time is UTC. */
        UTC,
        /** {@code +hhmm} or {@code -hhmm}: a local time and its difference to UTC. */
        OFFSET
    }

    /** The last component the text gives: a fraction, when there is one, belongs to it. */
    enum Precision { HOUR, MINUTE, SECOND }

    /**
     * A time read from the text. A fraction of an hour or a minute is spread
     * over the lower fields, so {@code 2024011512.5} reads as 12:30:00;
     * fractions finer than a nanosecond are dropped.
     *
     * @param year           four-digit year; for UTCTime the two digits read in the
     *                       window 1950..2049 (see {@link #twoDigitYear})
     * @param twoDigitYear   the text gave only two digits of the year (UTCTime)
     * @param month          1..12
     * @param day            1..31, valid for the month
     * @param hour           0..23
     * @param minute         0..59
     * @param second         0..59, or 60 for a GeneralizedTime leap second
     * @param nanos          0..999 999 999
     * @param precision      the last component given
     * @param fractionDigits digits of its fraction, 0 without one
     * @param zone           how the time relates to UTC
     * @param offsetMinutes  local time minus UTC in minutes, for {@link Zone#OFFSET}; 0 otherwise
     */
    record Time(int year, boolean twoDigitYear, int month, int day, int hour, int minute, int second, int nanos,
                Precision precision, int fractionDigits, Zone zone, int offsetMinutes) implements TimeParse {

        /** Milliseconds within the second. */
        public int millisecond() {
            return nanos / 1_000_000;
        }

        /** The date and time of day as written, ignoring the zone. A leap second reads as second 59. */
        public LocalDateTime localDateTime() {
            return LocalDateTime.of(year, month, day, hour, minute, Math.min(second, 59), nanos);
        }

        /** The time with its offset to UTC ({@code Z} is offset 0), or empty for a local time. */
        public Optional<OffsetDateTime> offsetDateTime() {
            if (zone == Zone.LOCAL) {
                return Optional.empty();
            }
            return Optional.of(OffsetDateTime.of(localDateTime(), ZoneOffset.ofTotalSeconds(offsetMinutes * 60)));
        }

        /** The instant on the UTC time line, or empty for a local time. */
        public Optional<Instant> instant() {
            return offsetDateTime().map(OffsetDateTime::toInstant);
        }
    }

    /**
     * Text that is not a time of its type.
     *
     * @param reason what is wrong
     * @param index  the character where it was found
     */
    record Malformed(String reason, int index) implements TimeParse {
    }
}
