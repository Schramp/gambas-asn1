package io.github.schramp.gambasasn1.wire.types;

import java.math.BigDecimal;
import java.time.YearMonth;

/** Reads the text of the time types into a {@link TimeParse}. */
final class TimeText {
    private final String s;
    private int at;

    private TimeText(String s) {
        this.s = s;
    }

    /** Malformed text, carried out of the reader. */
    private static final class Bad extends Exception {
        private static final long serialVersionUID = 1L;
        final int index;

        Bad(String reason, int index) {
            super(reason, null, false, false);
            this.index = index;
        }
    }

    /**
     * UTCTime (X.680 §47.3): {@code YYMMDDhhmm[ss]} then {@code Z} or
     * {@code ±hhmm}. The two-digit year is read in the window 1950..2049,
     * as X.509 does (RFC 5280 §4.1.2.5.1); X.680 itself gives no century.
     */
    static TimeParse utc(String s) {
        TimeText t = new TimeText(s);
        try {
            int yy = t.digits(2, "year");
            int year = yy < 50 ? 2000 + yy : 1900 + yy;
            int month = t.digits(2, "month");
            int day = t.digits(2, "day");
            int hour = t.digits(2, "hour");
            int minute = t.digits(2, "minute");
            TimeParse.Precision p = TimeParse.Precision.MINUTE;
            int second = 0;
            if (t.digitNext()) {
                second = t.digits(2, "second");
                p = TimeParse.Precision.SECOND;
            }
            if (t.at == s.length()) {
                throw new Bad("UTCTime needs Z or a time difference", t.at);
            }
            TimeParse.Zone zone;
            int offset = 0;
            if (t.consume('Z')) {
                zone = TimeParse.Zone.UTC;
            } else {
                zone = TimeParse.Zone.OFFSET;
                offset = t.offset(true);
            }
            t.end();
            return t.check(new TimeParse.Time(year, true, month, day, hour, minute, second, 0, p, 0, zone, offset),
                    false);
        } catch (Bad b) {
            return new TimeParse.Malformed(b.getMessage(), b.index);
        }
    }

    /**
     * GeneralizedTime (X.680 §46.3): {@code YYYYMMDDhh[mm[ss]]}, an
     * optional fraction of the last component after {@code .} or
     * {@code ,} (ISO 8601 basic format), then nothing (local time),
     * {@code Z} or {@code ±hh[mm]}.
     */
    static TimeParse generalized(String s) {
        TimeText t = new TimeText(s);
        try {
            int year = t.digits(4, "year");
            int month = t.digits(2, "month");
            int day = t.digits(2, "day");
            int hour = t.digits(2, "hour");
            int minute = 0;
            int second = 0;
            TimeParse.Precision p = TimeParse.Precision.HOUR;
            if (t.digitNext()) {
                minute = t.digits(2, "minute");
                p = TimeParse.Precision.MINUTE;
                if (t.digitNext()) {
                    second = t.digits(2, "second");
                    p = TimeParse.Precision.SECOND;
                }
            }
            int fractionDigits = 0;
            long nanosOfUnit = 0;
            if (t.at < s.length() && (s.charAt(t.at) == '.' || s.charAt(t.at) == ',')) {
                t.at++;
                int start = t.at;
                while (t.digitNext()) {
                    t.at++;
                }
                fractionDigits = t.at - start;
                if (fractionDigits == 0) {
                    throw new Bad("decimal sign without digits", start);
                }
                long unit = switch (p) {
                    case HOUR -> 3_600_000_000_000L;
                    case MINUTE -> 60_000_000_000L;
                    case SECOND -> 1_000_000_000L;
                };
                nanosOfUnit = new BigDecimal("0." + s.substring(start, t.at)).multiply(BigDecimal.valueOf(unit))
                        .longValue();
            }
            TimeParse.Zone zone = TimeParse.Zone.LOCAL;
            int offset = 0;
            if (t.consume('Z')) {
                zone = TimeParse.Zone.UTC;
            } else if (t.at < s.length()) {
                zone = TimeParse.Zone.OFFSET;
                offset = t.offset(false);
            }
            t.end();
            int nanos = (int) (nanosOfUnit % 1_000_000_000L);
            long wholeSeconds = nanosOfUnit / 1_000_000_000L;
            minute += (int) (wholeSeconds / 60);
            second += (int) (wholeSeconds % 60);
            return t.check(new TimeParse.Time(year, false, month, day, hour, minute, second, nanos, p,
                    fractionDigits, zone, offset), true);
        } catch (Bad b) {
            return new TimeParse.Malformed(b.getMessage(), b.index);
        }
    }

    private boolean digitNext() {
        return at < s.length() && s.charAt(at) >= '0' && s.charAt(at) <= '9';
    }

    private int digits(int n, String what) throws Bad {
        int v = 0;
        for (int i = 0; i < n; i++) {
            if (!digitNext()) {
                throw new Bad(at == s.length() ? "text ends before the " + what : "expected a digit of the " + what,
                        at);
            }
            v = v * 10 + (s.charAt(at++) - '0');
        }
        return v;
    }

    private boolean consume(char c) {
        if (at < s.length() && s.charAt(at) == c) {
            at++;
            return true;
        }
        return false;
    }

    /**
     * {@code ±hhmm}, or without {@code minutesRequired} also {@code ±hh};
     * local time minus UTC in minutes, at most 18 hours either way.
     */
    private int offset(boolean minutesRequired) throws Bad {
        int sign;
        if (consume('+')) {
            sign = 1;
        } else if (consume('-')) {
            sign = -1;
        } else {
            throw new Bad("expected Z, + or -", at);
        }
        int start = at;
        int hh = digits(2, "time difference hours");
        int mm = 0;
        if (minutesRequired || digitNext()) {
            mm = digits(2, "time difference minutes");
        }
        if (mm > 59 || hh * 60 + mm > 18 * 60) {
            throw new Bad("time difference out of range", start);
        }
        return sign * (hh * 60 + mm);
    }

    private void end() throws Bad {
        if (at != s.length()) {
            throw new Bad("unexpected character '" + s.charAt(at) + "'", at);
        }
    }

    /** Range checks on the fields; a leap second (60) only where {@code leapSecond} allows it. */
    private TimeParse check(TimeParse.Time t, boolean leapSecond) throws Bad {
        if (t.month() < 1 || t.month() > 12) {
            throw new Bad("month " + t.month() + " out of range", t.twoDigitYear() ? 2 : 4);
        }
        int days = YearMonth.of(t.year(), t.month()).lengthOfMonth();
        if (t.day() < 1 || t.day() > days) {
            throw new Bad("day " + t.day() + " out of range for the month", t.twoDigitYear() ? 4 : 6);
        }
        // Midnight at the end of a day (24) is excluded (X.680 §46.2 a)).
        if (t.hour() > 23) {
            throw new Bad("hour " + t.hour() + " out of range", t.twoDigitYear() ? 6 : 8);
        }
        if (t.minute() > 59) {
            throw new Bad("minute " + t.minute() + " out of range", t.twoDigitYear() ? 8 : 10);
        }
        if (t.second() > (leapSecond ? 60 : 59)) {
            throw new Bad("second " + t.second() + " out of range", t.twoDigitYear() ? 10 : 12);
        }
        return t;
    }
}
