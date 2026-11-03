package io.github.schramp.gambasasn1.wire.types;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertInstanceOf;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.time.Instant;
import java.util.Optional;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.CsvSource;
import org.junit.jupiter.api.Test;

/** Reading UTCTime (X.680 §47) and GeneralizedTime (X.680 §46) text. */
class TimeParseTest {
    private static TimeParse.Time utc(String s) {
        return assertInstanceOf(TimeParse.Time.class, new Asn1UtcTime(s).parse(), s);
    }

    private static TimeParse.Time gen(String s) {
        return assertInstanceOf(TimeParse.Time.class, new Asn1GeneralizedTime(s).parse(), s);
    }

    @Test
    void utcTimeTwoDigitYearsReadIn1950To2049() {
        TimeParse.Time t = utc("491231235959Z");
        assertEquals(2049, t.year());
        assertTrue(t.twoDigitYear());
        assertEquals(1950, utc("500101000000Z").year());
        assertEquals(Optional.of(Instant.parse("2049-12-31T23:59:59Z")), t.instant());
    }

    @Test
    void utcTimeWithoutSecondsAndWithADifference() {
        TimeParse.Time m = utc("2401151430Z");
        assertEquals(TimeParse.Precision.MINUTE, m.precision());
        assertEquals(0, m.second());
        TimeParse.Time o = utc("240115143000+0130");
        assertEquals(TimeParse.Zone.OFFSET, o.zone());
        assertEquals(90, o.offsetMinutes());
        assertEquals(Optional.of(Instant.parse("2024-01-15T13:00:00Z")), o.instant());
        assertEquals(Optional.of(Instant.parse("2024-01-15T19:30:00Z")), utc("2401151430-0500").instant());
    }

    @Test
    void generalizedTimeFractionsOfEachComponent() {
        TimeParse.Time s = gen("20240115143000.5Z");
        assertEquals(500, s.millisecond());
        assertEquals(TimeParse.Precision.SECOND, s.precision());
        assertEquals(1, s.fractionDigits());
        assertEquals(Optional.of(Instant.parse("2024-01-15T14:30:00.5Z")), s.instant());
        TimeParse.Time h = gen("2024011514,25");
        assertEquals(TimeParse.Precision.HOUR, h.precision());
        assertEquals(15, h.minute());
        assertEquals(0, h.second());
        assertEquals(TimeParse.Zone.LOCAL, h.zone());
        assertEquals(Optional.empty(), h.instant());
        assertEquals("2024-01-15T14:15", h.localDateTime().toString());
        TimeParse.Time m = gen("202401151430.5-05");
        assertEquals(30, m.second());
        assertEquals(-300, m.offsetMinutes());
        assertEquals(Optional.of(Instant.parse("2024-01-15T19:30:30Z")), m.instant());
        assertEquals(123_456_789, gen("20240115143000.1234567891Z").nanos());
    }

    @Test
    void generalizedTimeLeapDayAndLeapSecond() {
        assertEquals(29, gen("20240229000000Z").day());
        assertEquals(60, gen("20161231235960Z").second());
    }

    @ParameterizedTest(name = "{0}")
    @CsvSource(delimiter = '|', value = {
            "u|2401151430|UTCTime needs Z or a time difference|10",
            "u|240115143060Z|second 60 out of range|10",
            "u|240115143000+01|text ends before the time difference minutes|15",
            "u|24011514300Z|expected a digit of the second|11",
            "u|991301000000Z|month 13 out of range|2",
            "g|20230229000000Z|day 29 out of range for the month|6",
            "g|20240115240000Z|hour 24 out of range|8",
            "g|20240115143000.Z|decimal sign without digits|15",
            "g|20240115143000Zx|unexpected character 'x'|15",
            "g|20240115143000+1900|time difference out of range|15",
            "g|2024011|text ends before the day|7",
            "g|'' |text ends before the year|0",
    })
    void malformedTextSaysWhyAndWhere(String kind, String text, String reason, int index) {
        String s = text.strip();
        TimeParse p = kind.equals("u") ? new Asn1UtcTime(s).parse() : new Asn1GeneralizedTime(s).parse();
        assertEquals(new TimeParse.Malformed(reason, index), p);
    }
}
