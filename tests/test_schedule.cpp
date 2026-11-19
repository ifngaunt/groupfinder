#include <QtTest>

#include "meetings/schedule.h"
#include "tests.h"

using gf::Repeat;
using gf::Schedule;

namespace {
constexpr quint8 Mon = 0x01, Tue = 0x02, Thu = 0x08;

QDateTime U(const char* iso) { return QDateTime::fromString(QString::fromLatin1(iso), Qt::ISODate); }

Schedule S(const char* date, const char* time, const char* zone, Repeat repeat, int interval = 1, quint8 days = 0)
{
    Schedule s;
    s.startDate  = QDate::fromString(QString::fromLatin1(date), Qt::ISODate);
    s.time       = QTime::fromString(QString::fromLatin1(time), QStringLiteral("HH:mm"));
    s.timeZoneId = zone;
    s.repeat     = repeat;
    s.interval   = interval;
    s.weekdays   = days;
    return s;
}
} // namespace

class TestSchedule : public QObject {
    Q_OBJECT
private slots:
    void once_beforeStart()
    {
        auto s = S("2026-11-25", "20:00", "Europe/Berlin", Repeat::Once);
        QCOMPARE(gf::nextOccurrence(s, U("2026-11-20T00:00:00Z")), U("2026-11-25T19:00:00Z"));
    }
    void once_afterItPassed()
    {
        auto s = S("2026-11-25", "20:00", "Europe/Berlin", Repeat::Once);
        QVERIFY(!gf::nextOccurrence(s, U("2026-11-26T00:00:00Z")).isValid());
    }
    void weekly_nextTickedDay()
    {
        auto s = S("2026-11-17", "20:00", "Europe/Berlin", Repeat::Weekly, 1, Tue | Thu);
        QCOMPARE(gf::nextOccurrence(s, U("2026-11-19T12:00:00Z")), U("2026-11-19T19:00:00Z"));
    }
    void weekly_strictlyAfter()
    {
        auto s = S("2026-11-17", "20:00", "Europe/Berlin", Repeat::Weekly, 1, Tue | Thu);
        QCOMPARE(gf::nextOccurrence(s, U("2026-11-19T19:00:00Z")), U("2026-11-24T19:00:00Z"));
    }
    void weekly_everyTwoWeeks()
    {
        auto s = S("2026-11-17", "20:00", "Europe/Berlin", Repeat::Weekly, 2, Tue);
        QCOMPARE(gf::nextOccurrence(s, U("2026-11-18T00:00:00Z")), U("2026-12-01T19:00:00Z"));
    }
    void weekly_notBeforeStart()
    {
        auto s = S("2026-12-01", "20:00", "Europe/Berlin", Repeat::Weekly, 1, Tue);
        QCOMPARE(gf::nextOccurrence(s, U("2026-11-19T00:00:00Z")), U("2026-12-01T19:00:00Z"));
    }
    void dst_keepsWallClock()
    {
        // EU summer time starts 2027-03-28: 20:00 Berlin is 19:00Z before, 18:00Z after.
        auto s     = S("2027-03-23", "20:00", "Europe/Berlin", Repeat::Weekly, 1, Tue);
        auto first = gf::nextOccurrence(s, U("2027-03-23T00:00:00Z"));
        QCOMPARE(first, U("2027-03-23T19:00:00Z"));
        QCOMPARE(gf::nextOccurrence(s, first), U("2027-03-30T18:00:00Z"));
    }
    void dstGap_shiftsForward()
    {
        // 02:30 does not exist on 2027-03-28 in Berlin; expect 03:30 CEST = 01:30Z.
        auto s = S("2027-03-27", "02:30", "Europe/Berlin", Repeat::Daily);
        QCOMPARE(gf::nextOccurrence(s, U("2027-03-27T12:00:00Z")), U("2027-03-28T01:30:00Z"));
    }
    void daily_everyThreeDays()
    {
        auto s = S("2026-11-19", "09:00", "UTC", Repeat::Daily, 3);
        QCOMPARE(gf::nextOccurrence(s, U("2026-11-20T00:00:00Z")), U("2026-11-22T09:00:00Z"));
    }
    void monthly_clampsLastDay()
    {
        auto s = S("2027-01-31", "12:00", "UTC", Repeat::Monthly);
        QCOMPARE(gf::nextOccurrence(s, U("2027-02-01T00:00:00Z")), U("2027-02-28T12:00:00Z"));
    }
    void monthly_interval()
    {
        auto s = S("2026-11-05", "12:00", "UTC", Repeat::Monthly, 3);
        QCOMPARE(gf::nextOccurrence(s, U("2026-11-06T00:00:00Z")), U("2027-02-05T12:00:00Z"));
    }
    void unknownZone_usesSystem()
    {
        auto s = S("2026-11-19", "12:00", "Not/AZone", Repeat::Daily);
        QVERIFY(gf::nextOccurrence(s, U("2026-11-19T00:00:00Z")).isValid());
        QCOMPARE(gf::scheduleZone(s), QTimeZone::systemTimeZone());
    }
    void isValid_rules()
    {
        QVERIFY(gf::isValid(S("2026-11-17", "20:00", "UTC", Repeat::Weekly, 1, Tue)));
        QVERIFY(!gf::isValid(S("2026-11-17", "20:00", "UTC", Repeat::Weekly, 1, 0)));
        QVERIFY(!gf::isValid(S("2026-11-17", "20:00", "UTC", Repeat::Daily, 0)));
        QVERIFY(!gf::isValid(S("bad", "20:00", "UTC", Repeat::Once)));
    }
    void describe_cases()
    {
        QCOMPARE(gf::describeRepeat(S("2026-11-17", "20:00", "UTC", Repeat::Once)), QStringLiteral("Once"));
        QCOMPARE(gf::describeRepeat(S("2026-11-17", "20:00", "UTC", Repeat::Daily)), QStringLiteral("Daily"));
        QCOMPARE(gf::describeRepeat(S("2026-11-17", "20:00", "UTC", Repeat::Daily, 2)), QStringLiteral("Every 2 days"));
        QCOMPARE(gf::describeRepeat(S("2026-11-17", "20:00", "UTC", Repeat::Weekly, 1, Tue | Thu)), QStringLiteral("Weekly on Tue, Thu"));
        QCOMPARE(gf::describeRepeat(S("2026-11-17", "20:00", "UTC", Repeat::Weekly, 2, Tue)), QStringLiteral("Every 2 weeks on Tue"));
        QCOMPARE(gf::describeRepeat(S("2027-01-31", "20:00", "UTC", Repeat::Monthly)), QStringLiteral("Monthly on day 31"));
        QCOMPARE(gf::describeRepeat(S("2026-11-05", "20:00", "UTC", Repeat::Monthly, 3)), QStringLiteral("Every 3 months on day 5"));
        Q_UNUSED(Mon);
    }
};

QObject* createTestSchedule() { return new TestSchedule; }

#include "test_schedule.moc"
