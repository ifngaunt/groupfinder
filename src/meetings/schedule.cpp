#include "meetings/schedule.h"

#include <QStringList>
#include <algorithm>

namespace gf {

namespace {

QDate mondayOf(const QDate& d) { return d.addDays(1 - d.dayOfWeek()); }

int monthsBetween(const QDate& from, const QDate& to)
{
    return (to.year() - from.year()) * 12 + (to.month() - from.month());
}

bool matchesDay(const Schedule& s, const QDate& d)
{
    if (d < s.startDate)
        return false;
    switch (s.repeat) {
        case Repeat::Once:
            return d == s.startDate;
        case Repeat::Daily:
            return s.startDate.daysTo(d) % s.interval == 0;
        case Repeat::Weekly: {
            if (!(s.weekdays & (1u << (d.dayOfWeek() - 1))))
                return false;
            const qint64 weeks = mondayOf(s.startDate).daysTo(mondayOf(d)) / 7;
            return weeks % s.interval == 0;
        }
        case Repeat::Monthly:
            return monthsBetween(s.startDate, d) % s.interval == 0 &&
                   d.day() == std::min(s.startDate.day(), d.daysInMonth());
    }
    return false;
}

// The wall-clock time on day d in zone z. A time that falls in a DST gap moves forward an hour.
QDateTime atWallClock(const QDate& d, const QTime& t, const QTimeZone& z)
{
    QDateTime dt(d, t, z);
    if (!dt.isValid())
        dt = QDateTime(d, t.addSecs(3600), z);
    return dt;
}

} // namespace

QTimeZone scheduleZone(const Schedule& s)
{
    if (!s.timeZoneId.isEmpty()) {
        QTimeZone z(s.timeZoneId);
        if (z.isValid())
            return z;
    }
    return QTimeZone::systemTimeZone();
}

bool isValid(const Schedule& s)
{
    if (!s.startDate.isValid() || !s.time.isValid() || s.interval < 1)
        return false;
    if (s.repeat == Repeat::Weekly && (s.weekdays & 0x7F) == 0)
        return false;
    return true;
}

QDateTime nextOccurrence(const Schedule& s, const QDateTime& after)
{
    if (!isValid(s) || !after.isValid())
        return QDateTime();

    const QTimeZone z = scheduleZone(s);
    if (s.repeat == Repeat::Once) {
        const QDateTime dt = atWallClock(s.startDate, s.time, z);
        return dt > after ? dt.toUTC() : QDateTime();
    }

    // Start one day early so a time that is still ahead today (in the zone) is not skipped.
    QDate d = std::max(s.startDate, after.toTimeZone(z).date().addDays(-1));
    const qint64 limit = 400LL * s.interval + 62;  // covers every pattern's full period
    for (qint64 i = 0; i <= limit; ++i, d = d.addDays(1)) {
        if (!matchesDay(s, d))
            continue;
        const QDateTime dt = atWallClock(d, s.time, z);
        if (dt > after)
            return dt.toUTC();
    }
    return QDateTime();
}

QString describeRepeat(const Schedule& s)
{
    static const char* kDays[] = {"Mon", "Tue", "Wed", "Thu", "Fri", "Sat", "Sun"};
    const int n = s.interval;
    switch (s.repeat) {
        case Repeat::Once:
            return QStringLiteral("Once");
        case Repeat::Daily:
            return n == 1 ? QStringLiteral("Daily") : QStringLiteral("Every %1 days").arg(n);
        case Repeat::Weekly: {
            QStringList days;
            for (int i = 0; i < 7; ++i)
                if (s.weekdays & (1u << i))
                    days << QString::fromLatin1(kDays[i]);
            const QString on = days.join(QStringLiteral(", "));
            return n == 1 ? QStringLiteral("Weekly on %1").arg(on) : QStringLiteral("Every %1 weeks on %2").arg(n).arg(on);
        }
        case Repeat::Monthly:
            return n == 1 ? QStringLiteral("Monthly on day %1").arg(s.startDate.day())
                          : QStringLiteral("Every %1 months on day %2").arg(n).arg(s.startDate.day());
    }
    return QString();
}

} // namespace gf
