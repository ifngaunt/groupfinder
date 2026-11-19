#pragma once
// When a meeting happens. Pure logic on QtCore only (unit-tested in tests/test_schedule.cpp).
#include <QByteArray>
#include <QDate>
#include <QDateTime>
#include <QString>
#include <QTime>
#include <QTimeZone>

namespace gf {

enum class Repeat { Once = 0, Daily = 1, Weekly = 2, Monthly = 3 };

struct Schedule {
    QDate      startDate;      // first possible day, in the schedule's zone
    QTime      time;           // wall-clock time in the schedule's zone
    QByteArray timeZoneId;     // IANA id; empty or unknown = system zone
    Repeat     repeat   = Repeat::Weekly;
    int        interval = 1;   // every N days / weeks / months
    quint8     weekdays = 0;   // Weekly only: bit (dayOfWeek - 1), Mon = 0x01 ... Sun = 0x40
};

QTimeZone scheduleZone(const Schedule& s);
bool      isValid(const Schedule& s);
// First occurrence strictly after `after`, in UTC. Invalid QDateTime if there is none.
QDateTime nextOccurrence(const Schedule& s, const QDateTime& after);
// "Once", "Daily", "Every 2 days", "Weekly on Tue, Thu", "Every 3 months on day 5", ...
QString   describeRepeat(const Schedule& s);

} // namespace gf
