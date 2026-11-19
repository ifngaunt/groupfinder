#include <QFile>
#include <QTemporaryDir>
#include <QtTest>

#include "meetings/meeting.h"
#include "tests.h"

using gf::Action;
using gf::Meeting;
using gf::MeetingStore;
using gf::Repeat;

namespace {
Meeting fullMeeting()
{
    Meeting m;
    m.id                   = QStringLiteral("0b6c7a8e-1111-2222-3333-444455556666");
    m.name                 = QStringLiteral("Böse Öps — ✓");
    m.enabled              = false;
    m.serverName           = QStringLiteral("Arma Community");
    m.serverUid            = QStringLiteral("abc+/=UID");
    m.host                 = QStringLiteral("ts.example.com");
    m.port                 = 10011;
    m.serverPassword       = QStringLiteral("s3rv=pw;");
    m.nickname             = QStringLiteral("PhysicsGaunt");
    m.channelId            = 4242;
    m.channelPath          = QStringLiteral("Ops/Briefing");
    m.channelPassword      = QStringLiteral("chan pw");
    m.schedule.startDate   = QDate(2026, 11, 17);
    m.schedule.time        = QTime(20, 30);
    m.schedule.timeZoneId  = "America/New_York";
    m.schedule.repeat      = Repeat::Monthly;
    m.schedule.interval    = 3;
    m.schedule.weekdays    = 0x2A;
    m.action               = Action::WarnThenMove;
    m.warnMinutes          = 5;
    return m;
}

void compareMeetings(const Meeting& a, const Meeting& b)
{
    QCOMPARE(a.id, b.id);
    QCOMPARE(a.name, b.name);
    QCOMPARE(a.enabled, b.enabled);
    QCOMPARE(a.serverName, b.serverName);
    QCOMPARE(a.serverUid, b.serverUid);
    QCOMPARE(a.host, b.host);
    QCOMPARE(a.port, b.port);
    QCOMPARE(a.serverPassword, b.serverPassword);
    QCOMPARE(a.nickname, b.nickname);
    QCOMPARE(a.channelId, b.channelId);
    QCOMPARE(a.channelPath, b.channelPath);
    QCOMPARE(a.channelPassword, b.channelPassword);
    QCOMPARE(a.schedule.startDate, b.schedule.startDate);
    QCOMPARE(a.schedule.time, b.schedule.time);
    QCOMPARE(a.schedule.timeZoneId, b.schedule.timeZoneId);
    QCOMPARE(int(a.schedule.repeat), int(b.schedule.repeat));
    QCOMPARE(a.schedule.interval, b.schedule.interval);
    QCOMPARE(a.schedule.weekdays, b.schedule.weekdays);
    QCOMPARE(int(a.action), int(b.action));
    QCOMPARE(a.warnMinutes, b.warnMinutes);
}
} // namespace

class TestMeeting : public QObject {
    Q_OBJECT
private slots:
    void store_roundTrip()
    {
        QTemporaryDir dir;
        MeetingStore store(dir.filePath(QStringLiteral("m.ini")));
        const Meeting m = fullMeeting();
        store.save({m});
        const auto loaded = MeetingStore(dir.filePath(QStringLiteral("m.ini"))).load();
        QCOMPARE(loaded.size(), 1);
        compareMeetings(loaded.first(), m);
    }
    void store_missingFile()
    {
        QTemporaryDir dir;
        QVERIFY(MeetingStore(dir.filePath(QStringLiteral("nope.ini"))).load().isEmpty());
    }
    void store_saveRemovesDeleted()
    {
        QTemporaryDir dir;
        MeetingStore store(dir.filePath(QStringLiteral("m.ini")));
        Meeting a = fullMeeting(), b = fullMeeting();
        a.id = QStringLiteral("a");
        b.id = QStringLiteral("b");
        store.save({a, b});
        store.save({b});
        const auto loaded = store.load();
        QCOMPARE(loaded.size(), 1);
        QCOMPARE(loaded.first().id, QStringLiteral("b"));
    }
    void store_loadToleratesGarbage()
    {
        QTemporaryDir dir;
        const QString path = dir.filePath(QStringLiteral("m.ini"));
        QFile f(path);
        QVERIFY(f.open(QIODevice::WriteOnly));
        f.write("[abc]\nname=X\ntimeZone=Bogus/Zone\nrepeat=99\n");
        f.close();
        const auto loaded = MeetingStore(path).load();
        QCOMPARE(loaded.size(), 1);
        const Meeting& m = loaded.first();
        QCOMPARE(m.id, QStringLiteral("abc"));
        QCOMPARE(m.name, QStringLiteral("X"));
        QCOMPARE(int(m.schedule.repeat), int(Repeat::Once));
        QCOMPARE(m.port, quint16(9987));
        QCOMPARE(m.warnMinutes, 2);
        QCOMPARE(m.enabled, true);
        QCOMPARE(int(m.action), int(Action::MoveAtStart));
    }
    void store_keepsSeconds()
    {
        QTemporaryDir dir;
        MeetingStore store(dir.filePath(QStringLiteral("m.ini")));
        Meeting m = fullMeeting();
        m.schedule.time = QTime(20, 30, 15);
        store.save({m});
        QCOMPARE(store.load().first().schedule.time, QTime(20, 30, 15));
    }
    void store_readsMinutesOnlyTime()
    {
        QTemporaryDir dir;
        const QString path = dir.filePath(QStringLiteral("m.ini"));
        QFile f(path);
        QVERIFY(f.open(QIODevice::WriteOnly));
        f.write("[abc]\ntime=20:30\n");
        f.close();
        QCOMPARE(MeetingStore(path).load().first().schedule.time, QTime(20, 30));
    }
    void splitPath_cases()
    {
        QCOMPARE(gf::splitChannelPath(QStringLiteral("Ops/Briefing")), (QStringList{"Ops", "Briefing"}));
        QCOMPARE(gf::splitChannelPath(QStringLiteral("A\\/B/C")), (QStringList{"A/B", "C"}));
        QCOMPARE(gf::splitChannelPath(QString()), QStringList());
    }
    void displayName_cases()
    {
        Meeting m;
        m.channelPath = QStringLiteral("Ops/Briefing");
        QCOMPARE(gf::channelDisplayName(m), QStringLiteral("Briefing"));
        m.channelPath.clear();
        m.channelId = 12;
        QCOMPARE(gf::channelDisplayName(m), QStringLiteral("#12"));
    }
};

QObject* createTestMeeting() { return new TestMeeting; }

#include "test_meeting.moc"
