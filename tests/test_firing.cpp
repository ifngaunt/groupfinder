#include <QtTest>

#include "meetings/firing.h"
#include "tests.h"

using gf::Action;
using gf::FireAction;
using gf::Meeting;
using gf::Occurrence;

namespace {
const QDateTime S = QDateTime::fromString(QStringLiteral("2026-11-24T19:00:00Z"), Qt::ISODate);

Meeting meeting(Action a = Action::MoveAtStart, int warn = 2)
{
    Meeting m;
    m.action      = a;
    m.warnMinutes = warn;
    return m;
}
Occurrence occ() { return Occurrence{S}; }
int act(const Meeting& m, const Occurrence& o, qint64 offsetSecs) { return int(gf::decide(m, o, S.addSecs(offsetSecs))); }
} // namespace

class TestFiring : public QObject {
    Q_OBJECT
private slots:
    void disabled_none()
    {
        Meeting m = meeting();
        m.enabled = false;
        QCOMPARE(act(m, occ(), 0), int(FireAction::None));
    }
    void atStart_execute() { QCOMPARE(act(meeting(), occ(), 0), int(FireAction::Execute)); }
    void withinGrace_execute() { QCOMPARE(act(meeting(), occ(), 299), int(FireAction::Execute)); }
    void missed_advance() { QCOMPARE(act(meeting(), occ(), 301), int(FireAction::Advance)); }
    void cancelled_advance()
    {
        Occurrence o = occ();
        o.cancelled  = true;
        QCOMPARE(act(meeting(Action::WarnThenMove), o, 1), int(FireAction::Advance));
    }
    void done_advance()
    {
        Occurrence o = occ();
        o.done       = true;
        QCOMPARE(act(meeting(), o, 0), int(FireAction::Advance));
    }
    void warnWindow_show() { QCOMPARE(act(meeting(Action::WarnThenMove, 2), occ(), -120), int(FireAction::ShowWarning)); }
    void beforeWarnWindow_none() { QCOMPARE(act(meeting(Action::WarnThenMove, 2), occ(), -121), int(FireAction::None)); }
    void alreadyWarned_none()
    {
        Occurrence o = occ();
        o.warned     = true;
        QCOMPARE(act(meeting(Action::WarnThenMove, 2), o, -60), int(FireAction::None));
    }
    void moveMode_neverWarns() { QCOMPARE(act(meeting(Action::MoveAtStart, 2), occ(), -60), int(FireAction::None)); }
    void invalidStart_none() { QCOMPARE(int(gf::decide(meeting(), Occurrence{}, S)), int(FireAction::None)); }
};

QObject* createTestFiring() { return new TestFiring; }

#include "test_firing.moc"
