#include "meetings/meetingcontroller.h"

#include <QApplication>
#include <QMessageBox>
#include <QMutexLocker>
#include <QTimeZone>
#include <QUuid>

#include "meetings/meetingdialog.h"
#include "meetings/schedulerwindow.h"
#include "common/ts3api.h"
#include "meetings/warnpopup.h"
#include "teamspeak/public_definitions.h"
#include "teamspeak/public_errors.h"

namespace gf {

namespace {
constexpr qint64 kCancelWindowSecs = 600;
const QString    kTag              = QStringLiteral("[Meetings] ");
} // namespace

MeetingController::MeetingController(QString iniPath, QString soundPath, QObject* parent)
    : QObject(parent), m_iniPath(std::move(iniPath)), m_soundPath(std::move(soundPath))
{
    m_timer.setInterval(1000);
    connect(&m_timer, &QTimer::timeout, this, &MeetingController::tick);
}

MeetingController::~MeetingController()
{
    m_timer.stop();
    // Includes windows closed with WA_DeleteOnClose whose deferred delete hasn't run yet: after
    // ts3plugin_shutdown the DLL is unloaded, so nothing of ours may be left for the event loop.
    m_windows.deleteAll();
}

void MeetingController::start()
{
    m_meetings = MeetingStore(m_iniPath).load();
    const QDateTime now = QDateTime::currentDateTimeUtc();
    for (const Meeting& m : m_meetings)
        recompute(m.id, now);  // no catch-up for occurrences before plugin start
    m_timer.start();
    emit meetingsChanged();
}

const Meeting* MeetingController::find(const QString& id) const
{
    for (const Meeting& m : m_meetings)
        if (m.id == id)
            return &m;
    return nullptr;
}

QDateTime MeetingController::nextStart(const QString& id) const { return m_occ.value(id).startUtc; }

void MeetingController::recompute(const QString& id, const QDateTime& afterUtc)
{
    const Meeting* m = find(id);
    m_occ[id] = Occurrence{m ? nextOccurrence(m->schedule, afterUtc) : QDateTime()};
}

void MeetingController::save() { MeetingStore(m_iniPath).save(m_meetings); }

void MeetingController::upsertMeeting(const Meeting& m)
{
    bool replaced = false;
    for (Meeting& existing : m_meetings)
        if (existing.id == m.id) {
            existing = m;
            replaced = true;
        }
    if (!replaced)
        m_meetings << m;
    save();
    closeWarning(m.id);
    recompute(m.id, QDateTime::currentDateTimeUtc());
    emit meetingsChanged();
}

void MeetingController::removeMeeting(const QString& id)
{
    m_meetings.erase(std::remove_if(m_meetings.begin(), m_meetings.end(), [&](const Meeting& m) { return m.id == id; }),
                     m_meetings.end());
    m_occ.remove(id);
    closeWarning(id);
    save();
    emit meetingsChanged();
}

void MeetingController::tick()
{
    const QDateTime now = QDateTime::currentDateTimeUtc();
    const QVector<Meeting> snapshot = m_meetings;  // execute() must not see the list change under it
    for (const Meeting& m : snapshot) {
        Occurrence& occ = m_occ[m.id];
        switch (decide(m, occ, now)) {
            case FireAction::None:
                break;
            case FireAction::ShowWarning:
                occ.warned = true;
                showWarning(m);
                break;
            case FireAction::Execute: {
                const QDateTime start = occ.startUtc;
                closeWarning(m.id);
                execute(m);
                recompute(m.id, start);
                break;
            }
            case FireAction::Advance: {
                const QDateTime start = occ.startUtc;
                closeWarning(m.id);
                recompute(m.id, start);
                break;
            }
        }
    }
}

void MeetingController::markImminentDone(const QString& id)
{
    Occurrence& occ = m_occ[id];
    if (!occ.startUtc.isValid())
        return;
    if (m_popups.contains(id) || QDateTime::currentDateTimeUtc().secsTo(occ.startUtc) <= kCancelWindowSecs) {
        occ.done = true;
        closeWarning(id);
    }
}

void MeetingController::executeNow(const QString& id)
{
    if (const Meeting* m = find(id)) {
        const Meeting copy = *m;
        markImminentDone(copy.id);
        execute(copy);
    }
}

void MeetingController::joinNextNow()
{
    const Meeting* best = nullptr;
    QDateTime bestStart;
    for (const Meeting& m : m_meetings) {
        const QDateTime s = m_occ.value(m.id).startUtc;
        if (m.enabled && s.isValid() && (!best || s < bestStart)) {
            best      = &m;
            bestStart = s;
        }
    }
    if (!best) {
        ts3::print(ts3::currentServer(), kTag + QStringLiteral("No upcoming meetings."));
        return;
    }
    const Meeting copy = *best;
    markImminentDone(copy.id);
    execute(copy);
}

void MeetingController::cancelPending()
{
    const QDateTime now = QDateTime::currentDateTimeUtc();
    QStringList skipped;
    for (const Meeting& m : m_meetings) {
        Occurrence& occ = m_occ[m.id];
        if (!m.enabled || !occ.startUtc.isValid() || occ.cancelled || occ.done)
            continue;
        if (m_popups.contains(m.id) || now.secsTo(occ.startUtc) <= kCancelWindowSecs) {
            occ.cancelled = true;
            closeWarning(m.id);
            skipped << m.name;
        }
    }
    ts3::print(ts3::currentServer(),
               kTag + (skipped.isEmpty() ? QStringLiteral("No meeting move is pending.")
                                         : QStringLiteral("Not moving you for: %1 (this time only).").arg(skipped.join(QStringLiteral(", ")))));
}

void MeetingController::execute(const Meeting& m)
{
    if (const quint64 schid = ts3::findServer(m.serverUid, m.host, m.port)) {
        moveInto(schid, m, false);
        return;
    }
    const quint64 cur = ts3::currentServer();
    for (const QString& pendingId : m_pendingConnect)
        if (pendingId == m.id) {
            ts3::print(cur, kTag + QStringLiteral("Already connecting to %1 for '%2'.").arg(m.serverName, m.name));
            return;
        }
    ts3::print(cur, kTag + QStringLiteral("Connecting to %1 (%2:%3) for '%4'…").arg(m.serverName, m.host).arg(m.port).arg(m.name));
    if (const quint64 schid = ts3::connectNewTab(m))
        m_pendingConnect[schid] = m.id;
    else
        ts3::print(cur, kTag + QStringLiteral("Could not open a connection to %1.").arg(m.serverName));
}

void MeetingController::moveInto(quint64 schid, const Meeting& m, bool afterConnect)
{
    const QString chanName = channelDisplayName(m);
    const quint64 chan     = ts3::resolveChannel(schid, m.channelPath, m.channelId);
    if (!chan) {
        ts3::print(schid, kTag + QStringLiteral("Channel '%1' for '%2' not found on this server.").arg(m.channelPath, m.name));
        return;
    }
    if (ts3::ownChannel(schid) == chan) {
        ts3::print(schid, kTag + (afterConnect ? QStringLiteral("Joined %1 for '%2'.") : QStringLiteral("You're already in %1 for '%2'."))
                                     .arg(chanName, m.name));
        return;
    }
    QByteArray rc;
    if (!ts3::moveSelf(schid, chan, m.channelPassword, &rc)) {
        ts3::print(schid, kTag + QStringLiteral("Could not move you to %1.").arg(chanName));
        return;
    }
    if (!rc.isEmpty()) {
        QMutexLocker lock(&m_rcMutex);
        m_returnCodes.insert(rc, chanName);
    }
    ts3::print(schid, kTag + QStringLiteral("Moving you to %1 for '%2'.").arg(chanName, m.name));
}

void MeetingController::onConnectStatus(quint64 schid, int status)
{
    if (status == STATUS_DISCONNECTED) {
        m_pendingConnect.remove(schid);
        return;
    }
    if (status != STATUS_CONNECTION_ESTABLISHED || !m_pendingConnect.contains(schid))
        return;
    const QString id = m_pendingConnect.take(schid);
    if (const Meeting* m = find(id)) {
        const Meeting copy = *m;
        moveInto(schid, copy, true);
    }
}

bool MeetingController::onServerError(quint64 schid, const QString& message, unsigned int error, const QByteArray& returnCode)
{
    QString chanName;
    {
        QMutexLocker lock(&m_rcMutex);
        if (returnCode.isEmpty() || !m_returnCodes.contains(returnCode))
            return false;
        chanName = m_returnCodes.take(returnCode);
    }
    if (error != ERROR_ok)
        ts3::print(schid, kTag + QStringLiteral("Could not move you to %1: %2").arg(chanName, message));
    return true;
}

void MeetingController::openScheduler()
{
    QWidget* parent = gf::dialogParent();
    if (!m_window) {
        auto* w = new SchedulerWindow(this, parent);
        m_windows.own(w);
        m_window = w;
    } else if (QApplication::activeModalWidget() && parent != m_window && !parent->isAncestorOf(m_window)) {
        m_window->setParent(parent, m_window->windowFlags());  // already open, but now behind a modal dialog
    }
    m_window->show();
    m_window->raise();
    m_window->activateWindow();
}

Meeting MeetingController::newMeetingFor(quint64 schid, quint64 channelId) const
{
    Meeting m;
    m.id = QUuid::createUuid().toString(QUuid::WithoutBraces);
    if (const auto t = ts3::serverTab(schid)) {
        m.serverName     = t->name;
        m.serverUid      = t->uid;
        m.host           = t->host;
        m.port           = t->port;
        m.serverPassword = t->password;
        m.nickname       = t->nickname;
    }
    m.channelId = channelId;
    for (const auto& c : ts3::channels(schid))
        if (c.id == channelId)
            m.channelPath = c.path;
    m.channelPassword = ts3::channelPassword(schid, channelId);
    m.name            = QStringLiteral("Meeting in %1").arg(channelDisplayName(m));

    QDateTime nextHour = QDateTime::currentDateTime().addSecs(3600);  // default: next full hour, weekly
    nextHour.setTime(QTime(nextHour.time().hour(), 0));
    m.schedule.startDate  = nextHour.date();
    m.schedule.time       = nextHour.time();
    m.schedule.timeZoneId = QTimeZone::systemTimeZoneId();
    m.schedule.repeat     = Repeat::Weekly;
    m.schedule.weekdays   = quint8(1u << (nextHour.date().dayOfWeek() - 1));
    return m;
}

void MeetingController::openMeetingDialog(const Meeting& m, bool isNew)
{
    if (m_dialog) {  // one editor at a time
        m_dialog->raise();
        m_dialog->activateWindow();
        return;
    }
    QWidget* parent = (m_window && m_window->isVisible()) ? m_window.data() : gf::dialogParent();
    auto* dlg = new MeetingDialog(m, isNew, parent);
    m_windows.own(dlg);
    m_dialog = dlg;
    connect(dlg, &QDialog::accepted, this, [this, dlg] { upsertMeeting(dlg->result()); });
    dlg->open();
}

void MeetingController::addMeetingForChannel(quint64 schid, quint64 channelId)
{
    openMeetingDialog(newMeetingFor(schid, channelId), true);
}

void MeetingController::addMeetingFromCurrentTab()
{
    quint64 schid = ts3::currentServer();
    if (!ts3::serverTab(schid)) {
        const auto tabs = ts3::connectedServers();
        schid = tabs.isEmpty() ? 0 : tabs.first().schid;
    }
    if (!schid) {
        auto* box = new QMessageBox(QMessageBox::Information, QStringLiteral("Add meeting"),
                                    QStringLiteral("Connect to the meeting's server first — then right-click a channel and choose "
                                                   "<b>Add meeting here…</b>, or click <b>Add…</b> again."),
                                    QMessageBox::Ok, m_window ? m_window.data() : gf::dialogParent());
        box->setAttribute(Qt::WA_DeleteOnClose);
        m_windows.own(box);
        box->open();
        return;
    }
    openMeetingDialog(newMeetingFor(schid, ts3::ownChannel(schid)), true);
}

void MeetingController::editMeeting(const QString& id)
{
    if (const Meeting* m = find(id))
        openMeetingDialog(*m, false);
}

void MeetingController::showWarning(const Meeting& m)
{
    const QString id = m.id;
    auto* popup = new WarnPopup(m, m_occ.value(id).startUtc);  // top-level: must show even if TS3 is minimized
    m_windows.own(popup);
    m_popups[id] = popup;
    connect(popup, &WarnPopup::moveNowClicked, this, [this, id] {
        m_occ[id].done = true;
        closeWarning(id);
        executeNow(id);
    });
    connect(popup, &WarnPopup::dontMoveClicked, this, [this, id] {
        m_occ[id].cancelled = true;
        closeWarning(id);
        if (const Meeting* mm = find(id))
            ts3::print(ts3::currentServer(), kTag + QStringLiteral("Not moving you for '%1' this time.").arg(mm->name));
    });
    popup->show();
    const quint64 schid = ts3::findServer(m.serverUid, m.host, m.port);
    ts3::playSound(schid ? schid : ts3::currentServer(), m_soundPath);
}

void MeetingController::closeWarning(const QString& id)
{
    // close() + WA_DeleteOnClose defers the delete: safe even when called from the pop-up's own button.
    if (QPointer<QWidget> p = m_popups.take(id))
        p->close();
}

} // namespace gf
