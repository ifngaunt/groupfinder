#pragma once
// Owns the meeting list, the 1-second scheduler tick, all windows and every TS3 action the
// scheduler takes. Lives on Qt's GUI thread; gf_meetings.cpp queues calls onto it.
#include <QByteArray>
#include <QDateTime>
#include <QHash>
#include <QMutex>
#include <QObject>
#include <QPointer>
#include <QTimer>
#include <QVector>

#include "meetings/firing.h"
#include "meetings/meeting.h"

class QWidget;

namespace gf {

class MeetingController : public QObject {
    Q_OBJECT
public:
    MeetingController(QString iniPath, QString soundPath, QObject* parent = nullptr);
    ~MeetingController() override;  // closes every window this controller opened

    void start();  // load meetings, compute next occurrences, start the tick

    const QVector<Meeting>& meetings() const { return m_meetings; }
    QDateTime nextStart(const QString& id) const;  // UTC, invalid if none
    void upsertMeeting(const Meeting& m);
    void removeMeeting(const QString& id);

    void executeNow(const QString& id);  // move/connect right away (doesn't change the schedule)
    void joinNextNow();                   // hotkey: the enabled meeting starting soonest
    void cancelPending();                 // hotkey: skip occurrences being warned about or starting within 10 min

    void openScheduler();
    void addMeetingForChannel(quint64 schid, quint64 channelId);  // right-click channel -> pre-filled dialog
    void addMeetingFromCurrentTab();                               // "Add…" button: current tab + own channel
    void editMeeting(const QString& id);

    void onConnectStatus(quint64 schid, int status);
    // Thread-safe: called from TS3's callback thread.
    bool onServerError(quint64 schid, const QString& message, unsigned int error, const QByteArray& returnCode);

signals:
    void meetingsChanged();

private:
    void tick();
    void execute(const Meeting& m);
    void markImminentDone(const QString& id);  // user joined early: don't move again at start
    void moveInto(quint64 schid, const Meeting& m, bool afterConnect);
    void recompute(const QString& id, const QDateTime& afterUtc);
    void save();
    void showWarning(const Meeting& m);
    void closeWarning(const QString& id);
    void openMeetingDialog(const Meeting& m, bool isNew);
    Meeting newMeetingFor(quint64 schid, quint64 channelId) const;
    void own(QWidget* w);  // every window we create; deleted in the destructor if still alive
    QWidget* dialogParent() const;  // active modal dialog (e.g. TS3 Options) if any, else TS3's main window
    const Meeting* find(const QString& id) const;

    QString                            m_iniPath, m_soundPath;
    QVector<Meeting>                   m_meetings;
    QHash<QString, Occurrence>         m_occ;             // meeting id -> next occurrence state
    QTimer                             m_timer{this};
    QHash<quint64, QString>            m_pendingConnect;  // new connection handler -> meeting id
    QMutex                             m_rcMutex;
    QHash<QByteArray, QString>         m_returnCodes;     // move request -> channel display name
    QPointer<QWidget>                  m_window;
    QPointer<QWidget>                  m_dialog;
    QHash<QString, QPointer<QWidget>>  m_popups;          // meeting id -> warning pop-up
    QVector<QPointer<QWidget>>         m_owned;
};

} // namespace gf
