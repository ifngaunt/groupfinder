#pragma once
// A scheduled meeting and its on-disk store. Pure logic on QtCore only (tests/test_meeting.cpp).
#include <QString>
#include <QStringList>
#include <QVector>

#include "meetings/schedule.h"

namespace gf {

enum class Action { MoveAtStart = 0, WarnThenMove = 1 };

struct Meeting {
    QString  id;              // QUuid without braces; also the INI group name
    QString  name;
    bool     enabled = true;
    // Server: matched by uid when connected; host/port/password used to open a new tab.
    QString  serverName, serverUid, host;
    quint16  port = 9987;
    QString  serverPassword, nickname;
    // Channel: resolved by path first (survives ID changes), then by id.
    quint64  channelId = 0;
    QString  channelPath, channelPassword;
    Schedule schedule;
    Action   action      = Action::MoveAtStart;
    int      warnMinutes = 2;
};

// "Ops/Briefing" -> {"Ops", "Briefing"}; "\/" is an escaped slash inside a channel name.
QStringList splitChannelPath(const QString& path);
// Last path segment, or "#<channelId>" when the path is empty.
QString channelDisplayName(const Meeting& m);

class MeetingStore {
public:
    explicit MeetingStore(QString iniPath);
    QVector<Meeting> load() const;
    void save(const QVector<Meeting>& meetings) const;  // replaces the file's contents

private:
    QString m_path;
};

} // namespace gf
