#include "meetings/meeting.h"

#include <QFile>
#include <QSettings>
#include <algorithm>

namespace gf {

QStringList splitChannelPath(const QString& path)
{
    QStringList parts;
    QString cur;
    for (int i = 0; i < path.size(); ++i) {
        const QChar c = path.at(i);
        if (c == QLatin1Char('\\') && i + 1 < path.size() && path.at(i + 1) == QLatin1Char('/')) {
            cur += QLatin1Char('/');
            ++i;
        } else if (c == QLatin1Char('/')) {
            if (!cur.isEmpty())
                parts << cur;
            cur.clear();
        } else {
            cur += c;
        }
    }
    if (!cur.isEmpty())
        parts << cur;
    return parts;
}

QString channelDisplayName(const Meeting& m)
{
    const QStringList parts = splitChannelPath(m.channelPath);
    return parts.isEmpty() ? QStringLiteral("#%1").arg(m.channelId) : parts.last();
}

MeetingStore::MeetingStore(QString iniPath) : m_path(std::move(iniPath)) {}

QVector<Meeting> MeetingStore::load() const
{
    QVector<Meeting> out;
    if (!QFile::exists(m_path))
        return out;

    QSettings ini(m_path, QSettings::IniFormat);
    ini.setIniCodec("UTF-8");
    for (const QString& group : ini.childGroups()) {
        ini.beginGroup(group);
        Meeting m;
        m.id              = group;
        m.name            = ini.value(QStringLiteral("name")).toString();
        m.enabled         = ini.value(QStringLiteral("enabled"), true).toBool();
        m.serverName      = ini.value(QStringLiteral("serverName")).toString();
        m.serverUid       = ini.value(QStringLiteral("serverUid")).toString();
        m.host            = ini.value(QStringLiteral("host")).toString();
        const uint port   = ini.value(QStringLiteral("port"), 9987).toUInt();
        m.port            = (port >= 1 && port <= 65535) ? quint16(port) : quint16(9987);
        m.serverPassword  = ini.value(QStringLiteral("serverPassword")).toString();
        m.nickname        = ini.value(QStringLiteral("nickname")).toString();
        m.channelId       = ini.value(QStringLiteral("channelId")).toULongLong();
        m.channelPath     = ini.value(QStringLiteral("channelPath")).toString();
        m.channelPassword = ini.value(QStringLiteral("channelPassword")).toString();

        Schedule& s  = m.schedule;
        s.startDate  = QDate::fromString(ini.value(QStringLiteral("startDate")).toString(), Qt::ISODate);
        const QString t = ini.value(QStringLiteral("time")).toString();
        s.time       = QTime::fromString(t, QStringLiteral("HH:mm:ss"));
        if (!s.time.isValid())
            s.time = QTime::fromString(t, QStringLiteral("HH:mm"));
        s.timeZoneId = ini.value(QStringLiteral("timeZone")).toString().toUtf8();
        const int r  = ini.value(QStringLiteral("repeat"), 0).toInt();
        s.repeat     = (r >= 0 && r <= 3) ? Repeat(r) : Repeat::Once;
        s.interval   = std::max(1, ini.value(QStringLiteral("interval"), 1).toInt());
        s.weekdays   = quint8(ini.value(QStringLiteral("weekdays"), 0).toUInt() & 0x7F);

        const int a   = ini.value(QStringLiteral("action"), 0).toInt();
        m.action      = a == 1 ? Action::WarnThenMove : Action::MoveAtStart;
        const int w   = ini.value(QStringLiteral("warnMinutes"), 2).toInt();
        m.warnMinutes = (w >= 1 && w <= 120) ? w : 2;
        ini.endGroup();
        out << m;
    }
    return out;
}

void MeetingStore::save(const QVector<Meeting>& meetings) const
{
    QSettings ini(m_path, QSettings::IniFormat);
    ini.setIniCodec("UTF-8");
    ini.clear();
    // Top-level key: QSettings would keep this exact string in its process-wide cache, so it must not be
    // a QStringLiteral (static data inside this DLL, gone after the plugin unloads). Keys inside groups
    // are concatenated with the group prefix and therefore always heap copies.
    ini.setValue(QString::fromLatin1("formatVersion"), 1);
    for (const Meeting& m : meetings) {
        ini.beginGroup(m.id);
        ini.setValue(QStringLiteral("name"), m.name);
        ini.setValue(QStringLiteral("enabled"), m.enabled);
        ini.setValue(QStringLiteral("serverName"), m.serverName);
        ini.setValue(QStringLiteral("serverUid"), m.serverUid);
        ini.setValue(QStringLiteral("host"), m.host);
        ini.setValue(QStringLiteral("port"), uint(m.port));
        ini.setValue(QStringLiteral("serverPassword"), m.serverPassword);
        ini.setValue(QStringLiteral("nickname"), m.nickname);
        ini.setValue(QStringLiteral("channelId"), m.channelId);
        ini.setValue(QStringLiteral("channelPath"), m.channelPath);
        ini.setValue(QStringLiteral("channelPassword"), m.channelPassword);
        ini.setValue(QStringLiteral("startDate"), m.schedule.startDate.toString(Qt::ISODate));
        ini.setValue(QStringLiteral("time"), m.schedule.time.toString(QStringLiteral("HH:mm:ss")));
        ini.setValue(QStringLiteral("timeZone"), QString::fromUtf8(m.schedule.timeZoneId));
        ini.setValue(QStringLiteral("repeat"), int(m.schedule.repeat));
        ini.setValue(QStringLiteral("interval"), m.schedule.interval);
        ini.setValue(QStringLiteral("weekdays"), uint(m.schedule.weekdays));
        ini.setValue(QStringLiteral("action"), int(m.action));
        ini.setValue(QStringLiteral("warnMinutes"), m.warnMinutes);
        ini.endGroup();
    }
    ini.sync();
}

} // namespace gf
