#include "query/querycontroller.h"

#include <QWidget>

#include "query/alarmwindow.h"
#include "query/finderwindow.h"
#include "teamspeak/public_definitions.h"

namespace gf {

QueryController::QueryController(QObject* parent) : QObject(parent) {}

QueryController::~QueryController() { m_windows.deleteAll(); }

void QueryController::onGroup(quint64 schid, quint64 groupId, const QString& name)
{
    m_incoming[schid].append({groupId, name});
}

void QueryController::onGroupsDone(quint64 schid)
{
    m_groups[schid] = mergeGroupsByName(m_incoming.take(schid));
    emit groupsChanged(schid);
}

void QueryController::onConnectStatus(quint64 schid, int status)
{
    if (status == STATUS_DISCONNECTED || status == STATUS_CONNECTION_ESTABLISHED) {
        // A (re)connected tab may be a different server: forget the old list. plugin.c requests a
        // fresh one on STATUS_CONNECTION_ESTABLISHED, and its events reach us too.
        m_groups.remove(schid);
        m_incoming.remove(schid);
        m_requested.remove(schid);
        if (status == STATUS_CONNECTION_ESTABLISHED)
            m_requested.insert(schid);
        emit groupsChanged(schid);
    }
}

void QueryController::ensureGroups(quint64 schid)
{
    if (!schid || m_groups.contains(schid) || m_requested.contains(schid))
        return;
    m_requested.insert(schid);
    ts3::requestServerGroups(schid);
}

QVector<OnlineMatch> QueryController::matching(quint64 schid, const QVector<GroupInfo>& required) const
{
    QVector<OnlineMatch> out;
    if (required.isEmpty())
        return out;
    QVector<QVector<quint64>> ids;
    for (const GroupInfo& g : required)
        ids << g.ids;
    QHash<quint64, QString> channelNames;
    for (const ts3::ClientEntry& c : ts3::clients(schid)) {
        if (!clientMatches(parseGroupCsv(c.groupsCsv), ids))
            continue;
        if (!channelNames.contains(c.channelId))
            channelNames.insert(c.channelId, ts3::channelName(schid, c.channelId));
        out << OnlineMatch{c, channelNames.value(c.channelId)};
    }
    std::sort(out.begin(), out.end(), [](const OnlineMatch& a, const OnlineMatch& b) {
        return a.client.nickname.compare(b.client.nickname, Qt::CaseInsensitive) < 0;
    });
    return out;
}

void QueryController::openFinder()
{
    if (!m_finder) {
        auto* w = new FinderWindow(this, dialogParent());
        m_windows.own(w);
        m_finder = w;
    }
    m_finder->show();
    m_finder->raise();
    m_finder->activateWindow();
}

void QueryController::openAlarm(quint64 schid, const QVector<GroupInfo>* preset)
{
    if (m_alarm)
        m_alarm->close();  // reopen fresh, for this server (and preset)
    // Not a child of Find Users: closing that window must not take this one (and its edits) with it.
    auto* w = new AlarmWindow(this, schid ? schid : ts3::currentServer(), preset, dialogParent());
    m_windows.own(w);
    m_alarm = w;
    w->show();
    w->raise();
    w->activateWindow();
}

} // namespace gf
