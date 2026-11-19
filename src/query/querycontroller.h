#pragma once
// Owns the Find Users and Connect Alarm windows and each server's group list (built from TS3's
// server-group-list events). Lives on Qt's GUI thread; src/query/gf_query.cpp queues calls onto it.
#include <QHash>
#include <QObject>
#include <QPointer>
#include <QSet>
#include <QVector>

#include "common/ts3api.h"
#include "common/windowutil.h"
#include "query/groupquery.h"

class QWidget;

namespace gf {

struct OnlineMatch {
    ts3::ClientEntry client;
    QString          channel;
};

class QueryController : public QObject {
    Q_OBJECT
public:
    explicit QueryController(QObject* parent = nullptr);
    ~QueryController() override;

    // From TS3 (via the bridge): group list events and connection changes.
    void onGroup(quint64 schid, quint64 groupId, const QString& name);
    void onGroupsDone(quint64 schid);
    void onConnectStatus(quint64 schid, int status);

    bool               hasGroups(quint64 schid) const { return m_groups.contains(schid); }
    QVector<GroupInfo> groups(quint64 schid) const { return m_groups.value(schid); }
    void               ensureGroups(quint64 schid);  // asks TS3 for the list once if we don't have it
    // Online users who are in every one of `required` (each GroupInfo = any of its IDs).
    QVector<OnlineMatch> matching(quint64 schid, const QVector<GroupInfo>& required) const;

    void openFinder();
    void openAlarm(quint64 schid, const QVector<GroupInfo>* preset = nullptr);

signals:
    void groupsChanged(quint64 schid);

private:
    QHash<quint64, QVector<QPair<quint64, QString>>> m_incoming;
    QHash<quint64, QVector<GroupInfo>>               m_groups;
    QSet<quint64>                                    m_requested;
    QPointer<QWidget>                                m_finder;
    QPointer<QWidget>                                m_alarm;
    WindowOwner                                      m_windows;
};

} // namespace gf
