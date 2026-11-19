#pragma once
// Thin C++ wrapper over the TeamSpeak client function table. Handles ownership of strings/arrays
// returned by the client (released with freeMemory) and UTF-8 conversion.
#include <QByteArray>
#include <QString>
#include <QVector>
#include <optional>

#include "meetings/meeting.h"

struct TS3Functions;
class QWidget;

namespace gf::ts3 {

void setFunctions(const TS3Functions* funcs, QByteArray pluginId);

struct ServerTab {
    quint64 schid = 0;
    QString name, uid, host;
    quint16 port = 0;
    QString password, nickname;
};

struct ChannelEntry {
    quint64 id = 0;
    QString name, path;  // path as returned by getChannelConnectInfo ("Parent/Child")
    int     depth = 0;
};

struct ClientEntry {
    quint16 clid = 0;
    QString nickname, uid;
    QString groupsCsv;  // CLIENT_SERVERGROUPS, e.g. "6,13,62"
    quint64 channelId = 0;
};

QVector<ServerTab>       connectedServers();
QVector<ClientEntry>     clients(quint64 schid);  // everyone visible on that server
QString                  channelName(quint64 schid, quint64 channelId);
void                     requestServerGroups(quint64 schid);  // answer arrives as ts3plugin_onServerGroupList*Event
std::optional<ServerTab> serverTab(quint64 schid);  // only when fully connected
QVector<ChannelEntry>    channels(quint64 schid);   // tree order (parents before children, CHANNEL_ORDER)
QString                  channelPassword(quint64 schid, quint64 channelId);
quint64 findServer(const QString& uid, const QString& host, quint16 port);  // 0 = not connected
quint64 resolveChannel(quint64 schid, const QString& path, quint64 fallbackId);  // 0 = not found
quint64 ownChannel(quint64 schid);
// Requests moving ourselves; on success `returnCode` identifies the request in onServerErrorEvent.
bool    moveSelf(quint64 schid, quint64 channelId, const QString& password, QByteArray* returnCode);
quint64 connectNewTab(const Meeting& m);  // returns the new connection handler, 0 on failure
quint64 currentServer();
void    print(quint64 schid, const QString& text);  // schid 0 = current tab
void    playSound(quint64 schid, const QString& wavPath);
QWidget* mainWindow();  // TS3's main window, for parenting dialogs (nullptr in the test harness)

} // namespace gf::ts3
