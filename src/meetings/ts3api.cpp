#include "meetings/ts3api.h"

#include <QApplication>
#include <QFile>
#include <QHash>
#include <QMainWindow>
#include <QWidget>

#include "teamspeak/public_definitions.h"
#include "teamspeak/public_errors.h"
#include "teamspeak/public_rare_definitions.h"
#include "ts3_functions.h"

namespace gf::ts3 {

namespace {
const TS3Functions* F = nullptr;
QByteArray          g_pluginId;
constexpr size_t    kBuf = 512;

QString take(char* s)
{
    if (!s)
        return QString();
    const QString r = QString::fromUtf8(s);
    F->freeMemory(s);
    return r;
}

QString serverString(quint64 schid, size_t flag)
{
    char* s = nullptr;
    return F->getServerVariableAsString(schid, flag, &s) == ERROR_ok ? take(s) : QString();
}

bool channelExists(quint64 schid, quint64 id)
{
    char* s = nullptr;
    if (F->getChannelVariableAsString(schid, id, CHANNEL_NAME, &s) != ERROR_ok)
        return false;
    F->freeMemory(s);
    return true;
}
} // namespace

void setFunctions(const TS3Functions* funcs, QByteArray pluginId)
{
    F          = funcs;
    g_pluginId = std::move(pluginId);
}

std::optional<ServerTab> serverTab(quint64 schid)
{
    int status = STATUS_DISCONNECTED;
    if (!F || F->getConnectionStatus(schid, &status) != ERROR_ok || status != STATUS_CONNECTION_ESTABLISHED)
        return std::nullopt;
    ServerTab t;
    t.schid = schid;
    t.name  = serverString(schid, VIRTUALSERVER_NAME);
    t.uid   = serverString(schid, VIRTUALSERVER_UNIQUE_IDENTIFIER);
    char host[kBuf] = {0}, password[kBuf] = {0};
    unsigned short port = 0;
    if (F->getServerConnectInfo(schid, host, &port, password, kBuf) == 0) {
        t.host     = QString::fromUtf8(host);
        t.port     = port;
        t.password = QString::fromUtf8(password);
    }
    char* nick = nullptr;
    if (F->getClientSelfVariableAsString(schid, CLIENT_NICKNAME, &nick) == ERROR_ok)
        t.nickname = take(nick);
    return t;
}

QVector<ServerTab> connectedServers()
{
    QVector<ServerTab> out;
    uint64* ids = nullptr;
    if (!F || F->getServerConnectionHandlerList(&ids) != ERROR_ok || !ids)
        return out;
    for (size_t i = 0; ids[i]; ++i)
        if (auto t = serverTab(ids[i]))
            out << *t;
    F->freeMemory(ids);
    return out;
}

QVector<ChannelEntry> channels(quint64 schid)
{
    struct Raw {
        quint64 id, parent, order;
        QString name, path;
    };
    QVector<ChannelEntry> out;
    uint64* ids = nullptr;
    if (!F || F->getChannelList(schid, &ids) != ERROR_ok || !ids)
        return out;

    QHash<quint64, QVector<Raw>> children;  // parent -> children (unordered)
    for (size_t i = 0; ids[i]; ++i) {
        Raw r{ids[i], 0, 0, {}, {}};
        char* name = nullptr;
        if (F->getChannelVariableAsString(schid, r.id, CHANNEL_NAME, &name) == ERROR_ok)
            r.name = take(name);
        uint64 v = 0;
        if (F->getParentChannelOfChannel(schid, r.id, &v) == ERROR_ok)
            r.parent = v;
        if (F->getChannelVariableAsUInt64(schid, r.id, CHANNEL_ORDER, &v) == ERROR_ok)
            r.order = v;
        char path[kBuf] = {0};
        if (F->getChannelConnectInfo(schid, r.id, path, nullptr, kBuf) == 0)
            r.path = QString::fromUtf8(path);
        children[r.parent] << r;
    }
    F->freeMemory(ids);

    // CHANNEL_ORDER is "the channel this one sorts below" (0 = first). Follow that chain per parent;
    // anything left over (inconsistent data) is appended in list order.
    auto walk = [&](auto&& self, quint64 parent, int depth) -> void {
        QVector<Raw> sibs = children.value(parent);
        quint64 prev = 0;
        while (!sibs.isEmpty()) {
            int idx = -1;
            for (int i = 0; i < sibs.size(); ++i)
                if (sibs[i].order == prev) { idx = i; break; }
            if (idx < 0)
                idx = 0;
            const Raw r = sibs.takeAt(idx);
            out << ChannelEntry{r.id, r.name, r.path.isEmpty() ? r.name : r.path, depth};
            self(self, r.id, depth + 1);
            prev = r.id;
        }
    };
    walk(walk, 0, 0);
    return out;
}

QString channelPassword(quint64 schid, quint64 channelId)
{
    char path[kBuf] = {0}, password[kBuf] = {0};
    if (!F || F->getChannelConnectInfo(schid, channelId, path, password, kBuf) != 0)
        return QString();
    return QString::fromUtf8(password);
}

quint64 findServer(const QString& uid, const QString& host, quint16 port)
{
    const auto tabs = connectedServers();
    if (!uid.isEmpty())
        for (const auto& t : tabs)
            if (t.uid == uid)
                return t.schid;
    for (const auto& t : tabs)
        if (!host.isEmpty() && t.host.compare(host, Qt::CaseInsensitive) == 0 && t.port == port)
            return t.schid;
    return 0;
}

quint64 resolveChannel(quint64 schid, const QString& path, quint64 fallbackId)
{
    if (!F)
        return 0;
    const QStringList parts = splitChannelPath(path);
    if (!parts.isEmpty()) {
        QVector<QByteArray> utf8;
        for (const QString& p : parts)
            utf8 << p.toUtf8();
        QVector<char*> names;
        for (QByteArray& b : utf8)
            names << b.data();
        names << nullptr;
        uint64 id = 0;
        if (F->getChannelIDFromChannelNames(schid, names.data(), &id) == ERROR_ok && id)
            return id;
    }
    return (fallbackId && channelExists(schid, fallbackId)) ? fallbackId : 0;
}

quint64 ownChannel(quint64 schid)
{
    anyID me = 0;
    uint64 ch = 0;
    if (!F || F->getClientID(schid, &me) != ERROR_ok || F->getChannelOfClient(schid, me, &ch) != ERROR_ok)
        return 0;
    return ch;
}

bool moveSelf(quint64 schid, quint64 channelId, const QString& password, QByteArray* returnCode)
{
    anyID me = 0;
    if (!F || F->getClientID(schid, &me) != ERROR_ok)
        return false;
    char rc[128] = {0};
    if (!g_pluginId.isEmpty())
        F->createReturnCode(g_pluginId.constData(), rc, sizeof(rc));
    const QByteArray pw = password.toUtf8();
    if (F->requestClientMove(schid, me, channelId, pw.constData(), rc[0] ? rc : nullptr) != ERROR_ok)
        return false;
    if (returnCode)
        *returnCode = QByteArray(rc);
    return true;
}

quint64 connectNewTab(const Meeting& m)
{
    if (!F)
        return 0;
    const QByteArray label   = m.serverName.toUtf8();
    const QByteArray address = QStringLiteral("%1:%2").arg(m.host).arg(m.port).toUtf8();
    const QByteArray spw     = m.serverPassword.toUtf8();
    const QByteArray nick    = m.nickname.toUtf8();
    const QByteArray channel = m.channelPath.toUtf8();
    const QByteArray cpw     = m.channelPassword.toUtf8();
    uint64 schid = 0;
    // Empty strings = TS3 defaults for profiles, identity, one-time key and phonetic name.
    const unsigned int err = F->guiConnect(PLUGIN_CONNECT_TAB_NEW_IF_CURRENT_CONNECTED, label.constData(), address.constData(),
                                           spw.constData(), nick.constData(), channel.constData(), cpw.constData(),
                                           "", "", "", "", "", "", "", &schid);
    return err == ERROR_ok ? schid : 0;
}

quint64 currentServer() { return F ? F->getCurrentServerConnectionHandlerID() : 0; }

void print(quint64 schid, const QString& text)
{
    if (!F)
        return;
    const QByteArray b = text.toUtf8();
    if (schid)
        F->printMessage(schid, b.constData(), PLUGIN_MESSAGE_TARGET_SERVER);
    else
        F->printMessageToCurrentTab(b.constData());
}

void playSound(quint64 schid, const QString& wavPath)
{
    if (F && schid && QFile::exists(wavPath))
        F->playWaveFile(schid, wavPath.toUtf8().constData());
}

QWidget* mainWindow()
{
    for (QWidget* w : QApplication::topLevelWidgets())
        if (qobject_cast<QMainWindow*>(w))
            return w;
    return nullptr;
}

} // namespace gf::ts3
