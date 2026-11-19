// Loads the real groupfinder.dll into a fake TeamSpeak client and drives it.
//
//   gf_harness.exe <groupfinder.dll> <mode> <outdir>
//
// Modes: lifecycle, execute, warn, thread, screenshots. Prints "HARNESS OK <mode>" on success,
// "HARNESS FAIL: ..." otherwise (exit 1). Everything is also written to <outdir>/harness-<mode>.log.
// Only the TS3 functions the plugin is expected to call are faked; any other call hits a null
// pointer and crashes the harness loudly.
#include <QAbstractButton>
#include <QApplication>
#include <QComboBox>
#include <QDialog>
#include <QSettings>
#include <QLineEdit>
#include <QPushButton>
#include <QTableWidget>
#include <QDateTime>
#include <QDir>
#include <QElapsedTimer>
#include <QFile>
#include <QTemporaryDir>
#include <QTimeZone>
#include <QThread>
#include <QTimer>
#include <QWidget>
#include <windows.h>

#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <thread>

#include "meetings/meeting.h"
#include "teamspeak/public_definitions.h"
#include "teamspeak/public_errors.h"
#include "teamspeak/public_rare_definitions.h"
#include "ts3_functions.h"

namespace {

// ------------------------------------------------------------------ logging / checks
QFile g_log;
bool  g_failOnThreadWarning = false;
bool  g_lastWindowClosed    = false;  // closing one of our windows must never look like "app's last window closed"

void logLine(const QString& s)
{
    const QByteArray b = s.toUtf8() + "\n";
    fwrite(b.constData(), 1, size_t(b.size()), stdout);
    fflush(stdout);
    if (g_log.isOpen()) {
        g_log.write(b);
        g_log.flush();
    }
}

[[noreturn]] void fail(const QString& why)
{
    logLine(QStringLiteral("HARNESS FAIL: ") + why);
    _exit(1);  // don't run destructors that may call into a half-unloaded plugin
}

#define CHECK(cond, msg)                                                                   \
    do {                                                                                   \
        if (!(cond))                                                                       \
            fail(QStringLiteral("%1 [%2:%3]").arg(QString(msg)).arg(__FILE__).arg(__LINE__)); \
    } while (0)

void qtMessages(QtMsgType type, const QMessageLogContext&, const QString& msg)
{
    logLine(QStringLiteral("[qt:%1] %2").arg(int(type)).arg(msg));
    if (g_failOnThreadWarning && msg.contains(QLatin1String("thread"), Qt::CaseInsensitive))
        fail(QStringLiteral("Qt thread warning: ") + msg);
    if (type == QtFatalMsg)
        fail(QStringLiteral("Qt fatal: ") + msg);
}

void pump(int ms)
{
    QElapsedTimer t;
    t.start();
    while (t.elapsed() < ms) {
        QCoreApplication::processEvents(QEventLoop::AllEvents, 20);
        QThread::msleep(5);
    }
}

QWidget* findVisible(const QString& objectName)
{
    for (QWidget* w : QApplication::topLevelWidgets())
        if (w->isVisible() && w->objectName() == objectName)
            return w;
    return nullptr;
}

// ------------------------------------------------------------------ fake TeamSpeak world
struct FakeServer {
    uint64         schid;
    int            status;
    QString        name, uid, host;
    unsigned short port;
    uint64         selfChannel;
};
struct FakeChannel {
    uint64  id, parent, order;
    QString name;
};
struct Move {
    uint64  schid;
    anyID   clid;
    uint64  channel;
    QString password;
};
struct Connect {
    int     tab;
    QString label, address, password, nickname, channel, channelPassword;
    uint64  schid;
};

const anyID              kSelf = 5;
const QVector<FakeChannel> kChannels = {
    {10, 0, 0, QStringLiteral("Lobby")},
    {11, 0, 10, QStringLiteral("Ops")},
    {12, 11, 0, QStringLiteral("Briefing")},
    {13, 0, 11, QStringLiteral("AFK")},
};
QVector<FakeServer> servers;
QVector<Move>       moves;
QVector<Connect>    connects;
QStringList         prints;
int                 sounds = 0, returnCodes = 0;
uint64              currentSchid = 1;
QByteArray          configDir;

FakeServer* server(uint64 schid)
{
    for (auto& s : servers)
        if (s.schid == schid)
            return &s;
    return nullptr;
}
bool connected(uint64 schid)
{
    const FakeServer* s = server(schid);
    return s && s->status == STATUS_CONNECTION_ESTABLISHED;
}
const FakeChannel* channel(uint64 id)
{
    for (const auto& c : kChannels)
        if (c.id == id)
            return &c;
    return nullptr;
}
char* dup(const QString& s)
{
    const QByteArray b = s.toUtf8();
    char* p = static_cast<char*>(malloc(size_t(b.size()) + 1));
    memcpy(p, b.constData(), size_t(b.size()) + 1);
    return p;
}
void copyOut(char* dst, size_t max, const QString& s)
{
    if (!dst || !max)
        return;
    const QByteArray b = s.toUtf8();
    strncpy(dst, b.constData(), max - 1);
    dst[max - 1] = '\0';
}
QString pathOf(uint64 id)
{
    QStringList parts;
    for (const FakeChannel* c = channel(id); c; c = c->parent ? channel(c->parent) : nullptr)
        parts.prepend(c->name);
    return parts.join(QLatin1Char('/'));
}

unsigned int f_freeMemory(void* p) { free(p); return ERROR_ok; }
unsigned int f_logMessage(const char* m, enum LogLevel, const char*, uint64) { logLine(QStringLiteral("[ts3log] ") + QString::fromUtf8(m)); return ERROR_ok; }
void         f_getConfigPath(char* path, size_t maxLen) { copyOut(path, maxLen, QString::fromUtf8(configDir)); }
unsigned int f_getServerConnectionHandlerList(uint64** r)
{
    *r = static_cast<uint64*>(malloc(sizeof(uint64) * size_t(servers.size() + 1)));
    for (int i = 0; i < servers.size(); ++i)
        (*r)[i] = servers[i].schid;
    (*r)[servers.size()] = 0;
    return ERROR_ok;
}
unsigned int f_getConnectionStatus(uint64 schid, int* r)
{
    const FakeServer* s = server(schid);
    *r = s ? s->status : STATUS_DISCONNECTED;
    return s ? ERROR_ok : 1u;
}
unsigned int f_getServerVariableAsString(uint64 schid, size_t flag, char** r)
{
    if (!connected(schid))
        return ERROR_not_connected;
    const FakeServer* s = server(schid);
    *r = dup(flag == VIRTUALSERVER_NAME ? s->name : flag == VIRTUALSERVER_UNIQUE_IDENTIFIER ? s->uid : QString());
    return ERROR_ok;
}
unsigned int f_requestServerVariables(uint64) { return ERROR_ok; }
unsigned int f_getServerConnectInfo(uint64 schid, char* host, unsigned short* port, char* password, size_t maxLen)
{
    if (!connected(schid))
        return 1;
    copyOut(host, maxLen, server(schid)->host);
    *port = server(schid)->port;
    copyOut(password, maxLen, QString());
    return 0;
}
unsigned int f_getClientSelfVariableAsString(uint64 schid, size_t flag, char** r)
{
    if (!connected(schid))
        return ERROR_not_connected;
    *r = dup(flag == CLIENT_NICKNAME ? QStringLiteral("HarnessUser") : QString());
    return ERROR_ok;
}
unsigned int f_getClientID(uint64 schid, anyID* r)
{
    *r = kSelf;
    return connected(schid) ? ERROR_ok : ERROR_not_connected;
}
unsigned int f_getChannelOfClient(uint64 schid, anyID clid, uint64* r)
{
    if (!connected(schid) || clid != kSelf)
        return ERROR_not_connected;
    *r = server(schid)->selfChannel;
    return ERROR_ok;
}
unsigned int f_getChannelList(uint64 schid, uint64** r)
{
    if (!connected(schid))
        return ERROR_not_connected;
    *r = static_cast<uint64*>(malloc(sizeof(uint64) * size_t(kChannels.size() + 1)));
    for (int i = 0; i < kChannels.size(); ++i)
        (*r)[i] = kChannels[i].id;
    (*r)[kChannels.size()] = 0;
    return ERROR_ok;
}
unsigned int f_getChannelVariableAsString(uint64 schid, uint64 id, size_t flag, char** r)
{
    const FakeChannel* c = channel(id);
    if (!connected(schid) || !c)
        return ERROR_channel_invalid_id;
    *r = dup(flag == CHANNEL_NAME ? c->name : QString());
    return ERROR_ok;
}
unsigned int f_getChannelVariableAsUInt64(uint64 schid, uint64 id, size_t flag, uint64* r)
{
    const FakeChannel* c = channel(id);
    if (!connected(schid) || !c)
        return ERROR_channel_invalid_id;
    *r = flag == CHANNEL_ORDER ? c->order : 0;
    return ERROR_ok;
}
unsigned int f_getParentChannelOfChannel(uint64 schid, uint64 id, uint64* r)
{
    const FakeChannel* c = channel(id);
    if (!connected(schid) || !c)
        return ERROR_channel_invalid_id;
    *r = c->parent;
    return ERROR_ok;
}
unsigned int f_getChannelConnectInfo(uint64 schid, uint64 id, char* path, char* password, size_t maxLen)
{
    if (!connected(schid) || !channel(id))
        return 1;
    copyOut(path, maxLen, pathOf(id));
    copyOut(password, maxLen, QString());
    return 0;
}
unsigned int f_getChannelIDFromChannelNames(uint64 schid, char** names, uint64* r)
{
    *r = 0;
    if (!connected(schid))
        return ERROR_not_connected;
    uint64 parent = 0;
    // Like the real client (verified from a TS3 crash dump): the array ends at an EMPTY STRING and every
    // entry is dereferenced until then — a NULL terminator crashes TeamSpeak with an access violation.
    for (int i = 0; names[i][0] != '\0'; ++i) {
        uint64 found = 0;
        for (const auto& c : kChannels)
            if (c.parent == parent && c.name == QString::fromUtf8(names[i]))
                found = c.id;
        if (!found)
            return ERROR_channel_invalid_id;
        parent = found;
    }
    *r = parent;
    return ERROR_ok;
}
unsigned int f_requestClientMove(uint64 schid, anyID clid, uint64 ch, const char* pw, const char*)
{
    moves << Move{schid, clid, ch, QString::fromUtf8(pw ? pw : "")};
    if (FakeServer* s = server(schid))
        s->selfChannel = ch;
    logLine(QStringLiteral("[ts3] move schid=%1 clid=%2 channel=%3").arg(schid).arg(clid).arg(ch));
    return ERROR_ok;
}
void f_createReturnCode(const char*, char* rc, size_t maxLen) { copyOut(rc, maxLen, QStringLiteral("rc%1").arg(++returnCodes)); }
unsigned int f_guiConnect(enum PluginConnectTab tab, const char* label, const char* address, const char* spw, const char* nick,
                          const char* chan, const char* cpw, const char*, const char*, const char*, const char*, const char*,
                          const char*, const char*, uint64* sch)
{
    uint64 id = 1;
    for (const auto& s : servers)
        id = std::max(id, s.schid + 1);
    const QString addr = QString::fromUtf8(address);
    servers << FakeServer{id, STATUS_CONNECTING, QString::fromUtf8(label), QStringLiteral("UID1"), addr.section(QLatin1Char(':'), 0, 0),
                          static_cast<unsigned short>(addr.section(QLatin1Char(':'), 1).toUInt()), 10};
    connects << Connect{int(tab), QString::fromUtf8(label), addr, QString::fromUtf8(spw), QString::fromUtf8(nick),
                        QString::fromUtf8(chan), QString::fromUtf8(cpw), id};
    *sch = id;
    logLine(QStringLiteral("[ts3] guiConnect %1 channel=%2 -> schid %3").arg(addr, QString::fromUtf8(chan)).arg(id));
    return ERROR_ok;
}
uint64 f_getCurrentServerConnectionHandlerID() { return currentSchid; }
void   f_printMessage(uint64 schid, const char* m, enum PluginMessageTarget)
{
    prints << QString::fromUtf8(m);
    logLine(QStringLiteral("[ts3 tab %1] %2").arg(schid).arg(QString::fromUtf8(m)));
}
void f_printMessageToCurrentTab(const char* m)
{
    prints << QString::fromUtf8(m);
    logLine(QStringLiteral("[ts3 current tab] ") + QString::fromUtf8(m));
}
unsigned int f_playWaveFile(uint64, const char* path)
{
    ++sounds;
    logLine(QStringLiteral("[ts3] playWaveFile ") + QString::fromUtf8(path));
    return ERROR_ok;
}
unsigned int f_requestServerGroupList(uint64, const char*) { return ERROR_ok; }
unsigned int f_getClientList(uint64, anyID** r)
{
    *r = static_cast<anyID*>(malloc(sizeof(anyID) * 2));
    (*r)[0] = kSelf;
    (*r)[1] = 0;
    return ERROR_ok;
}
unsigned int f_getClientVariableAsString(uint64, anyID, size_t flag, char** r)
{
    *r = dup(flag == CLIENT_SERVERGROUPS ? QStringLiteral("6") : flag == CLIENT_NICKNAME ? QStringLiteral("HarnessUser") : QStringLiteral("harnessUID="));
    return ERROR_ok;
}

TS3Functions fakeFunctions()
{
    TS3Functions f{};
    f.freeMemory                    = f_freeMemory;
    f.logMessage                    = f_logMessage;
    f.getConfigPath                 = f_getConfigPath;
    f.getServerConnectionHandlerList = f_getServerConnectionHandlerList;
    f.getConnectionStatus           = f_getConnectionStatus;
    f.getServerVariableAsString     = f_getServerVariableAsString;
    f.requestServerVariables        = f_requestServerVariables;
    f.getServerConnectInfo          = f_getServerConnectInfo;
    f.getClientSelfVariableAsString = f_getClientSelfVariableAsString;
    f.getClientID                   = f_getClientID;
    f.getChannelOfClient            = f_getChannelOfClient;
    f.getChannelList                = f_getChannelList;
    f.getChannelVariableAsString    = f_getChannelVariableAsString;
    f.getChannelVariableAsUInt64    = f_getChannelVariableAsUInt64;
    f.getParentChannelOfChannel     = f_getParentChannelOfChannel;
    f.getChannelConnectInfo         = f_getChannelConnectInfo;
    f.getChannelIDFromChannelNames  = f_getChannelIDFromChannelNames;
    f.requestClientMove             = f_requestClientMove;
    f.createReturnCode              = f_createReturnCode;
    f.guiConnect                    = f_guiConnect;
    f.getCurrentServerConnectionHandlerID = f_getCurrentServerConnectionHandlerID;
    f.printMessage                  = f_printMessage;
    f.printMessageToCurrentTab      = f_printMessageToCurrentTab;
    f.playWaveFile                  = f_playWaveFile;
    f.requestServerGroupList        = f_requestServerGroupList;
    f.getClientList                 = f_getClientList;
    f.getClientVariableAsString     = f_getClientVariableAsString;
    return f;
}

// ------------------------------------------------------------------ plugin loader
using SetFns       = void (*)(const struct TS3Functions);
using IntFn        = int (*)();
using VoidFn       = void (*)();
using RegId        = void (*)(const char*);
using InitMenus    = void (*)(struct PluginMenuItem***, char**);
using InitHotkeys  = void (*)(struct PluginHotkey***);
using FreeMem      = void (*)(void*);
using ProcCmd      = int (*)(uint64, const char*);
using Configure    = void (*)(void*, void*);
using OnHotkey     = void (*)(const char*);
using OnMenu       = void (*)(uint64, enum PluginMenuType, int, uint64);
using OnConnect    = void (*)(uint64, int, unsigned int);

struct Plugin {
    HMODULE h = nullptr;

    template <class T>
    T sym(const char* name, bool required = true)
    {
        auto p = reinterpret_cast<T>(GetProcAddress(h, name));
        if (!p && required)
            fail(QStringLiteral("missing export %1").arg(QString::fromLatin1(name)));
        return p;
    }
    void load(const QString& dll)
    {
        h = LoadLibraryW(reinterpret_cast<const wchar_t*>(dll.utf16()));
        CHECK(h, QStringLiteral("LoadLibrary failed, error %1").arg(GetLastError()));
        sym<SetFns>("ts3plugin_setFunctionPointers")(fakeFunctions());
        CHECK(sym<IntFn>("ts3plugin_init")() == 0, "ts3plugin_init failed");
        sym<RegId>("ts3plugin_registerPluginID")("harness.plugin.id");
        pump(300);
    }
    void hotkey(const char* keyword) { sym<OnHotkey>("ts3plugin_onHotkeyEvent")(keyword); }
    void unload()
    {
        sym<VoidFn>("ts3plugin_shutdown")();
        pump(50);
        for (QWidget* w : QApplication::allWidgets())
            CHECK(!w->objectName().startsWith(QLatin1String("gf")), "widget survived shutdown: " + w->objectName());
        FreeLibrary(h);
        h = nullptr;
        // The unload checks are only meaningful if the DLL is really gone from the process.
        CHECK(!GetModuleHandleW(L"groupfinder.dll"), "groupfinder.dll still mapped after FreeLibrary (something pinned it)");
        pump(100);
    }
};

void resetWorld()
{
    servers = {{1, STATUS_CONNECTION_ESTABLISHED, QStringLiteral("Test Server"), QStringLiteral("UID1"), QStringLiteral("ts.example.com"), 9987, 10}};
    moves.clear();
    connects.clear();
    prints.clear();
    sounds       = 0;
    currentSchid = 1;
}

QString iniPath() { return QDir(QString::fromUtf8(configDir)).filePath(QStringLiteral("groupfinder_meetings.ini")); }

gf::Meeting fixture(const QString& id, const QString& name, const QString& path, quint64 channelId)
{
    gf::Meeting m;
    m.id                  = id;
    m.name                = name;
    m.serverName          = QStringLiteral("Test Server");
    m.serverUid           = QStringLiteral("UID1");
    m.host                = QStringLiteral("ts.example.com");
    m.port                = 9987;
    m.nickname            = QStringLiteral("Gaunt");
    m.channelId           = channelId;
    m.channelPath         = path;
    m.schedule.startDate  = QDate(2020, 1, 1);
    m.schedule.time       = QDateTime::currentDateTimeUtc().addSecs(12 * 3600).time();  // far from "now"
    m.schedule.timeZoneId = "UTC";
    m.schedule.repeat     = gf::Repeat::Daily;
    return m;
}

void grab(QWidget* w, const QString& out, const QString& name)
{
    CHECK(w, "nothing to grab: " + name);
    const QString file = QDir(out).filePath(name + QStringLiteral(".png"));
    CHECK(w->grab().save(file), "could not save " + file);
    logLine(QStringLiteral("screenshot: ") + file);
}

template <class T>
T* child(QWidget* top, const char* name)
{
    T* c = top ? top->findChild<T*>(QString::fromLatin1(name)) : nullptr;
    CHECK(c, QStringLiteral("missing widget %1").arg(QString::fromLatin1(name)));
    return c;
}

// ------------------------------------------------------------------ modes
void modeLifecycle(const QString& dll)
{
    resetWorld();
    Plugin p;
    p.load(dll);

    struct PluginMenuItem** items = nullptr;
    char* icon = nullptr;
    p.sym<InitMenus>("ts3plugin_initMenus")(&items, &icon);
    auto freeMem = p.sym<FreeMem>("ts3plugin_freeMemory");
    int nMenus = 0;
    for (; items && items[nMenus]; ++nMenus)
        freeMem(items[nMenus]);
    freeMem(items);
    if (icon)
        freeMem(icon);
    logLine(QStringLiteral("menus: %1").arg(nMenus));

    int nHotkeys = -1;
    if (auto initHotkeys = p.sym<InitHotkeys>("ts3plugin_initHotkeys", false)) {
        struct PluginHotkey** hk = nullptr;
        initHotkeys(&hk);
        for (nHotkeys = 0; hk && hk[nHotkeys]; ++nHotkeys) {
            logLine(QStringLiteral("hotkey: %1 = %2").arg(QString::fromUtf8(hk[nHotkeys]->keyword), QString::fromUtf8(hk[nHotkeys]->description)));
            freeMem(hk[nHotkeys]);
        }
        freeMem(hk);
    }
    logLine(QStringLiteral("hotkeys: %1").arg(nHotkeys));
    CHECK(nMenus == 4, QStringLiteral("expected 4 menu items, got %1").arg(nMenus));
    CHECK(nHotkeys == 5, QStringLiteral("expected 5 hotkeys, got %1").arg(nHotkeys));

    prints.clear();
    p.hotkey("gf_alarm_toggle");
    CHECK(prints.join(QLatin1Char('\n')).contains(QLatin1String("[Alarm] ENABLED")), "gf_alarm_toggle did not enable the alarm");
    prints.clear();
    p.hotkey("gf_find_alarm");
    CHECK(prints.join(QLatin1Char('\n')).contains(QLatin1String("No criteria")), "gf_find_alarm without criteria gave no hint");

    CHECK(p.sym<ProcCmd>("ts3plugin_processCommand")(1, "help") == 0, "processCommand(help) not handled");
    CHECK(prints.join(QLatin1Char('\n')).contains(QLatin1String("Usage: /findgroup")), "help text not printed");

    p.sym<Configure>("ts3plugin_configure")(nullptr, nullptr);
    pump(500);
    CHECK(findVisible(QStringLiteral("gfSchedulerWindow")), "scheduler window not shown by ts3plugin_configure");
    p.unload();
}

void modeExecute(const QString& dll)
{
    const gf::Meeting op   = fixture(QStringLiteral("op"), QStringLiteral("Op"), QStringLiteral("Ops/Briefing"), 12);
    const gf::Meeting gone = fixture(QStringLiteral("gone"), QStringLiteral("Gone"), QStringLiteral("Nope"), 999);

    // A: connected to the meeting's server -> move self into the channel.
    resetWorld();
    gf::MeetingStore(iniPath()).save({op});
    {
        Plugin p;
        p.load(dll);
        p.hotkey("gf_join_next");
        pump(300);
        CHECK(moves.size() == 1, QStringLiteral("A: expected 1 move, got %1").arg(moves.size()));
        CHECK(moves[0].schid == 1 && moves[0].clid == kSelf && moves[0].channel == 12, "A: wrong move target");
        CHECK(prints.join(QLatin1Char('\n')).contains(QLatin1String("[Meetings]")), "A: no [Meetings] message");
        p.unload();
    }

    // B: channel no longer exists -> message, no move.
    resetWorld();
    gf::MeetingStore(iniPath()).save({gone});
    {
        Plugin p;
        p.load(dll);
        p.hotkey("gf_join_next");
        pump(300);
        CHECK(moves.isEmpty(), "B: moved although the channel does not exist");
        CHECK(prints.join(QLatin1Char('\n')).contains(QLatin1String("not found")), "B: no 'not found' message");
        p.unload();
    }

    // C: not connected to that server -> new tab via guiConnect, then verify channel after connect.
    resetWorld();
    servers[0].status = STATUS_DISCONNECTED;
    gf::MeetingStore(iniPath()).save({op});
    {
        Plugin p;
        p.load(dll);
        p.hotkey("gf_join_next");
        pump(300);
        CHECK(connects.size() == 1, QStringLiteral("C: expected 1 guiConnect, got %1").arg(connects.size()));
        const Connect c = connects[0];
        CHECK(c.tab == PLUGIN_CONNECT_TAB_NEW_IF_CURRENT_CONNECTED, "C: wrong tab mode");
        CHECK(c.address == QLatin1String("ts.example.com:9987"), "C: wrong address " + c.address);
        CHECK(c.channel == QLatin1String("Ops/Briefing"), "C: wrong channel " + c.channel);
        CHECK(c.nickname == QLatin1String("Gaunt"), "C: wrong nickname " + c.nickname);
        server(c.schid)->status = STATUS_CONNECTION_ESTABLISHED;  // TS3 put us in Lobby (10)
        p.sym<OnConnect>("ts3plugin_onConnectStatusChangeEvent")(c.schid, STATUS_CONNECTION_ESTABLISHED, 0);
        pump(300);
        CHECK(moves.size() == 1 && moves[0].schid == c.schid && moves[0].channel == 12, "C: no move after connecting");
        p.unload();
    }

    // D: "Join next" pressed twice while the connection is still being made -> only one new tab.
    resetWorld();
    servers[0].status = STATUS_DISCONNECTED;
    gf::MeetingStore(iniPath()).save({op});
    {
        Plugin p;
        p.load(dll);
        p.hotkey("gf_join_next");
        pump(200);
        p.hotkey("gf_join_next");
        pump(300);
        CHECK(connects.size() == 1, QStringLiteral("D: expected 1 guiConnect, got %1").arg(connects.size()));
        p.unload();
    }
}

void modeScreenshots(const QString& dll, const QString& out)
{
    resetWorld();
    gf::Meeting op = fixture(QStringLiteral("op"), QStringLiteral("Weekly op"), QStringLiteral("Ops/Briefing"), 12);
    op.schedule.repeat     = gf::Repeat::Weekly;
    op.schedule.weekdays   = 0x02 | 0x08;
    op.schedule.time       = QTime(20, 0);
    op.schedule.timeZoneId = "Europe/Berlin";
    gf::Meeting standup = fixture(QStringLiteral("standup"), QStringLiteral("Stand-up"), QStringLiteral("Lobby"), 10);
    standup.action      = gf::Action::WarnThenMove;
    standup.enabled     = false;
    gf::MeetingStore(iniPath()).save({op, standup});

    Plugin p;
    p.load(dll);
    auto onMenu = p.sym<OnMenu>("ts3plugin_onMenuItemEvent");
    onMenu(1, PLUGIN_MENU_TYPE_GLOBAL, 1003, 0);
    pump(400);
    QWidget* win = findVisible(QStringLiteral("gfSchedulerWindow"));
    CHECK(win, "scheduler not opened by Plugins menu item 1003");
    auto* table = child<QTableWidget>(win, "gfMeetingTable");
    CHECK(table->rowCount() == 2, QStringLiteral("expected 2 rows, got %1").arg(table->rowCount()));
    grab(win, out, QStringLiteral("scheduler"));

    onMenu(1, PLUGIN_MENU_TYPE_CHANNEL, 1004, 12);
    pump(400);
    QWidget* dlg = findVisible(QStringLiteral("gfMeetingDialog"));
    CHECK(dlg, "meeting dialog not opened by channel menu item 1004");
    CHECK(child<QComboBox>(dlg, "gfChannelCombo")->currentData().toULongLong() == 12, "channel 12 not preselected");
    CHECK(child<QComboBox>(dlg, "gfServerCombo")->currentText().contains(QLatin1String("Test Server")), "server not preselected");
    grab(dlg, out, QStringLiteral("meeting-dialog"));

    child<QLineEdit>(dlg, "gfNameEdit")->setText(QStringLiteral("Harness meeting"));
    child<QPushButton>(dlg, "gfSaveButton")->click();
    pump(300);
    CHECK(!findVisible(QStringLiteral("gfMeetingDialog")), "dialog still open after Save");
    CHECK(table->rowCount() == 3, "new meeting not listed");
    bool found = false;
    for (const gf::Meeting& m : gf::MeetingStore(iniPath()).load())
        if (m.name == QLatin1String("Harness meeting")) {
            found = true;
            CHECK(m.channelId == 12 && m.channelPath == QLatin1String("Ops/Briefing"), "saved meeting has wrong channel");
            CHECK(m.serverUid == QLatin1String("UID1") && m.host == QLatin1String("ts.example.com") && m.port == 9987, "saved meeting has wrong server");
            CHECK(gf::isValid(m.schedule), "saved meeting has an invalid schedule");
        }
    CHECK(found, "new meeting not saved to the INI");
    grab(win, out, QStringLiteral("scheduler-after-add"));
    p.unload();
}

gf::Meeting startingIn(const QString& id, int secs)
{
    gf::Meeting m       = fixture(id, id, QStringLiteral("Ops/Briefing"), 12);
    m.schedule.time     = QDateTime::currentDateTimeUtc().addSecs(secs).time();
    m.action            = gf::Action::WarnThenMove;
    m.warnMinutes       = 2;
    return m;
}

void modeWarn(const QString& dll, const QString& out)
{
    // 1: countdown runs out -> moved automatically, pop-up closes.
    resetWorld();
    gf::MeetingStore(iniPath()).save({startingIn(QStringLiteral("Auto"), 4)});
    {
        Plugin p;
        p.load(dll);
        pump(1500);
        QWidget* pop = findVisible(QStringLiteral("gfWarnPopup"));
        CHECK(pop, "warning pop-up not shown");
        CHECK(sounds >= 1, "no sound played with the warning");
        CHECK(moves.isEmpty(), "moved before the start time");
        grab(pop, out, QStringLiteral("warn-popup"));
        pump(4500);
        CHECK(moves.size() == 1 && moves[0].channel == 12, QStringLiteral("1: expected 1 move at start, got %1").arg(moves.size()));
        CHECK(!findVisible(QStringLiteral("gfWarnPopup")), "1: pop-up still open after start");
        p.unload();
    }
    // 2: "Don't move me" -> pop-up closes, no move at start.
    resetWorld();
    gf::MeetingStore(iniPath()).save({startingIn(QStringLiteral("Skip"), 4)});
    {
        Plugin p;
        p.load(dll);
        pump(1500);
        child<QPushButton>(findVisible(QStringLiteral("gfWarnPopup")), "gfDontMoveButton")->click();
        pump(300);
        CHECK(!findVisible(QStringLiteral("gfWarnPopup")), "2: pop-up not closed by Don't move me");
        pump(4500);
        CHECK(moves.isEmpty(), "2: moved although cancelled");
        p.unload();
    }
    // 3: "Move now" -> moved immediately, not again at start.
    resetWorld();
    gf::MeetingStore(iniPath()).save({startingIn(QStringLiteral("Now"), 4)});
    {
        Plugin p;
        p.load(dll);
        pump(1500);
        child<QPushButton>(findVisible(QStringLiteral("gfWarnPopup")), "gfMoveNowButton")->click();
        pump(300);
        CHECK(moves.size() == 1, "3: Move now did not move");
        pump(4500);
        CHECK(moves.size() == 1, QStringLiteral("3: moved %1 times").arg(moves.size()));
        p.unload();
    }
    // 4: "Join next" hotkey shortly before a move-at-start meeting -> not moved again at start,
    //    even after the user wandered off to another channel.
    resetWorld();
    gf::Meeting early = startingIn(QStringLiteral("Early"), 4);
    early.action      = gf::Action::MoveAtStart;
    gf::MeetingStore(iniPath()).save({early});
    {
        Plugin p;
        p.load(dll);
        p.hotkey("gf_join_next");
        pump(300);
        CHECK(moves.size() == 1, "4: join next did not move");
        server(1)->selfChannel = 13;  // user goes to AFK
        pump(4500);
        CHECK(moves.size() == 1, QStringLiteral("4: moved again at start after joining early (%1 moves)").arg(moves.size()));
        p.unload();
    }
}

void modeThread(const QString& dll)
{
    // TS3 may call hotkey/menu/connect/error callbacks from non-GUI threads.
    g_failOnThreadWarning = true;
    resetWorld();
    gf::MeetingStore(iniPath()).save({fixture(QStringLiteral("op"), QStringLiteral("Op"), QStringLiteral("Ops/Briefing"), 12)});
    Plugin p;
    p.load(dll);
    auto onMenu    = p.sym<OnMenu>("ts3plugin_onMenuItemEvent");
    auto onConnect = p.sym<OnConnect>("ts3plugin_onConnectStatusChangeEvent");
    auto onError   = p.sym<int (*)(uint64, const char*, unsigned int, const char*, const char*)>("ts3plugin_onServerErrorEvent");
    int errorResult = -1;
    std::thread worker([&] {
        p.hotkey("gf_open_meetings");
        onMenu(1, PLUGIN_MENU_TYPE_CHANNEL, 1004, 12);
        onConnect(1, STATUS_CONNECTION_ESTABLISHED, 0);
        errorResult = onError(1, "some error", 1, "not-ours", "");
    });
    worker.join();
    pump(600);
    CHECK(findVisible(QStringLiteral("gfSchedulerWindow")), "scheduler not shown after hotkey from worker thread");
    CHECK(findVisible(QStringLiteral("gfMeetingDialog")), "dialog not shown after channel menu from worker thread");
    CHECK(errorResult == 0, "foreign return code claimed by the plugin");
    p.unload();
}

void modeEdit(const QString& dll)
{
    // Edit + save an existing meeting through the UI, unload, then touch the same INI from the host.
    resetWorld();
    gf::Meeting m          = fixture(QStringLiteral("bogus"), QStringLiteral("Bogus zone"), QStringLiteral("Ops/Briefing"), 12);
    m.schedule.timeZoneId  = "Bogus/Zone";  // hand-edited / unknown zone: runs on the system zone
    gf::MeetingStore(iniPath()).save({m});
    {
        Plugin p;
        p.load(dll);
        p.sym<OnMenu>("ts3plugin_onMenuItemEvent")(1, PLUGIN_MENU_TYPE_GLOBAL, 1003, 0);
        pump(400);
        QWidget* win = findVisible(QStringLiteral("gfSchedulerWindow"));
        CHECK(win, "scheduler not shown");
        child<QTableWidget>(win, "gfMeetingTable")->selectRow(0);
        child<QPushButton>(win, "gfEditButton")->click();
        pump(400);
        QWidget* dlg = findVisible(QStringLiteral("gfMeetingDialog"));
        CHECK(dlg, "edit dialog not shown");
        const QByteArray shown = child<QComboBox>(dlg, "gfZoneCombo")->currentData().toByteArray();
        CHECK(shown == QTimeZone::systemTimeZoneId(),
              QStringLiteral("unknown zone shown as %1 instead of the system zone %2").arg(QString::fromUtf8(shown), QString::fromUtf8(QTimeZone::systemTimeZoneId())));
        child<QPushButton>(dlg, "gfSaveButton")->click();
        pump(300);
        child<QPushButton>(win, "gfCloseButton")->click();
        pump(300);
        p.unload();
    }
    // The plugin's QSettings writes must not leave pointers into the unloaded DLL in Qt's settings cache.
    QSettings ini(iniPath(), QSettings::IniFormat);
    const QStringList keys = ini.allKeys();
    logLine(QStringLiteral("keys after unload: %1").arg(keys.size()));
    const auto saved = gf::MeetingStore(iniPath()).load();
    CHECK(saved.size() == 1, "meeting lost after edit");
    CHECK(gf::scheduleZone(saved[0].schedule) == QTimeZone::systemTimeZone(), "saving without touching the zone changed it");
}

void modeModal(const QString& dll)
{
    // TS3 opens ts3plugin_configure from its (modal) Options dialog: the scheduler must not open blocked behind it.
    resetWorld();
    Plugin p;
    p.load(dll);
    {
        QDialog options;
        options.setObjectName(QStringLiteral("harnessOptions"));
        options.setAttribute(Qt::WA_QuitOnClose, false);
        options.setWindowModality(Qt::ApplicationModal);
        options.show();
        pump(100);
        p.sym<Configure>("ts3plugin_configure")(nullptr, &options);
        pump(400);
        QWidget* win = findVisible(QStringLiteral("gfSchedulerWindow"));
        CHECK(win, "scheduler not shown from configure");
        bool insideModal = false;
        for (QWidget* w = win; w; w = w->parentWidget())
            insideModal |= (w == &options);
        CHECK(insideModal, "scheduler opened outside the modal Options dialog (it would be unclickable)");
        options.hide();
    }
    pump(100);
    p.unload();
}

} // namespace

int main(int argc, char** argv)
{
    if (argc < 4) {
        fprintf(stderr, "usage: gf_harness <groupfinder.dll> <mode> <outdir>\n");
        return 2;
    }
    QApplication app(argc, argv);
    const QString dll  = QString::fromLocal8Bit(argv[1]);
    const QString mode = QString::fromLocal8Bit(argv[2]);
    const QString out  = QString::fromLocal8Bit(argv[3]);
    QDir().mkpath(out);
    g_log.setFileName(QDir(out).filePath(QStringLiteral("harness-%1.log").arg(mode)));
    g_log.open(QIODevice::WriteOnly | QIODevice::Truncate);
    qInstallMessageHandler(qtMessages);

    QTemporaryDir cfg;
    configDir = QDir::toNativeSeparators(cfg.path()).toUtf8();
    QApplication::setQuitOnLastWindowClosed(true);  // TS3 may run like this, e.g. while minimized to the tray
    QObject::connect(&app, &QGuiApplication::lastWindowClosed, [] { g_lastWindowClosed = true; });

    // Run inside app.exec() like a real application: some Qt behaviour (e.g. lastWindowClosed) only
    // happens while the event loop is running.
    QTimer::singleShot(0, [&] {
        if (mode == QLatin1String("lifecycle"))
            modeLifecycle(dll);
        else if (mode == QLatin1String("execute"))
            modeExecute(dll);
        else if (mode == QLatin1String("screenshots"))
            modeScreenshots(dll, out);
        else if (mode == QLatin1String("warn"))
            modeWarn(dll, out);
        else if (mode == QLatin1String("thread"))
            modeThread(dll);
        else if (mode == QLatin1String("edit"))
            modeEdit(dll);
        else if (mode == QLatin1String("modal"))
            modeModal(dll);
        else
            fail(QStringLiteral("unknown mode ") + mode);

        CHECK(!g_lastWindowClosed, "closing a plugin window emitted lastWindowClosed (would quit TeamSpeak when it is in the tray)");
        logLine(QStringLiteral("HARNESS OK ") + mode);
        QCoreApplication::exit(0);
    });
    app.exec();
    return 0;
}
