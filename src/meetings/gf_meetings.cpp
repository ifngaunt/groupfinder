// C bridge (src/gf_meetings.h) -> MeetingController on Qt's GUI thread.
#include "gf_meetings.h"

#include <QCoreApplication>
#include <QDir>
#include <QThread>
#include <atomic>
#include <cstring>

#include "meetings/meetingcontroller.h"
#include "meetings/ts3api.h"
#include "ts3_functions.h"

namespace {
std::atomic<gf::MeetingController*> g_controller{nullptr};

// Run fn(controller) on the controller's (GUI) thread, after the current TS3 callback returns.
template <class F>
void post(F fn)
{
    gf::MeetingController* c = g_controller.load();
    if (!c)
        return;
    QMetaObject::invokeMethod(c, [c, fn] { fn(c); }, Qt::QueuedConnection);
}
} // namespace

extern "C" {

void gf_meetings_init(const struct TS3Functions* funcs, const char* pluginID, const char* configDir, const char* soundPath)
{
    QCoreApplication* app = QCoreApplication::instance();
    if (g_controller.load() || !app || !funcs)
        return;
    gf::ts3::setFunctions(funcs, QByteArray(pluginID ? pluginID : ""));
    const QString ini = QDir(QString::fromUtf8(configDir ? configDir : ".")).filePath(QStringLiteral("groupfinder_meetings.ini"));
    auto* c = new gf::MeetingController(ini, QString::fromUtf8(soundPath ? soundPath : ""));
    if (c->thread() != app->thread())
        c->moveToThread(app->thread());
    g_controller.store(c);
    QMetaObject::invokeMethod(c, [c] { c->start(); }, Qt::QueuedConnection);
}

void gf_meetings_shutdown(void)
{
    gf::MeetingController* c = g_controller.exchange(nullptr);
    if (!c)
        return;
    QCoreApplication* app = QCoreApplication::instance();
    if (!app || QThread::currentThread() == c->thread())
        delete c;
    else  // windows must be destroyed on the GUI thread, and before this DLL is unloaded
        QMetaObject::invokeMethod(app, [c] { delete c; }, Qt::BlockingQueuedConnection);
}

void gf_meetings_open_scheduler(void)
{
    post([](gf::MeetingController* c) { c->openScheduler(); });
}

void gf_meetings_add_for_channel(uint64 schid, uint64 channelID)
{
    post([schid, channelID](gf::MeetingController* c) { c->addMeetingForChannel(schid, channelID); });
}

int gf_meetings_handle_hotkey(const char* keyword)
{
    if (!keyword)
        return 0;
    if (!strcmp(keyword, "gf_open_meetings"))
        post([](gf::MeetingController* c) { c->openScheduler(); });
    else if (!strcmp(keyword, "gf_join_next"))
        post([](gf::MeetingController* c) { c->joinNextNow(); });
    else if (!strcmp(keyword, "gf_cancel_move"))
        post([](gf::MeetingController* c) { c->cancelPending(); });
    else
        return 0;
    return 1;
}

void gf_meetings_on_connect_status(uint64 schid, int newStatus)
{
    post([schid, newStatus](gf::MeetingController* c) { c->onConnectStatus(schid, newStatus); });
}

int gf_meetings_on_server_error(uint64 schid, const char* errorMessage, unsigned int error, const char* returnCode)
{
    gf::MeetingController* c = g_controller.load();
    if (!c || !returnCode || !*returnCode)
        return 0;
    return c->onServerError(schid, QString::fromUtf8(errorMessage ? errorMessage : ""), error, QByteArray(returnCode)) ? 1 : 0;
}

} // extern "C"
