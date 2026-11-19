// C bridge (src/gf_meetings.h) -> MeetingController on Qt's GUI thread.
#include "gf_meetings.h"

#include <QCoreApplication>
#include <QDir>
#include <QThread>
#include <atomic>
#include <cstring>

#include "common/guipost.h"
#include "meetings/meetingcontroller.h"
#include "common/ts3api.h"
#include "ts3_functions.h"

namespace {
std::atomic<gf::MeetingController*> g_controller{nullptr};

template <class F>
void post(F fn)
{
    gf::postTo(g_controller.load(), fn);
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
    gf::moveToGuiThread(c);
    g_controller.store(c);
    QMetaObject::invokeMethod(c, [c] { c->start(); }, Qt::QueuedConnection);
}

void gf_meetings_shutdown(void)
{
    if (gf::MeetingController* c = g_controller.exchange(nullptr))
        gf::deleteOnItsThread(c);  // windows must be gone before the DLL unloads
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
