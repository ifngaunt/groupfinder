// C bridge (src/gf_query.h) -> QueryController on Qt's GUI thread.
#include "gf_query.h"

#include <atomic>

#include "common/guipost.h"
#include "common/ts3api.h"
#include "query/querycontroller.h"

namespace {
std::atomic<gf::QueryController*> g_query{nullptr};

template <class F>
void post(F fn)
{
    gf::postTo(g_query.load(), fn);
}
} // namespace

extern "C" {

void gf_query_init(const struct TS3Functions* funcs, const char* pluginID)
{
    if (g_query.load() || !QCoreApplication::instance() || !funcs)
        return;
    gf::ts3::setFunctions(funcs, QByteArray(pluginID ? pluginID : ""));
    auto* c = new gf::QueryController;
    gf::moveToGuiThread(c);
    g_query.store(c);
}

void gf_query_shutdown(void)
{
    if (gf::QueryController* c = g_query.exchange(nullptr))
        gf::deleteOnItsThread(c);  // windows must be gone before the DLL unloads
}

void gf_query_open_finder(void)
{
    post([](gf::QueryController* c) { c->openFinder(); });
}

void gf_query_on_group(uint64 schid, uint64 groupID, const char* name)
{
    const QString n = QString::fromUtf8(name ? name : "");
    post([schid, groupID, n](gf::QueryController* c) { c->onGroup(schid, groupID, n); });
}

void gf_query_on_groups_done(uint64 schid)
{
    post([schid](gf::QueryController* c) { c->onGroupsDone(schid); });
}

void gf_query_on_connect_status(uint64 schid, int newStatus)
{
    post([schid, newStatus](gf::QueryController* c) { c->onConnectStatus(schid, newStatus); });
}

} // extern "C"
