/*
 * C interface between plugin.c and the Qt "query" windows in src/query/ (Find Users by Group,
 * Connect Alarm Settings). Every function may be called from any thread; GUI work is queued onto
 * Qt's GUI thread.
 */
#ifndef GF_QUERY_H
#define GF_QUERY_H

#include "teamspeak/public_definitions.h"

struct TS3Functions;

#ifdef __cplusplus
extern "C" {
#endif

void gf_query_init(const struct TS3Functions* funcs, const char* pluginID);
void gf_query_shutdown(void); /* destroys the windows; call from ts3plugin_shutdown */

void gf_query_open_finder(void);
void gf_query_open_alarm(uint64 schid);

/* Forwarded TS3 events */
void gf_query_on_group(uint64 schid, uint64 groupID, const char* name);
void gf_query_on_groups_done(uint64 schid);
void gf_query_on_connect_status(uint64 schid, int newStatus);

#ifdef __cplusplus
}
#endif

#endif
