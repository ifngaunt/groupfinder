/*
 * C interface between plugin.c (all ts3plugin_* exports) and the C++/Qt meeting scheduler in
 * src/meetings/. Every function may be called from any thread; GUI work is queued onto Qt's GUI thread.
 */
#ifndef GF_MEETINGS_H
#define GF_MEETINGS_H

#include "teamspeak/public_definitions.h"

struct TS3Functions;

#ifdef __cplusplus
extern "C" {
#endif

/* Call once after ts3plugin_registerPluginID. `funcs` must outlive the scheduler. */
void gf_meetings_init(const struct TS3Functions* funcs, const char* pluginID, const char* configDir, const char* soundPath);
/* Destroys every window. Must be called from ts3plugin_shutdown before the DLL unloads. */
void gf_meetings_shutdown(void);

void gf_meetings_open_scheduler(void);
void gf_meetings_add_for_channel(uint64 schid, uint64 channelID);
/* Returns 1 if `keyword` is a meeting hotkey (gf_open_meetings, gf_join_next, gf_cancel_move). */
int  gf_meetings_handle_hotkey(const char* keyword);
void gf_meetings_on_connect_status(uint64 schid, int newStatus);
/* Returns 1 if `returnCode` belongs to a meeting move (the client should not print the error itself). */
int  gf_meetings_on_server_error(uint64 schid, const char* errorMessage, unsigned int error, const char* returnCode);

#ifdef __cplusplus
}
#endif

#endif
