/*
 * Connect-alarm settings, implemented in plugin.c and used by the Qt alarm window (src/query/).
 * One config per server tab; saved to "<TS3 config dir>/<server name>_alarm.cfg". Thread-safe.
 */
#ifndef GF_ALARM_H
#define GF_ALARM_H

#include "teamspeak/public_definitions.h"

#define GF_ALARM_QUERY_SIZE 512
#define GF_ALARM_SOUND_SIZE 512

typedef struct GfAlarmConfig {
    int  enabled;
    char query[GF_ALARM_QUERY_SIZE]; /* /findgroup tokens: "Head Administrator" 62 ... (all must match) */
    char sound[GF_ALARM_SOUND_SIZE]; /* WAV path; empty = the plugin's default.wav */
} GfAlarmConfig;

#ifdef __cplusplus
extern "C" {
#endif

void        gf_alarm_get(uint64 schid, GfAlarmConfig* out);
/* Stores, saves to the server's file and prints the new status in that server's tab. */
void        gf_alarm_set(uint64 schid, const GfAlarmConfig* cfg);
/* Plays soundPath (default sound when empty) on schid; returns 0 if the file doesn't exist. */
int         gf_alarm_play(uint64 schid, const char* soundPath);
const char* gf_alarm_default_sound(void);

#ifdef __cplusplus
}
#endif

#endif
