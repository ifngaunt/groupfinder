/*
 * TeamSpeak 3 Group Finder plugin (cleaned) + Connect-Alarm via Menus & Persistence
 *
 * Alarm configuration uses the same token syntax and matching logic as /findgroup:
 *   - Tokens may be server-group IDs or names (names can be quoted)
 *   - AND across tokens, OR across IDs that match a single name token
 *   - /findgroup alarm set "Head Administrator" "Guest"  -> both groups required
 *   - /findgroup alarm set 62 13                          -> both IDs required
 */

#if defined(WIN32) || defined(__WIN32__) || defined(_WIN32)
  #if defined(_MSC_VER)
    #pragma warning(disable : 4100)
  #endif
  #include <windows.h>
#endif

#include <assert.h>
#include <ctype.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "teamspeak/public_definitions.h"
#include "teamspeak/public_errors.h"
#include "teamspeak/public_errors_rare.h"
#include "teamspeak/public_rare_definitions.h"
#include "ts3_functions.h"

#include "plugin.h"

/* ------------------------------ Small utilities ------------------------------ */
#ifdef _WIN32
#define _strcpy(dest, destSize, src) strcpy_s(dest, destSize, src)
#define snprintf sprintf_s
#else
#define _strcpy(dest, destSize, src)                \
    {                                              \
        strncpy(dest, src, destSize - 1);          \
        (dest)[destSize - 1] = '\0';               \
    }
#endif

#define PLUGIN_API_VERSION 26
#define PATH_BUFSIZE 512

static struct TS3Functions ts3Functions;
static char* pluginID = NULL; /* set by ts3plugin_registerPluginID() */

/* ------------------------------ Group cache ------------------------------ */
#define MAX_GROUPS 256

typedef struct {
    uint64 id;
    char   name[128];
} GroupEntry;

typedef struct {
    uint64 schid;
    GroupEntry items[MAX_GROUPS];
    size_t count;
    int ready;
} GroupCache;

static GroupCache g_cache = {0};

static void cache_reset(uint64 schid) { g_cache.schid = schid; g_cache.count = 0; g_cache.ready = 0; }

static void cache_add(uint64 schid, uint64 sgid, const char* name) {
    if (g_cache.schid != schid) return;
    for (size_t i = 0; i < g_cache.count; ++i)
        if (g_cache.items[i].id == sgid) return;
    if (g_cache.count >= MAX_GROUPS) return;
    g_cache.items[g_cache.count].id = sgid;
    _strcpy(g_cache.items[g_cache.count].name, sizeof(g_cache.items[g_cache.count].name), name ? name : "");
    g_cache.count++;
}

static const char* resolve_group_name_by_id(uint64 schid, uint64 sgid) {
    if (g_cache.schid != schid || !g_cache.ready) return NULL;
    for (size_t i = 0; i < g_cache.count; ++i)
        if (g_cache.items[i].id == sgid) return g_cache.items[i].name;
    return NULL;
}

/* case-insensitive strcmp */
static int icmp(const char* a, const char* b) {
    while (*a && *b) {
        int da = tolower((unsigned char)*a++), db = tolower((unsigned char)*b++);
        if (da != db) return da - db;
    }
    return (int)(unsigned char)*a - (int)(unsigned char)*b;
}

/* true if CSV of ints contains wanted id */
static int csv_contains_id(const char* csv, uint64 wanted) {
    const char* p = csv;
    while (*p) {
        char* end = NULL;
        long v = strtol(p, &end, 10);
        if (end == p) break;
        if ((uint64)v == wanted) return 1;
        p = (*end == ',') ? end + 1 : end;
    }
    return 0;
}

/* ------------------------------ Matching logic ------------------------------ */
typedef struct {
    const char* name;
    uint64 ids[16];
    int m;
} GroupSet;

static int client_matches_sets(const char* csv, const GroupSet* sets, int sN) {
    for (int s = 0; s < sN; ++s) {
        int ok = 0;
        for (int j = 0; j < sets[s].m; ++j)
            if (csv_contains_id(csv, sets[s].ids[j])) { ok = 1; break; }
        if (!ok) return 0;
    }
    return 1;
}

/* split a string into argv respecting double quotes. Returns argc. Allocates argv+strings; caller frees. */
static int split_quoted_args(const char* s, char*** outv) {
    char**  argv = NULL; size_t cap = 0, argc = 0; const char* p = s;
    while (*p == ' ') ++p;
    while (*p) {
        if (argc == cap) {
            size_t ncap = cap ? cap * 2 : 4;
            char** n = (char**)realloc(argv, ncap * sizeof(char*));
            if (!n) break;
            argv = n;
            cap = ncap;
        }
        char buf[256]; size_t bi = 0;
        if (*p == '"') {
            ++p;
            while (*p && *p != '"' && bi + 1 < sizeof(buf)) buf[bi++] = *p++;
            if (*p == '"') ++p;
        } else {
            while (*p && *p != ' ' && bi + 1 < sizeof(buf)) buf[bi++] = *p++;
        }
        buf[bi] = '\0';
        if (bi) {
            argv[argc] = (char*)malloc(bi + 1);
            if (!argv[argc]) break;
            memcpy(argv[argc], buf, bi + 1);
            ++argc;
        }
        while (*p == ' ') ++p;
    }
    *outv = argv;
    return (int)argc;
}

/* Build GroupSet[] from tokens using the same logic as /findgroup */
static int build_groupsets_from_tokens(uint64 schid, char** tokens, int tokc, GroupSet* sets_out, int max_sets) {
    int sN = 0;
    for (int i = 0; i < tokc && sN < max_sets; ++i) {
        const char* tok = tokens[i];
        if (!tok || !*tok) continue;
        GroupSet gs; memset(&gs, 0, sizeof(gs));
        char* endp = NULL; long v = strtol(tok, &endp, 10);
        if (endp && *endp=='\0' && v>0) {
            gs.ids[gs.m++] = (uint64)v;
            const char* nm = resolve_group_name_by_id(schid, (uint64)v);
            gs.name = nm ? nm : tok;
        } else {
            if (g_cache.schid != schid || !g_cache.ready) return -1;
            int added_exact = 0;
            for (size_t k=0; k<g_cache.count && gs.m<16; ++k)
                if (strcmp(g_cache.items[k].name, tok) == 0)
                    gs.ids[gs.m++] = g_cache.items[k].id, added_exact = 1;
            if (!added_exact)
                for (size_t k=0; k<g_cache.count && gs.m<16; ++k)
                    if (icmp(g_cache.items[k].name, tok) == 0)
                        gs.ids[gs.m++] = g_cache.items[k].id;
            if (gs.m == 0) return -2;
            gs.name = tok;
        }
        sets_out[sN++] = gs;
    }
    return sN;
}

/* ------------------------------ Alarm state + persistence ------------------------------ */
static int  g_alarm_enabled = 0;
static char g_alarm_query[512] = {0};
static char g_default_wav[PATH_BUFSIZE] = {0};

/* Make "<configPath>/<serverName>_alarm.cfg" (serverName sanitized) */
static void sanitize_filename(char* s) {
    /* replace characters that are illegal/problematic on Windows and most filesystems */
    for (char* p = s; *p; ++p) {
        switch (*p) {
            case '\\': case '/': case ':': case '*': case '?':
            case '"':  case '<': case '>': case '|': case '\r':
            case '\n': case '\t':
                *p = '_';
                break;
            default: break;
        }
    }
}

static void make_cfg_path_for_server(uint64 schid, char* out, size_t outsz) {
    char cfgDir[PATH_BUFSIZE] = {0};
    ts3Functions.getConfigPath(cfgDir, PATH_BUFSIZE);

    /* ask TS3 to refresh, then read the server name */
    ts3Functions.requestServerVariables(schid);

    char* sname = NULL;
    if (ts3Functions.getServerVariableAsString(schid, VIRTUALSERVER_NAME, &sname) == ERROR_ok && sname && *sname) {
        char nameBuf[PATH_BUFSIZE];
        _strcpy(nameBuf, sizeof(nameBuf), sname);
        ts3Functions.freeMemory(sname);
        sanitize_filename(nameBuf);
        snprintf(out, outsz, "%s/%s_alarm.cfg", cfgDir, nameBuf);
    } else {
        /* fallback if name unavailable */
        snprintf(out, outsz, "%s/groupfinder_alarm.cfg", cfgDir);
    }
}


/* Load per-server settings into globals */
static void alarm_load_for_server(uint64 schid) {
    char path[PATH_BUFSIZE] = {0};
    make_cfg_path_for_server(schid, path, sizeof(path));

    g_alarm_enabled = 0; g_alarm_query[0] = '\0';

    FILE* f = fopen(path, "r");
    if (!f) return;

    char line[600];
    while (fgets(line, sizeof(line), f)) {
        if (!strncmp(line, "enabled=", 8)) {
            int v=0; sscanf(line+8, "%d", &v); g_alarm_enabled = v?1:0;
        } else if (!strncmp(line, "query=", 6)) {
            size_t L = strlen(line+6);
            while (L && (line[6+L-1]=='\n' || line[6+L-1]=='\r')) --L;
            if (L >= sizeof(g_alarm_query)) L = sizeof(g_alarm_query)-1;
            memcpy(g_alarm_query, line+6, L); g_alarm_query[L] = '\0';
        }
    }
    fclose(f);
}

/* Save current globals to this server's file */
static void alarm_save_for_server(uint64 schid) {
    char path[PATH_BUFSIZE] = {0};
    make_cfg_path_for_server(schid, path, sizeof(path));
    FILE* f = fopen(path, "w");
    if (!f) return;
    fprintf(f, "enabled=%d\n", g_alarm_enabled ? 1 : 0);
    fprintf(f, "query=%s\n", g_alarm_query);
    fclose(f);
}

static void alarm_print_status(uint64 schid) {
    (void)schid;
    char buf[700];
    snprintf(buf, sizeof(buf), "[Alarm] %s  query: %s",
             g_alarm_enabled ? "ENABLED" : "DISABLED",
             g_alarm_query[0] ? g_alarm_query : "<not set>");
    ts3Functions.printMessageToCurrentTab(buf);
}

/* ------------------------------ Plugin entry points ------------------------------ */

#ifdef _WIN32
/* Convert wchar_t to UTF-8 (needed because ts3plugin_name returns UTF-8) */
static int wcharToUtf8(const wchar_t* str, char** result) {
    int outlen = WideCharToMultiByte(CP_UTF8, 0, str, -1, 0, 0, 0, 0);
    *result    = (char*)malloc(outlen);
    if (WideCharToMultiByte(CP_UTF8, 0, str, -1, *result, outlen, 0, 0) == 0) {
        *result = NULL;
        return -1;
    }
    return 0;
}
#endif

const char* ts3plugin_name() {
#ifdef _WIN32
    static char* result = NULL;
    if (!result) {
        const wchar_t* name = L"Group Finder Plugin";
        if (wcharToUtf8(name, &result) == -1) result = "Group Finder Plugin";
    }
    return result;
#else
    return "Group Finder Plugin";
#endif
}

const char* ts3plugin_version() { return "1.2.0"; }
int ts3plugin_apiVersion() { return PLUGIN_API_VERSION; }
const char* ts3plugin_author() { return "PhysicsGaunt"; }
const char* ts3plugin_description() { return "Find users by (server) group + connect-alarm using the same matcher."; }

void ts3plugin_setFunctionPointers(const struct TS3Functions funcs) { ts3Functions = funcs; }

int ts3plugin_init() {
    /* Paths depending on DLL/plugin location are resolved later in registerPluginID */
    return 0;
}

void ts3plugin_shutdown() {
    if (pluginID) { free(pluginID); pluginID = NULL; }
}

void ts3plugin_registerPluginID(const char* id) {
    const size_t sz = strlen(id) + 1;
    pluginID = (char*)malloc(sz);
    _strcpy(pluginID, sz, id);

#if defined(_WIN32)
    /* Derive asset dir from the DLL filename:
       .../TS3Client/plugins/<dllName>.dll  -> assets at .../TS3Client/plugins/<dllName>/sound/default.wav */
    char modPath[PATH_BUFSIZE] = {0};
    HMODULE hmod = NULL;
    if (GetModuleHandleExA(GET_MODULE_HANDLE_EX_FLAG_FROM_ADDRESS |
                           GET_MODULE_HANDLE_EX_FLAG_UNCHANGED_REFCOUNT,
                           (LPCSTR)&ts3plugin_registerPluginID, &hmod)) {
        if (GetModuleFileNameA(hmod, modPath, sizeof(modPath))) {
            char* lastSlash = strrchr(modPath, '\\'); if (!lastSlash) lastSlash = strrchr(modPath, '/');
            char dllDir[PATH_BUFSIZE] = {0};
            char dllName[PATH_BUFSIZE] = {0};
            if (lastSlash) {
                *lastSlash = '\0';
                _strcpy(dllDir, sizeof(dllDir), modPath);
                _strcpy(dllName, sizeof(dllName), lastSlash + 1);
            } else {
                _strcpy(dllDir, sizeof(dllDir), ".");
                _strcpy(dllName, sizeof(dllName), modPath);
            }
            char* dot = strrchr(dllName, '.'); if (dot) *dot = '\0';
            char assetDir[PATH_BUFSIZE] = {0};
            snprintf(assetDir, sizeof(assetDir), "%s/%s", dllDir, dllName);
            for (char* p = assetDir; *p; ++p) if (*p == '\\') *p = '/';
            snprintf(g_default_wav, sizeof(g_default_wav), "%s/sound/default.wav", assetDir);
        }
    }
#else
    g_default_wav[0] = '\0';
#endif

    if (!g_default_wav[0]) _strcpy(g_default_wav, sizeof(g_default_wav), "/sound/default.wav");
}

/* Make our "/findgroup" command available */
const char* ts3plugin_commandKeyword() { return "findgroup"; }

/* Load per-server state when connection becomes ready */
void ts3plugin_onConnectStatusChangeEvent(uint64 schid, int newStatus, unsigned int errorNumber) {
    (void)errorNumber;
    if (newStatus == STATUS_CONNECTION_ESTABLISHED) {
        cache_reset(schid);
        ts3Functions.requestServerGroupList(schid, NULL);

        /* Load per-server alarm state (groupfinder_alarm_<serverUID>.cfg) */
        alarm_load_for_server(schid);
        alarm_print_status(schid);
    }
}

/* Fill cache as TS3 streams the groups */
void ts3plugin_onServerGroupListEvent(uint64 schid, uint64 serverGroupID, const char* name, int type, int iconID, int saveDB) {
    (void)type; (void)iconID; (void)saveDB;
    cache_add(schid, serverGroupID, name ? name : "");
}

/* Mark cache ready */
void ts3plugin_onServerGroupListFinishedEvent(uint64 schid) {
    if (g_cache.schid == schid) g_cache.ready = 1;
}

/* ------------------------------ Menu scaffolding ------------------------------ */
enum { MENU_ID_GLOBAL_ALARM_TOGGLE = 1001, MENU_ID_GLOBAL_ALARM_SETQUERY = 1002 };

void ts3plugin_initMenus(struct PluginMenuItem*** menuItems, char** menuIcon) {
    (void)menuIcon;
    const size_t count = 2;
    struct PluginMenuItem** m = (struct PluginMenuItem**)malloc(sizeof(struct PluginMenuItem*) * (count + 1));

    m[0] = (struct PluginMenuItem*)malloc(sizeof(struct PluginMenuItem));
    m[0]->type = PLUGIN_MENU_TYPE_GLOBAL; m[0]->id = MENU_ID_GLOBAL_ALARM_TOGGLE;
    _strcpy(m[0]->text, PLUGIN_MENU_BUFSZ, "Connect Alarm: Toggle");
    m[0]->icon[0] = '\0';

    m[1] = (struct PluginMenuItem*)malloc(sizeof(struct PluginMenuItem));
    m[1]->type = PLUGIN_MENU_TYPE_GLOBAL; m[1]->id = MENU_ID_GLOBAL_ALARM_SETQUERY;
    _strcpy(m[1]->text, PLUGIN_MENU_BUFSZ, "Connect Alarm: Set Criteria...");
    m[1]->icon[0] = '\0';

    m[2] = NULL;
    *menuItems = m;
    *menuIcon = NULL;
}

void ts3plugin_onMenuItemEvent(uint64 schid, enum PluginMenuType type, int menuItemID, uint64 selectedItemID) {
    (void)selectedItemID;
    if (type != PLUGIN_MENU_TYPE_GLOBAL) return;
    switch (menuItemID) {
        case MENU_ID_GLOBAL_ALARM_TOGGLE:
            g_alarm_enabled = !g_alarm_enabled;
            alarm_save_for_server(schid);
            alarm_print_status(schid);
            break;
        case MENU_ID_GLOBAL_ALARM_SETQUERY:
            ts3Functions.printMessageToCurrentTab("[Alarm] Use: /findgroup alarm set <criteria tokens...>   e.g. /findgroup alarm set \"Head Administrator\" Guest");
            ts3Functions.printMessageToCurrentTab("[Alarm] Or clear with: /findgroup alarm clear");
            alarm_print_status(schid);
            break;
        default: break;
    }
}

/* ------------------------------ Connect detection + alarm ------------------------------ */
void ts3plugin_onClientMoveEvent(uint64 schid, anyID clid, uint64 oldChannelID, uint64 newChannelID, int visibility, const char* moveMessage) {
    (void)visibility; (void)moveMessage;
    if (!g_alarm_enabled || !g_alarm_query[0]) return;
    if (oldChannelID != 0 || newChannelID == 0) return; /* only initial connect */

    /* Build GroupSet[] from stored query */
    char** toks = NULL; int tokc = split_quoted_args(g_alarm_query, &toks);
    if (tokc <= 0) { if (toks) free(toks); return; }

    GroupSet sets[32]; int sN = build_groupsets_from_tokens(schid, toks, tokc, sets, 32);
    for (int i=0;i<tokc;++i){ if(toks[i]) free(toks[i]); } if (toks) free(toks);
    if (sN < 0) return;

    char* sgroups = NULL;
    if (ts3Functions.getClientVariableAsString(schid, clid, CLIENT_SERVERGROUPS, &sgroups) != ERROR_ok || !sgroups) return;
    int hit = client_matches_sets(sgroups, sets, sN);
    ts3Functions.freeMemory(sgroups);
    if (!hit) return;

    /* Print clickable client link */
    {
        char* uid  = NULL;
        char* nick = NULL;
        if (ts3Functions.getClientVariableAsString(schid, clid, CLIENT_UNIQUE_IDENTIFIER, &uid)  == ERROR_ok &&
            ts3Functions.getClientVariableAsString(schid, clid, CLIENT_NICKNAME,          &nick) == ERROR_ok) {
            char line[512];
            snprintf(line, sizeof(line),
                    "[Alarm] Match: [URL=client://%u/%s]%s[/URL] — playing sound...",
                    (unsigned)clid, uid, nick);
            ts3Functions.printMessageToCurrentTab(line);
        } else {
            ts3Functions.printMessageToCurrentTab("[Alarm] Match detected, playing sound...");
        }
        if (uid)  ts3Functions.freeMemory(uid);
        if (nick) ts3Functions.freeMemory(nick);
    }


    FILE* f = fopen(g_default_wav, "rb");
    if (!f) {
        char msg[PATH_BUFSIZE + 64];
        snprintf(msg, sizeof(msg), "[Alarm] WAV not found: %s", g_default_wav);
        ts3Functions.printMessageToCurrentTab(msg);
        return;
    }
    fclose(f);

    ts3Functions.playWaveFile(schid, g_default_wav);
}

/* ------------------------------ Command implementation ------------------------------ */
/* /findgroup <group_id_or_name> [...]  |  /findgroup alarm on|off|status|set <tokens...>|clear */
int ts3plugin_processCommand(uint64 schid, const char* command) {
    static const char* kUsage =
        "Usage: /findgroup <group_id_or_name> [<group_id_or_name> ...]\n"
        "       /findgroup alarm on|off|status|set <criteria tokens...>|clear\n"
        "Notes:\n"
        "  • Names may be quoted, matching is case-insensitive for names.\n"
        "  • Multiple tokens are ANDed; IDs within a token are ORed (for name matches).\n"
        "Examples:\n"
        "  /findgroup 62\n"
        "  /findgroup \"Head Administrator\" \"Rust\"\n"
        "  /findgroup alarm set 62 13\n"
        "  /findgroup alarm set \"Head Administrator\" Guest\n";

    char** argv = NULL; 
    int argc = split_quoted_args(command, &argv);
    if (argc <= 0) goto done;

    /* Handle alarm subcommand */
    if (icmp(argv[0], "alarm") == 0) {
        if (argc >= 2 && icmp(argv[1], "on") == 0)  { g_alarm_enabled = 1; alarm_save_for_server(schid); alarm_print_status(schid); goto done; }
        if (argc >= 2 && icmp(argv[1], "off") == 0) { g_alarm_enabled = 0; alarm_save_for_server(schid); alarm_print_status(schid); goto done; }
        if (argc >= 2 && icmp(argv[1], "status") == 0){ alarm_print_status(schid); goto done; }
        if (argc >= 2 && icmp(argv[1], "clear") == 0) { g_alarm_query[0] = '\0'; alarm_save_for_server(schid); alarm_print_status(schid); goto done; }
        if (argc >= 3 && icmp(argv[1], "set") == 0) {
            g_alarm_query[0] = '\0';
            for (int i=2; i<argc; ++i) {
                const char* tok = argv[i]; if (!tok) continue;
                int need_quote = strchr(tok, ' ') != NULL;
                size_t cur = strlen(g_alarm_query);
                if (cur + strlen(tok) + 4 >= sizeof(g_alarm_query)) break;
                if (cur) strncat(g_alarm_query, " ", sizeof(g_alarm_query)-cur-1);
                if (need_quote) {
                    strncat(g_alarm_query, "\"", sizeof(g_alarm_query)-strlen(g_alarm_query)-1);
                    strncat(g_alarm_query, tok, sizeof(g_alarm_query)-strlen(g_alarm_query)-1);
                    strncat(g_alarm_query, "\"", sizeof(g_alarm_query)-strlen(g_alarm_query)-1);
                } else {
                    strncat(g_alarm_query, tok, sizeof(g_alarm_query)-strlen(g_alarm_query)-1);
                }
            }
            alarm_save_for_server(schid);
            alarm_print_status(schid);
            goto done;
        }
        ts3Functions.printMessageToCurrentTab(kUsage);
        goto done;
    }

    /* Explicit help */
    if (argc == 1 && (
            icmp(argv[0], "help") == 0 ||
            icmp(argv[0], "-h") == 0 ||
            icmp(argv[0], "--help") == 0 ||
            icmp(argv[0], "?") == 0))
    {
        ts3Functions.printMessageToCurrentTab(kUsage);
        goto done;
    }

    /* Build per-token ID sets */
    GroupSet sets[32]; int sN = 0;
    for (int i = 0; i < argc && sN < 32; ++i) {
        const char* tok = argv[i];
        if (!tok || !*tok) continue;
        GroupSet gs; memset(&gs, 0, sizeof(gs));
        char* endp = NULL; long v = strtol(tok, &endp, 10);

        if (endp && *endp == '\0' && v > 0) {
            gs.ids[gs.m++] = (uint64)v;
            const char* nm = resolve_group_name_by_id(schid, (uint64)v);
            gs.name = nm ? nm : tok;
        } else {
            if (g_cache.schid != schid || !g_cache.ready) {
                ts3Functions.printMessageToCurrentTab("Group list not ready yet. Try again in a moment.");
                goto done;
            }
            int added_exact = 0;
            for (size_t k = 0; k < g_cache.count && gs.m < 16; ++k)
                if (strcmp(g_cache.items[k].name, tok) == 0)
                    gs.ids[gs.m++] = g_cache.items[k].id, added_exact = 1;
            if (!added_exact)
                for (size_t k = 0; k < g_cache.count && gs.m < 16; ++k)
                    if (icmp(g_cache.items[k].name, tok) == 0)
                        gs.ids[gs.m++] = g_cache.items[k].id;

            if (gs.m == 0) {
                char msg[256];
                snprintf(msg, sizeof(msg), "No matching server-group(s) found for \"%s\".", tok);
                ts3Functions.printMessageToCurrentTab(msg);
                goto done;
            }
            gs.name = tok;
        }
        sets[sN++] = gs;
    }

    if (sN == 0) {
        ts3Functions.printMessageToCurrentTab("No valid groups provided.\n\nTip: '/findgroup help' shows usage.");
        goto done;
    }

    /* Get clients */
    anyID* clids = NULL;
    if (ts3Functions.getClientList(schid, &clids) != ERROR_ok || !clids) {
        ts3Functions.logMessage("Could not get client list", LogLevel_ERROR, "Plugin", schid);
        goto done;
    }

    /* Count matches */
    size_t hits = 0;
    for (size_t i = 0; clids[i]; ++i) {
        char* sgroups = NULL;
        if (ts3Functions.getClientVariableAsString(schid, clids[i], CLIENT_SERVERGROUPS, &sgroups) != ERROR_ok || !sgroups)
            continue;
        if (client_matches_sets(sgroups, sets, sN)) ++hits;
        ts3Functions.freeMemory(sgroups);
    }

    /* Header + list */
    {
        char namesBuf[512] = {0};
        for (int s = 0; s < sN; ++s) {
            char idsPart[192] = {0};
            for (int j = 0; j < sets[s].m; ++j) {
                char tmp[32]; snprintf(tmp, sizeof(tmp), "%s%llu", (j ? ", " : ""), (unsigned long long)sets[s].ids[j]);
                strncat(idsPart, tmp, sizeof(idsPart) - strlen(idsPart) - 1);
            }
            char piece[256]; snprintf(piece, sizeof(piece), "%s\"%s\" (id %s)", (s ? ", " : ""), (sets[s].name ? sets[s].name : ""), idsPart);
            strncat(namesBuf, piece, sizeof(namesBuf) - strlen(namesBuf) - 1);
        }
        char head[512];
        snprintf(head, sizeof(head), "Found %llu user(s) in group%s %s:",
                 (unsigned long long)hits, (sN > 1 ? "s" : ""), namesBuf[0] ? namesBuf : "(unknown)");
        ts3Functions.printMessageToCurrentTab(head);
    }

    for (size_t i = 0; clids[i]; ++i) {
        char* sgroups = NULL;
        if (ts3Functions.getClientVariableAsString(schid, clids[i], CLIENT_SERVERGROUPS, &sgroups) != ERROR_ok || !sgroups)
            continue;
        if (client_matches_sets(sgroups, sets, sN)) {
            char* uid  = NULL; 
            char* nick = NULL;
            if (ts3Functions.getClientVariableAsString(schid, clids[i], CLIENT_UNIQUE_IDENTIFIER, &uid)  == ERROR_ok &&
                ts3Functions.getClientVariableAsString(schid, clids[i], CLIENT_NICKNAME,          &nick) == ERROR_ok) {
                char line[512]; snprintf(line, sizeof(line), "[URL=client://%u/%s]%s[/URL]", (unsigned)clids[i], uid, nick);
                ts3Functions.printMessageToCurrentTab(line);
            }
            if (uid)  ts3Functions.freeMemory(uid);
            if (nick) ts3Functions.freeMemory(nick);
        }
        ts3Functions.freeMemory(sgroups);
    }

    ts3Functions.freeMemory(clids);

 done:
    if (argv) { for (int k = 0; k < argc; ++k) if (argv[k]) free(argv[k]); free(argv); }
    return 0;
}
