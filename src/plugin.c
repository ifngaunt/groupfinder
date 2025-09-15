/*
 * TeamSpeak 3 Groupfinder (cleaned)
 *
 * Keeps only what the TS3 client actually needs for:
 *  - loading the plugin
 *  - registering "/findgroup" command
 *  - caching server groups (via list events)
 *  - finding and printing clients in matching groups
 *
 * Notes on TS3 requirements (read this before editing):
 *  - REQUIRED entry points: ts3plugin_name, ts3plugin_version, ts3plugin_apiVersion,
 *    ts3plugin_author, ts3plugin_description, ts3plugin_setFunctionPointers,
 *    ts3plugin_init, ts3plugin_shutdown.
 *  - Using a chat command ("/findgroup") REQUIRES ts3plugin_registerPluginID and
 *    ts3plugin_commandKeyword. Do NOT remove those.
 *  - We request the server-group list on connection (onConnectStatusChangeEvent) and
 *    fill a small cache in onServerGroupListEvent / onServerGroupListFinishedEvent.
 *    The command depends on that cache. Keep those three callbacks.
 *  - All other demo callbacks, menu and hotkey scaffolding, and the info panel are
 *    removed for clarity.
 */

#if defined(WIN32) || defined(__WIN32__) || defined(_WIN32)
  #if defined(_MSC_VER)
    #pragma warning(disable : 4100)  /* MSVC: unreferenced formal parameter */
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
#define INFODATA_BUFSIZE 128
#define CHANNELINFO_BUFSIZE 512
enum { MENU_ID_CHANNEL_PULL_ALL = 1001 };

static struct PluginMenuItem* createMenuItem(enum PluginMenuType type, int id, const char* text, const char* icon){
    struct PluginMenuItem* m = (struct PluginMenuItem*)malloc(sizeof(struct PluginMenuItem));
    m->type = type; m->id = id;
    _strcpy(m->text, PLUGIN_MENU_BUFSZ, text);
    _strcpy(m->icon, PLUGIN_MENU_BUFSZ, icon ? icon : "");
    return m;
}

/* required when using menus */
void ts3plugin_freeMemory(void* p){ free(p); }


static struct TS3Functions ts3Functions;
static char* pluginID = NULL; /* set by ts3plugin_registerPluginID() */

#ifdef _WIN32
/* Convert wchar_t to UTF-8 (needed because ts3plugin_name returns UTF‑8) */
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

/* ------------------------------ Group cache ------------------------------ */
#define MAX_GROUPS 256

typedef struct {
    uint64 id;
    char   name[128];
} GroupEntry;

typedef struct {
    uint64 schid;          /* serverConnectionHandlerID this cache belongs to */
    GroupEntry items[MAX_GROUPS];
    size_t count;
    int ready;             /* set when finished list arrives */
} GroupCache;

static GroupCache g_cache = {0};

static void cache_reset(uint64 schid) {
    g_cache.schid = schid;
    g_cache.count = 0;
    g_cache.ready = 0;
}

static void cache_add(uint64 schid, uint64 sgid, const char* name) {
    if (g_cache.schid != schid) return;

    /* skip if we already have this group id */
    for (size_t i = 0; i < g_cache.count; ++i)
        if (g_cache.items[i].id == sgid) return;

    if (g_cache.count >= MAX_GROUPS) return;
    g_cache.items[g_cache.count].id = sgid;
    _strcpy(g_cache.items[g_cache.count].name, sizeof(g_cache.items[g_cache.count].name), name ? name : "");
    g_cache.count++;
}

/* Name lookup from the cache (exact id match) */
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
    const char* name;   /* token label */
    uint64 ids[16];     /* all matching group IDs for this token */
    int m;              /* count */
} GroupSet;

static int client_matches_sets(const char* csv, const GroupSet* sets, int sN) {
    for (int s = 0; s < sN; ++s) {           /* AND across tokens */
        int ok = 0;
        for (int j = 0; j < sets[s].m; ++j)  /* OR within token */
            if (csv_contains_id(csv, sets[s].ids[j])) { ok = 1; break; }
        if (!ok) return 0;
    }
    return 1;
}

/* split a string into argv respecting double quotes. Returns argc. Allocates argv+strings; caller frees. */
static int split_quoted_args(const char* s, char*** outv) {
    char**  argv = NULL;
    size_t  cap  = 0, argc = 0;
    const char* p = s;

    while (*p == ' ') ++p; /* skip leading spaces */

    while (*p) {
        if (argc == cap) { /* grow argv if needed */
            size_t ncap = cap ? cap * 2 : 4;
            char** n = (char**)realloc(argv, ncap * sizeof(char*));
            if (!n) break; /* OOM */
            argv = n; cap = ncap;
        }

        char buf[256]; size_t bi = 0; /* parse one token (quoted or bare) */
        if (*p == '"') {
            ++p;
            while (*p && *p != '"' && bi + 1 < sizeof(buf)) buf[bi++] = *p++;
            if (*p == '"') ++p; /* skip closing quote */
        } else {
            while (*p && *p != ' ' && bi + 1 < sizeof(buf)) buf[bi++] = *p++;
        }
        buf[bi] = '\0';

        if (bi) { /* store token if not empty */
            argv[argc] = (char*)malloc(bi + 1);
            if (!argv[argc]) break;
            memcpy(argv[argc], buf, bi + 1);
            ++argc;
        }
        while (*p == ' ') ++p; /* skip spaces between tokens */
    }

    *outv = argv;
    return (int)argc;
}

/* ------------------------------ Plugin entry points ------------------------------ */

const char* ts3plugin_name() {
#ifdef _WIN32
    static char* result = NULL; /* allocate once */
    if (!result) {
        const wchar_t* name = L"Groupfinder";
        if (wcharToUtf8(name, &result) == -1) result = "Groupfinder"; /* fallback */
    }
    return result;
#else
    return "Groupfinder";
#endif
}

const char* ts3plugin_version() { return "1.0.0"; }
int ts3plugin_apiVersion() { return PLUGIN_API_VERSION; }
const char* ts3plugin_author() { return "PhysicsGaunt"; }
const char* ts3plugin_description() { return "Find users by (server) group. Also, allows some extra options to pull efficiently."; }

void ts3plugin_setFunctionPointers(const struct TS3Functions funcs) { ts3Functions = funcs; }

int ts3plugin_init() {
    char appPath[PATH_BUFSIZE], resourcesPath[PATH_BUFSIZE], configPath[PATH_BUFSIZE], pluginPath[PATH_BUFSIZE];
    printf("PLUGIN: init\n");
    ts3Functions.getAppPath(appPath, PATH_BUFSIZE);
    ts3Functions.getResourcesPath(resourcesPath, PATH_BUFSIZE);
    ts3Functions.getConfigPath(configPath, PATH_BUFSIZE);
    ts3Functions.getPluginPath(pluginPath, PATH_BUFSIZE, pluginID);
    printf("PLUGIN: App path: %s\nResources path: %s\nConfig path: %s\nPlugin path: %s\n", appPath, resourcesPath, configPath, pluginPath);
    return 0; /* 0 = success */
}

void ts3plugin_shutdown() {
    printf("PLUGIN: shutdown\n");
    if (pluginID) { free(pluginID); pluginID = NULL; }
}

/* REQUIRED when using commands/hotkeys/menus: registers our pluginID */
void ts3plugin_registerPluginID(const char* id) {
    const size_t sz = strlen(id) + 1;
    pluginID = (char*)malloc(sz);
    _strcpy(pluginID, sz, id); /* id buffer is invalid after return */
    printf("PLUGIN: registerPluginID: %s\n", pluginID);
}

void ts3plugin_initMenus(struct PluginMenuItem*** menuItems, char** menuIcon){
    *menuIcon = NULL;
    *menuItems = (struct PluginMenuItem**)malloc(sizeof(struct PluginMenuItem*) * 2);
    (*menuItems)[0] = createMenuItem(PLUGIN_MENU_TYPE_CHANNEL, MENU_ID_CHANNEL_PULL_ALL, "Pull all users to current channel!", "icons/pull.png");
    (*menuItems)[1] = NULL;
}


/* Make our "/findgroup" command available */
const char* ts3plugin_commandKeyword() { return "findgroup"; }

/* On connect, request the server-group list so our cache is ready for commands */
void ts3plugin_onConnectStatusChangeEvent(uint64 schid, int newStatus, unsigned int errorNumber) {
    (void)errorNumber; /* unused */
    if (newStatus == STATUS_CONNECTION_ESTABLISHED) {
        cache_reset(schid);
        ts3Functions.requestServerGroupList(schid, NULL);
    }
}

/* Fill cache as TS3 streams the groups */
void ts3plugin_onServerGroupListEvent(uint64 schid, uint64 serverGroupID, const char* name, int type, int iconID, int saveDB) {
    (void)type; (void)iconID; (void)saveDB; /* not needed for this plugin */
    cache_add(schid, serverGroupID, name ? name : "");
}

/* Mark cache ready */
void ts3plugin_onServerGroupListFinishedEvent(uint64 schid) {
    if (g_cache.schid == schid) g_cache.ready = 1;
}

static void pull_all_from_channel(uint64 schid, uint64 srcChannelID){
    anyID myID; uint64 myChan = 0;
    if(ts3Functions.getClientID(schid, &myID) != ERROR_ok) return;
    if(ts3Functions.getChannelOfClient(schid, myID, &myChan) != ERROR_ok) return;
    if(!myChan || myChan == srcChannelID){
        ts3Functions.printMessageToCurrentTab("Nothing to pull (same channel).");
        return;
    }

    char path[CHANNELINFO_BUFSIZE]; char password[CHANNELINFO_BUFSIZE];
    memset(password, 0, sizeof(password));
    if(ts3Functions.getChannelConnectInfo(schid, myChan, path, password, CHANNELINFO_BUFSIZE) != 0){
        password[0] = '\0';
    }

    anyID* clids = NULL;
    if(ts3Functions.getChannelClientList(schid, srcChannelID, &clids) != ERROR_ok || !clids){
        ts3Functions.printMessageToCurrentTab("Could not read clients in source channel.");
        return;
    }

    unsigned moved = 0, failed = 0;
    for(size_t i=0; clids[i]; ++i){
        if(clids[i] == myID) continue;
        unsigned int e = ts3Functions.requestClientMove(schid, clids[i], myChan, password[0] ? password : "", NULL);
        if(e == ERROR_ok) ++moved; else ++failed;
    }
    ts3Functions.freeMemory(clids);

    char msg[128];
    snprintf(msg, sizeof(msg), "Pull complete: moved %u, failed %u.", moved, failed);
    ts3Functions.printMessageToCurrentTab(msg);
}


/* ------------------------------ Command implementation ------------------------------ */
/* /findgroup <group_id_or_name> [<group_id_or_name> ...] (names may be quoted) */
int ts3plugin_processCommand(uint64 schid, const char* command) {
    static const char* kUsage =
        "Usage: /findgroup <group_id_or_name> [<group_id_or_name> ...]\n"
        "Notes:\n"
        "  • Names may be quoted, matching is case-insensitive for names.\n"
        "  • Multiple tokens are ANDed; IDs within a token are ORed (for name matches).\n"
        "Examples:\n"
        "  /findgroup 62\n"
        "  /findgroup \"Head Administrator\" \"Rust\"";

    /* Parse args with quote support */
    char** argv = NULL; 
    int argc = split_quoted_args(command, &argv);

    /* TS3 does not invoke us for a bare '/findgroup', but allow explicit help. */
    if (argc == 1 && (
            icmp(argv[0], "help") == 0 ||
            icmp(argv[0], "-h") == 0 ||
            icmp(argv[0], "--help") == 0 ||
            icmp(argv[0], "?") == 0)) 
    {
        ts3Functions.printMessageToCurrentTab(kUsage);
        goto done;
    }

    if (argc <= 0) {
        /* Defensive: unreachable for bare '/findgroup' (TS3 intercepts), harmless otherwise. */
        goto done;
    }

    /* Build per-token ID sets */
    GroupSet sets[32]; 
    int sN = 0;

    for (int i = 0; i < argc && sN < 32; ++i) {
        const char* tok = argv[i];
        if (!tok || !*tok) continue;

        GroupSet gs = {0};
        char* endp = NULL; 
        long v = strtol(tok, &endp, 10);

        if (endp && *endp == '\0' && v > 0) {        /* numeric token -> single ID */
            gs.ids[gs.m++] = (uint64)v;
            const char* nm = resolve_group_name_by_id(schid, (uint64)v);
            gs.name = nm ? nm : tok;
        } else {                                      /* name token -> all matching IDs */
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
            gs.name = tok; /* show the requested token */
        }
        sets[sN++] = gs;
    }

    if (sN == 0) { 
        ts3Functions.printMessageToCurrentTab("No valid groups provided.\n\n" \
                                              "Tip: '/findgroup help' shows usage.");
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

    /* Header: Found N user(s) in group(s) ... */
    {
        char namesBuf[512] = {0};
        for (int s = 0; s < sN; ++s) {
            char idsPart[192] = {0};
            for (int j = 0; j < sets[s].m; ++j) {
                char tmp[32]; 
                snprintf(tmp, sizeof(tmp), "%s%llu", (j ? ", " : ""), (unsigned long long)sets[s].ids[j]);
                strncat(idsPart, tmp, sizeof(idsPart) - strlen(idsPart) - 1);
            }
            char piece[256]; 
            snprintf(piece, sizeof(piece), "%s\"%s\" (id %s)", (s ? ", " : ""), (sets[s].name ? sets[s].name : ""), idsPart);
            strncat(namesBuf, piece, sizeof(namesBuf) - strlen(namesBuf) - 1);
        }
        char head[512];
        snprintf(head, sizeof(head), "Found %llu user(s) in group%s %s:",
                 (unsigned long long)hits, (sN > 1 ? "s" : ""), namesBuf[0] ? namesBuf : "(unknown)");
        ts3Functions.printMessageToCurrentTab(head);
    }

    /* Print each match as a clickable link */
    for (size_t i = 0; clids[i]; ++i) {
        char* sgroups = NULL;
        if (ts3Functions.getClientVariableAsString(schid, clids[i], CLIENT_SERVERGROUPS, &sgroups) != ERROR_ok || !sgroups)
            continue;
        if (client_matches_sets(sgroups, sets, sN)) {
            char* uid  = NULL; 
            char* nick = NULL;
            if (ts3Functions.getClientVariableAsString(schid, clids[i], CLIENT_UNIQUE_IDENTIFIER, &uid)  == ERROR_ok &&
                ts3Functions.getClientVariableAsString(schid, clids[i], CLIENT_NICKNAME,          &nick) == ERROR_ok) {
                char line[512]; 
                snprintf(line, sizeof(line), "[URL=client://%u/%s]%s[/URL]", (unsigned)clids[i], uid, nick);
                ts3Functions.printMessageToCurrentTab(line);
            }
            if (uid)  ts3Functions.freeMemory(uid);
            if (nick) ts3Functions.freeMemory(nick);
        }
        ts3Functions.freeMemory(sgroups);
    }

    ts3Functions.freeMemory(clids);

done:
    if (argv) {
        for (int k = 0; k < argc; ++k) if (argv[k]) free(argv[k]);
        free(argv);
    }
    return 0;
}

void ts3plugin_onMenuItemEvent(uint64 schid, enum PluginMenuType type, int menuItemID, uint64 selectedItemID){
    if(type == PLUGIN_MENU_TYPE_CHANNEL && menuItemID == MENU_ID_CHANNEL_PULL_ALL){
        pull_all_from_channel(schid, selectedItemID);
    }
}
