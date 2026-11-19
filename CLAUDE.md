# groupfinder — TeamSpeak 3 client plugin

Native TS3 client plugin (plugin API **26**, Windows x64). Author: PhysicsGaunt. Features: Find Users by Group
(window + `/findgroup`), per-server connect alarm (window: groups, sound, preview), meeting scheduler (auto-move or
connect-in-new-tab at meeting time), plugin hotkeys. All Qt windows live in TS3's own Qt.

Reference SDK is cloned alongside at `../ts3client-pluginsdk` (upstream `teamspeak/ts3client-pluginsdk`).
`include/` and `src/plugin.h` here are **byte-identical** to the SDK — do not edit them; update by
copying from the SDK when bumping the API version.

## Build (MSVC + Qt, driven from WSL)

TS3 ships **Qt 5.15.2 built with MSVC 2019 x64** (`Qt5Core/Gui/Widgets.dll` in the TS3 install dir). The
plugin links against those DLLs, so it must be built with MSVC (MinGW C++ can't link MSVC-built Qt) in
**Release** (Debug would bind to `Qt5Cored.dll`). Never ship Qt DLLs in the package.

Toolchain on this machine:
- Visual Studio Build Tools 2022 (MSVC 14.44, ABI-compatible with 2019) incl. CMake + Ninja.
- Qt dev files: `%USERPROFILE%\Qt\5.15.2\msvc2019_64` (qtbase only), installed without admin via
  `~/.venvs/aqt/bin/aqt install-qt windows desktop 5.15.2 win64_msvc2019_64 --archives qtbase --outputdir "$(wslpath "$(cmd.exe /c echo %USERPROFILE% | tr -d '\r')")/Qt"`.

```sh
scripts/build.sh build      # -> dist/groupfinder.dll, prints exports + checks DLL imports
scripts/build.sh test       # + unit tests (QtTest)
scripts/build.sh harness [modes]   # + plugin harness: lifecycle execute warn thread screenshots edit modal alarm query limits unicode
scripts/build.sh all        # build + test + every harness mode
scripts/build.sh package    # -> dist/groupfinder-<version>.ts3_plugin
```

How the script works: mirrors the repo to `%LOCALAPPDATA%\groupfinder-build\src` (MSVC/Ninja are unreliable
on `\\wsl$` paths), writes a `run.bat` (vcvars64 + Qt on PATH) and runs it with `cmd.exe`. Output from Windows
processes is collected via files (QtTest stdout doesn't reach WSL): unit-test results in `testout/`, harness
logs + screenshots in `shots/` (copied to `dist/shots/`). cmd gotcha: always `set "X=Y"` (quoted) — an
unquoted `set X=Y || ...` keeps a trailing space. Override paths with `GF_QT_DIR` / `GF_BUILD_ROOT`.

The import allowlist (KERNEL32, USER32, Qt5Core/Gui/Widgets, VCRUNTIME140(_1), MSVCP140, api-ms-win-crt-*)
is enforced by `build.sh`; `ts3client_win64.exe` itself imports VCRUNTIME140_1 and MSVCP140, so those are
always present. Avoid `std::function`/iostreams etc. in plugin code to keep MSVCP140 out anyway.

Version: single source `project(groupfinder VERSION x.y.z)` in `CMakeLists.txt` → `GF_VERSION` define and
`Version =` in the packaged `package.ini` (rewritten at package time).

### Packaging (.ts3_plugin)

Zip with `package.ini` + `plugins/` at the root:
```
package.ini                                  (from groupfinder/package.ini, Platforms = win64)
plugins/groupfinder.dll
plugins/groupfinder/sound/default.wav        (asset dir name == DLL basename)
```

## Architecture

`src/plugin.c` (C) holds **every** `ts3plugin_*` export and all `/findgroup` + alarm logic (per-server alarm
slots and per-server group caches, both keyed by schid). Qt code: `src/meetings/` (scheduler, bridge
`src/gf_meetings.h`, kept separable for a later split), `src/query/` (Find Users + Connect Alarm windows, bridge
`src/gf_query.h`; reads/writes alarm settings through `src/gf_alarm.h`, implemented in plugin.c), and
`src/common/` (ts3api wrapper, `windowutil` = dialogParent()/WindowOwner, `guipost.h` = GUI-thread posting).

| File | Role |
|---|---|
| `src/plugin.c` | exports; finder (`split_quoted_args`, `build_groupsets_from_tokens`, `client_matches_sets`); per-server alarm + group caches; menus 1001–1005; hotkeys table `kHotkeys`; forwards to both bridges |
| `src/gf_meetings.h` / `meetings/gf_meetings.cpp` | C bridge. `init` creates `MeetingController` on Qt's GUI thread; every other entry point queues onto it (`QMetaObject::invokeMethod(..., Qt::QueuedConnection)`); `shutdown` deletes it (blocking-queued if off-thread) |
| `meetings/schedule.*` | `Schedule` + `nextOccurrence()` (QTimeZone, DST-aware, DST gap → +1 h), `describeRepeat()` — pure, unit-tested |
| `meetings/meeting.*` | `Meeting` struct, `MeetingStore` (INI via QSettings, `<TS3 config>/groupfinder_meetings.ini`), `splitChannelPath()` — pure, unit-tested |
| `meetings/firing.*` | `decide(meeting, occurrence, now)` → None/ShowWarning/Execute/Advance; 5-min missed grace — pure, unit-tested |
| `query/groupquery.*` | merge groups by name, CSV parse, AND/OR matching, alarm query ⇄ ticked groups — pure, unit-tested |
| `query/querycontroller.*`, `finderwindow.*`, `alarmwindow.*`, `groupchecklist.*` | per-server group lists from forwarded `onServerGroupList*Event`s (requests the list if missing), live results, alarm editing via `gf_alarm_get/set` |
| `src/gf_alarm.h` (impl. in plugin.c) | `GfAlarmConfig {enabled, query, sound}` per schid; SRWLOCK-guarded; file `<server name>_alarm.cfg` with `enabled=`, `query=`, `sound=` |
| `common/ts3api.*` | wrapper over `TS3Functions` (connected servers, channel tree in CHANNEL_ORDER order, resolve channel by path then id, move self w/ return code, `guiConnect` new tab, print, sound) |
| `meetings/meetingcontroller.*` | 1 s tick applying `decide()`; execute = move if connected to server UID (fallback host:port) else `guiConnect` + move after `STATUS_CONNECTION_ESTABLISHED`; owns all windows (`own()`), deletes them in its destructor |
| `meetings/schedulerwindow.*`, `meetingdialog.*`, `warnpopup.*` | Qt UI. Non-blocking only (`show()`/`open()`, never `exec()`). Warning pop-up is parentless + stays-on-top |

Menus: 1005 Find Users by Group…, 1002 Connect Alarm Settings…, 1001 Connect Alarm: Toggle, 1003 Meeting
Scheduler… (all GLOBAL), 1004 Add meeting here… (CHANNEL). Hotkeys: `gf_open_finder`, `gf_open_meetings`,
`gf_join_next`, `gf_cancel_move`, `gf_alarm_toggle`, `gf_find_alarm`. `ts3plugin_configure` (Settings button)
opens the scheduler.

## TS3 plugin SDK rules that matter here

- Hooks are discovered by **exported symbol name**. Defining a `ts3plugin_*` function enables it; a
  prototype in `plugin.h` alone does nothing.
- `ts3plugin_apiVersion()` must equal the client's plugin API major version or the plugin won't load.
- Load order: `setFunctionPointers` → `init` → `registerPluginID` (copy the id) → `initMenus`/`initHotkeys`.
  The bridge is initialised at the end of `registerPluginID`.
- Memory from the client → `ts3Functions.freeMemory`. Memory given to the client (menus, hotkeys,
  `infoData`) → client calls our `ts3plugin_freeMemory` (`free`).
- `processCommand` returns 0 = handled, 1 = not handled.
- `onServerErrorEvent`: return 1 only for our own return codes (the bridge tracks them).
- Every window must be destroyed in `ts3plugin_shutdown` — including closed ones whose deferred delete
  hasn't run — or TS3 crashes after the DLL unloads.
- Callbacks can arrive on non-GUI threads: never touch widgets directly from a `ts3plugin_*` function. In the
  harness fake, anything that schedules Qt timers must hop to the main thread first.
- `getChannelIDFromChannelNames(schid, names, &id)`: `names` must end with an **empty string `""`**, not NULL —
  TS3 dereferences every entry until `""` (a NULL terminator crashed 1.3.0 on "Join now"; found via crash dump).
  The SDK header doesn't document this; when an API takes a list, check the TS3 ClientLib docs or a dump.
- Debugging real crashes: TS3 writes `%APPDATA%\TS3Client\crashdumps\ts3dump_*.zip`; extract and run
  `cdb.exe -z <dmp> -c ".ecxr;k 40;q"` (Windows SDK Debuggers\x64). Frames show as `groupfinder!ts3plugin_version+0x…`
  (nearest export): add that export's RVA, `objdump -d` the release DLL there, and map `call *0xNN(%reg)`
  on the TS3Functions pointer to slot NN/8 of `struct TS3Functions`.
- `guiConnect(PLUGIN_CONNECT_TAB_NEW_IF_CURRENT_CONNECTED, label, "host:port", serverPw, nick, channelPath, channelPw, "", …)`:
  empty strings = TS3 defaults. Channel path format is what `getChannelConnectInfo` returns ("Parent/Child").
- Useful unused API: `requestServerGroupClientList` (offline members), `onServerGroupClientAdded/DeletedEvent`,
  `infoTitle/infoData` (info panel), `CLIENT_AWAY`, `CLIENT_COUNTRY`, `setPluginMenuEnabled`.

## Testing

- `tests/test_*.cpp` (QtTest, one exe `gf_tests`): schedule math incl. DST, store round-trip/garbage, firing rules.
- `tests/plugin_harness.cpp` (`gf_harness <dll> <mode> <outdir>`): loads the real DLL with a fake
  `TS3Functions` (one server "Test Server"/UID1, channels Lobby/Ops/Ops→Briefing/AFK, self clid 5) and checks
  exports, menus (5), hotkeys (6), move/connect/not-found paths, warn pop-up countdown + buttons, calls from a
  worker thread, clean unload (asserts the DLL is really unmapped), edit/save + Qt settings cache after unload,
  opening from inside a modal dialog, per-server alarms (`alarm`), both query windows end to end (`query`), long
  names/input (`limits`), non-ASCII plugin folder + sound (`unicode`), and that closing our windows never emits
  `lastWindowClosed`; writes
  screenshots. Each mode runs inside `app.exec()` (some Qt behaviour only happens in a running event loop),
  with `QT_QPA_PLATFORM=offscreen`.
- Not testable here: the real TS3 client (theme, `guiConnect` behaviour, real return codes). Manual checklist
  in `docs/superpowers/plans/2026-11-19-meeting-scheduler.md` Task 8.

## Known issues / gotchas (as of 1.4.0)

1. `processCommand` duplicates `build_groupsets_from_tokens` inline instead of calling it.
2. (fixed in 1.4.0: group cache and alarm are per server tab.) Up to 8 cached servers / 16 alarm slots; the
   oldest is reused beyond that.
3. Alarm config file is keyed by server **name**, not UID (renaming a server loses its alarm).
4. (fixed in 1.4.0) plugin.c no longer maps snprintf→sprintf_s and `_strcpy` truncates (`strncpy_s(...,_TRUNCATE)`):
   the `_s` functions *terminate the process* on overflow. Never reintroduce them for user-controlled text.
   Paths: the plugin's own path comes from the W API converted to UTF-8; check UTF-8 paths with
   `utf8_file_exists` (narrow `fopen` reads the ANSI code page). Alarm `.cfg` files still use narrow `fopen` on
   `getConfigPath` + server name (changing that would orphan existing files).
5. `icmp` is ASCII-only. Alarm matching is AND-only (no "any of these groups" mode). The C finder (/findgroup)
   and the C++ window each have their own matcher with the same semantics (groupquery.cpp mirrors plugin.c).
6. Repo hygiene: `plugin.o` (root, stale SDK demo) and `src/plugin.o` are tracked build artifacts;
   `.travis.yml` is dead; `groupfinder/plugins/groupfinder.dll` is the old 1.2.0 MinGW build (packages are
   built from `dist/`).
7. Server/channel passwords for meetings are stored in plain text in the INI (like TS3 bookmarks).
8. Never hand a `QStringLiteral` to Qt state that outlives the DLL (QSettings top-level keys, global caches):
   its data lives in the DLL image. Never leave `WA_QuitOnClose` on a plugin window (`MeetingController::own`).
9. Deferred review minors (1.4.0): alarm window re-applies saved ticks when the group list re-arrives (loses
   unsaved ticks); "Loading groups…" forever without list permission (no retry/timeout), and plugin.c doesn't
   request the list for tabs connected before the plugin was enabled; a group named like a number is saved as an
   ID; window server lists don't refresh while open; template/query group types aren't filtered; >256 groups or
   >16 same-name IDs exceed plugin.c's matcher limits. Older (1.3.0): cancel state resets on edit/restart; pop-up title escapes `&`; channel
   switch in dialog keeps old auto-filled password; QSettings write errors not reported; host:port fallback +
   channel-id fallback on a reinstalled server; list "Next" can lag 30 s.
