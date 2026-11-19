# Meeting Scheduler + Hotkeys Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Add a Qt meeting scheduler (list window, per-channel "Add meeting here…", auto-move / warn-then-move, connect-in-new-tab) and five plugin hotkeys to groupfinder, built with MSVC against TS3's Qt 5.15.2, shipped as a self-contained `.ts3_plugin`.

**Architecture:** `src/plugin.c` keeps every `ts3plugin_*` export and the existing finder/alarm logic, and forwards meeting events through a C-linkage bridge (`src/gf_meetings.h`). Meeting code is C++/Qt in `src/meetings/`: pure logic (schedule math, store, firing decisions) unit-tested with QtTest; a GUI-thread `MeetingController` that owns the timer, windows and TS3 calls. A test harness exe loads the real DLL with a fake `TS3Functions` table to exercise lifecycle, execution paths, threading and to screenshot the windows.

**Tech Stack:** C11 + C++17, Qt 5.15.2 (Core/Gui/Widgets/Test) msvc2019_64, MSVC Build Tools 2022 (14.44), CMake + Ninja, driven from WSL by `scripts/build.sh`.

**Spec:** `docs/superpowers/specs/2026-11-19-meeting-scheduler-design.md`

## Global Constraints

- Release builds only; link Qt 5.15.2 msvc2019_64 import libs; never ship Qt DLLs.
- `/MD` CRT, `/utf-8` for all sources, `_CRT_SECURE_NO_WARNINGS`.
- DLL imports allowed: `KERNEL32`, `USER32`, `Qt5Core`, `Qt5Gui`, `Qt5Widgets`, `VCRUNTIME140`, `VCRUNTIME140_1`, `MSVCP140`, `api-ms-win-crt-*`. Anything else (e.g. `Qt5Cored`, `MSVCP140D`, `libgcc*`) fails the build script.
- Plugin API version 26. Plugin version `1.3.0`, single source `project(groupfinder VERSION 1.3.0)`.
- Every GUI action runs on `qApp->thread()` via `QMetaObject::invokeMethod(controller, fn, Qt::QueuedConnection)`.
- All windows/popups destroyed in `ts3plugin_shutdown`.
- Do not commit (user commits on request). Work on branch `feature/meeting-scheduler`.

## Review Focus

1. TS3 calls a callback (hotkey/menu/connect) on a non-GUI thread → widget created off-thread → crash. Expect: window appears, no Qt thread warnings. (Task 7 harness `thread` mode.)
2. User unloads/disables the plugin with the scheduler and a warning pop-up open → TS3 crashes. Expect: clean unload. (Task 6 harness `lifecycle` mode opens windows before shutdown.)
3. Meeting's channel was deleted/renamed or server unreachable → expect a `[Meetings]` message, no move to a wrong channel, no crash. (Task 5 harness `execute` mode, "Gone" channel case.)
4. DST transition between creating and running a weekly meeting → expect same wall-clock time in the meeting's zone. (Task 2 `dst_keepsWallClock`.)
5. Hand-edited / older INI with missing keys or an unknown timezone → expect load with defaults, no crash. (Task 3 `store_loadToleratesGarbage`.)

---

### Task 1: MSVC/CMake build of the existing plugin

**Files:**
- Create: `CMakeLists.txt`, `scripts/build.sh`
- Modify: `src/plugin.c` (version string only), `.gitignore`
- Delete: `Makefile`

**Interfaces:**
- Produces: `scripts/build.sh <cmd>` with `cmd ∈ {build, test, harness, package, all}`; output `dist/groupfinder.dll`, later `dist/groupfinder-<ver>.ts3_plugin`. CMake option `GF_BUILD_TESTS` (ON from script). Compile definition `GF_VERSION="1.3.0"`.

- [ ] **Step 1:** `CMakeLists.txt`: `cmake_minimum_required(3.16)`, `project(groupfinder VERSION 1.3.0 LANGUAGES C CXX)`, C++17, `CMAKE_AUTOMOC ON`, `find_package(Qt5 5.15 REQUIRED COMPONENTS Core Gui Widgets)`, `add_library(groupfinder SHARED src/plugin.c)`, include dirs `include` `src`, defs `GF_VERSION="${PROJECT_VERSION}" _CRT_SECURE_NO_WARNINGS WIN32`, options `/utf-8 /W3`, link `Qt5::Core Qt5::Gui Qt5::Widgets`, `PREFIX ""` (output `groupfinder.dll`). Tests block under `if(GF_BUILD_TESTS)` with `enable_testing()` (filled in later tasks).
- [ ] **Step 2:** `src/plugin.c`: `#ifndef GF_VERSION / #define GF_VERSION "dev"`; `ts3plugin_version()` returns `GF_VERSION`.
- [ ] **Step 3:** `scripts/build.sh`: resolves `%LOCALAPPDATA%\groupfinder-build` and `%USERPROFILE%\Qt\5.15.2\msvc2019_64` (override `GF_QT_DIR`) via `cmd.exe`, finds vcvars64 with `vswhere -latest -requires Microsoft.VisualStudio.Component.VC.Tools.x86.x64`, `rsync -a --delete` repo (minus `.git build dist`) to `<root>/src`, writes CRLF `build.bat` (vcvars → `cmake -G Ninja -DCMAKE_BUILD_TYPE=Release -DGF_BUILD_TESTS=ON -DCMAKE_PREFIX_PATH=<qt>` → `cmake --build`), runs it with `cmd.exe /c`, copies `groupfinder.dll` to `dist/`, prints exports and imports with `objdump -p`, fails on any import outside the allowlist.
- [ ] **Step 4:** `.gitignore` add `build/`, `dist/`; `git rm --cached` nothing (leave tracked .o files; note in final report). Delete `Makefile`.
- [ ] **Step 5:** Run `scripts/build.sh build`. Expected: exit 0; exports list = the 17 existing names; imports within allowlist.

### Task 2: Schedule math (TDD)

**Files:**
- Create: `src/meetings/schedule.h`, `src/meetings/schedule.cpp`, `tests/test_schedule.cpp`
- Modify: `CMakeLists.txt` (test target `gf_tests`: `tests/test_*.cpp` + pure `src/meetings/{schedule,meeting,firing}.cpp`, links `Qt5::Core Qt5::Test`; `add_test`), `scripts/build.sh` (`test` runs `ctest --output-on-failure` with `<qt>\bin` on PATH)

**Interfaces:**
- Produces (namespace `gf`):
  - `enum class Repeat { Once = 0, Daily = 1, Weekly = 2, Monthly = 3 };`
  - `struct Schedule { QDate startDate; QTime time; QByteArray timeZoneId; Repeat repeat = Repeat::Weekly; int interval = 1; quint8 weekdays = 0; };` — `weekdays` bit `1 << (dayOfWeek-1)`, Mon = 0x01 … Sun = 0x40; empty `timeZoneId` = system zone.
  - `QTimeZone scheduleZone(const Schedule&)` — invalid/unknown id → `QTimeZone::systemTimeZone()`.
  - `bool isValid(const Schedule&)` — valid date+time, `interval >= 1`, Weekly requires `weekdays != 0`.
  - `QDateTime nextOccurrence(const Schedule&, const QDateTime& after)` — UTC, strictly `> after`, invalid if none.
  - `QString describeRepeat(const Schedule&)`.

- [ ] **Step 1: Write failing tests** (`class TestSchedule : public QObject`, `QTEST_APPLESS_MAIN` lives in a single `tests/test_main.cpp` that runs every test class; dates below were checked against a calendar):

```cpp
// helper: S(start, "20:00", "Europe/Berlin", Repeat::Weekly, interval, weekdays); U("2026-11-19T19:00:00Z")
once_beforeStart:       Once 2026-11-25 20:00 Berlin, after U(2026-11-20T00:00Z) → U(2026-11-25T19:00Z)
once_afterItPassed:     same, after U(2026-11-26T00:00Z) → !isValid()
weekly_nextTickedDay:   start 2026-11-17 (Tue), Tue|Thu (0x02|0x08), after U(2026-11-19T12:00Z) → U(2026-11-19T19:00Z)
weekly_strictlyAfter:   same, after U(2026-11-19T19:00Z) → U(2026-11-24T19:00Z)
weekly_everyTwoWeeks:   start 2026-11-17, Tue, interval 2, after U(2026-11-18T00:00Z) → U(2026-12-01T19:00Z)
weekly_notBeforeStart:  start 2026-12-01, Tue, after U(2026-11-19T00:00Z) → U(2026-12-01T19:00Z)
dst_keepsWallClock:     start 2027-03-23 Tue weekly, after U(2027-03-23T00:00Z) → U(2027-03-23T19:00Z); after that → U(2027-03-30T18:00Z)
dstGap_shiftsForward:   Daily 02:30 Berlin start 2027-03-27, after U(2027-03-27T12:00Z) → U(2027-03-28T01:30Z)
daily_everyThreeDays:   start 2026-11-19 09:00 "UTC", interval 3, after U(2026-11-20T00:00Z) → U(2026-11-22T09:00Z)
monthly_clampsLastDay:  start 2027-01-31 12:00 UTC, after U(2027-02-01T00:00Z) → U(2027-02-28T12:00Z)
monthly_interval:       start 2026-11-05 12:00 UTC, interval 3, after U(2026-11-06T00:00Z) → U(2027-02-05T12:00Z)
unknownZone_usesSystem: timeZoneId "Not/AZone" → nextOccurrence(...).isValid()
isValid_weeklyNeedsDay: Weekly weekdays 0 → false; interval 0 → false
describe_cases:         Once→"Once", Daily i1→"Daily", Daily i2→"Every 2 days", Weekly Tue|Thu→"Weekly on Tue, Thu",
                        Weekly i2 Tue→"Every 2 weeks on Tue", Monthly day31→"Monthly on day 31", Monthly i3 day5→"Every 3 months on day 5"
```

- [ ] **Step 2:** `scripts/build.sh test` → FAIL (link errors / undefined `gf::nextOccurrence`).
- [ ] **Step 3:** Implement. Algorithm for `nextOccurrence`: zone `z`; Once → single candidate. Otherwise iterate dates `d` from `max(startDate, after.toTimeZone(z).date().addDays(-1))` for at most `400 * interval + 62` days; `d` matches when Daily: `startDate.daysTo(d) % interval == 0`; Weekly: weekday bit set and `(mondayOf(startDate).daysTo(mondayOf(d)) / 7) % interval == 0`; Monthly: `monthsBetween % interval == 0` and `d.day() == min(startDate.day(), d.daysInMonth())`. Candidate `QDateTime(d, time, z)`; if `!isValid()` use `time.addSecs(3600)`. First candidate `> after` → `.toUTC()`.
- [ ] **Step 4:** `scripts/build.sh test` → all `TestSchedule` PASS.

### Task 3: Meeting model + INI store (TDD)

**Files:**
- Create: `src/meetings/meeting.h`, `src/meetings/meeting.cpp`, `tests/test_meeting.cpp`

**Interfaces:**
- Consumes: `gf::Schedule`, `gf::Repeat` (Task 2).
- Produces (namespace `gf`):
  - `enum class Action { MoveAtStart = 0, WarnThenMove = 1 };`
  - `struct Meeting { QString id, name; bool enabled = true; QString serverName, serverUid, host; quint16 port = 9987; QString serverPassword, nickname; quint64 channelId = 0; QString channelPath, channelPassword; Schedule schedule; Action action = Action::MoveAtStart; int warnMinutes = 2; };`
  - `QStringList splitChannelPath(const QString&)` — split on `/` not preceded by `\`, unescape `\/`.
  - `QString channelDisplayName(const Meeting&)` — last path segment, else `"#<channelId>"`.
  - `class MeetingStore { public: explicit MeetingStore(QString iniPath); QVector<Meeting> load() const; void save(const QVector<Meeting>&) const; };` — `QSettings::IniFormat`, UTF-8 codec, one group per id, `save` clears then writes all.

- [ ] **Step 1: Failing tests** (`TestMeeting`, temp dir via `QTemporaryDir`):
  - `store_roundTrip`: meeting with every field non-default, name `"Böse Öps — ✓"`, weekdays `0x2A`, zone `"America/New_York"`, Monthly interval 3, WarnThenMove 5 → `load()` equals saved field-by-field.
  - `store_missingFile`: `load()` on nonexistent path → empty.
  - `store_saveRemovesDeleted`: save [a,b], save [b] → load → only b.
  - `store_loadToleratesGarbage`: INI group with only `name=X` and `timeZone=Bogus/Zone`, `repeat=99` → loads 1 meeting, `repeat == Repeat::Once`?? — no: unknown repeat → `Repeat::Once`, `port == 9987`, `warnMinutes == 2`, id = group name.
  - `splitPath_cases`: `"Ops/Briefing"`→`{"Ops","Briefing"}`; `"A\/B/C"`→`{"A/B","C"}`; `""`→`{}`.
- [ ] **Step 2:** `scripts/build.sh test` → FAIL.
- [ ] **Step 3:** Implement `meeting.cpp`.
- [ ] **Step 4:** `scripts/build.sh test` → PASS.

### Task 4: Firing decisions (TDD)

**Files:**
- Create: `src/meetings/firing.h`, `src/meetings/firing.cpp`, `tests/test_firing.cpp`

**Interfaces:**
- Consumes: `gf::Meeting`, `gf::Action`.
- Produces (namespace `gf`):
  - `struct Occurrence { QDateTime startUtc; bool warned = false; bool cancelled = false; bool done = false; };`
  - `enum class FireAction { None, ShowWarning, Execute, Advance };`
  - `constexpr qint64 kMissedGraceSecs = 300;`
  - `FireAction decide(const Meeting&, const Occurrence&, const QDateTime& nowUtc);`
  Rules: disabled or invalid start → None. `now >= start`: cancelled/done → Advance; `now - start > grace` → Advance; else Execute. `now < start`: WarnThenMove, not warned/cancelled/done, `now >= start - warnMinutes*60s` → ShowWarning; else None.

- [ ] **Step 1: Failing tests** (`TestFiring`, start `S = 2026-11-24T19:00Z`): `disabled_none`; `atStart_execute` (now = S); `withinGrace_execute` (S+299 s); `missed_advance` (S+301 s); `cancelled_advance` (S+1 s); `done_advance`; `warnWindow_show` (WarnThenMove 2, now S−120 s); `beforeWarnWindow_none` (S−121 s); `alreadyWarned_none`; `moveMode_neverWarns` (MoveAtStart, S−60 s → None).
- [ ] **Step 2:** FAIL. **Step 3:** implement. **Step 4:** `scripts/build.sh test` → PASS.

### Task 5: Bridge, TS3 wrapper, controller core, harness

**Files:**
- Create: `src/gf_meetings.h`, `src/meetings/gf_meetings.cpp`, `src/meetings/ts3api.h`, `src/meetings/ts3api.cpp`, `src/meetings/meetingcontroller.h`, `src/meetings/meetingcontroller.cpp`, `tests/plugin_harness.cpp`
- Modify: `src/plugin.c`, `CMakeLists.txt` (add sources to `groupfinder`; harness exe `gf_harness` links `Qt5::Widgets`, not the plugin), `scripts/build.sh` (`harness` cmd runs `gf_harness.exe <dll> <mode> <outdir>` with `QT_QPA_PLATFORM=offscreen`, `QT_PLUGIN_PATH=<qt>\plugins`, `<qt>\bin` on PATH)

**Interfaces:**
- `src/gf_meetings.h` (C linkage, includes `teamspeak/public_definitions.h`):
  ```c
  void gf_meetings_init(const struct TS3Functions* funcs, const char* pluginID, const char* configDir, const char* soundPath);
  void gf_meetings_shutdown(void);
  void gf_meetings_open_scheduler(void);
  void gf_meetings_add_for_channel(uint64 schid, uint64 channelID);
  int  gf_meetings_handle_hotkey(const char* keyword);      /* 1 = meeting hotkey handled */
  void gf_meetings_on_connect_status(uint64 schid, int newStatus);
  int  gf_meetings_on_server_error(uint64 schid, const char* errorMessage, unsigned int error, const char* returnCode); /* 1 = ours */
  ```
  Init creates the controller, `moveToThread(qApp->thread())` if needed, queues `start()`. Shutdown deletes it on the GUI thread (`BlockingQueuedConnection` if called elsewhere). All other entry points queue onto the controller.
- `gf::ts3` (ts3api.h): `void setFunctions(const TS3Functions*, QByteArray pluginId); struct ServerTab { quint64 schid; QString name, uid, host; quint16 port; QString password, nickname; }; struct ChannelEntry { quint64 id; QString name, path; int depth; }; QVector<ServerTab> connectedServers(); std::optional<ServerTab> serverTab(quint64); QVector<ChannelEntry> channels(quint64); /* tree order via CHANNEL_ORDER */ QString channelPassword(quint64, quint64); quint64 findServer(const QString& uid, const QString& host, quint16 port); quint64 resolveChannel(quint64 schid, const QString& path, quint64 fallbackId); quint64 ownChannel(quint64); QByteArray moveSelf(quint64 schid, quint64 channelId, const QString& pw); quint64 connectNewTab(const Meeting&); quint64 currentServer(); void print(quint64 schid, const QString&); void playSound(quint64 schid, const QString& wav); QWidget* mainWindow();`
- `gf::MeetingController : QObject` — `MeetingController(QString iniPath, QString soundPath)`, `void start()`, `const QVector<Meeting>& meetings() const`, `QDateTime nextStart(const QString& id) const`, `void upsertMeeting(const Meeting&)`, `void removeMeeting(const QString& id)`, `void executeNow(const QString& id)`, `void joinNextNow()`, `void cancelPending()`, `void openScheduler()`, `void addMeetingForChannel(quint64, quint64)`, `void onConnectStatus(quint64, int)`, `bool onServerError(quint64, const QString&, unsigned, const QByteArray&)` (thread-safe, `QMutex` around return-code map), signal `meetingsChanged()`. Execution per spec "Executing a meeting"; messages prefixed `[Meetings] `.
- `src/plugin.c` adds: `ts3plugin_freeMemory`, `ts3plugin_onServerErrorEvent`, `ts3plugin_offersConfigure` (`PLUGIN_OFFERS_CONFIGURE_QT_THREAD`), `ts3plugin_configure`; calls `gf_meetings_init` at end of `registerPluginID` (config dir from `getConfigPath`), `gf_meetings_shutdown` first in `shutdown`, `gf_meetings_on_connect_status` at top of connect handler.
- Harness fake world: schid 1 "Test Server" uid `UID1` host `ts.example.com:9987`, own clid 5 in channel 10; channels 10 "Lobby", 11 "Ops", 12 "Briefing" (child of 11), 13 "AFK"; records `requestClientMove`, `guiConnect`, `printMessage*`, `playWaveFile`. Modes: `lifecycle`, `execute`.

- [ ] **Step 1:** Write `tests/plugin_harness.cpp` modes `lifecycle` (load DLL, setFunctionPointers, init → 0, registerPluginID, initMenus/initHotkeys freed through the plugin's `ts3plugin_freeMemory`, `processCommand(1,"help")`, open scheduler via `ts3plugin_onMenuItemEvent(GLOBAL, 1003)`, pump events 500 ms, shutdown, `FreeLibrary`, pump 200 ms, exit 0) and `execute` (pre-write INI with meeting "Op" uid `UID1` path `Ops/Briefing` id 12 + meeting "Gone" path `Nope` id 999; hotkey `gf_join_next` → expect move(1,5,12); `executeNow("Gone")` path tested via second INI run → expect a print containing `not found`, no move; mark server disconnected → `gf_join_next` → expect `guiConnect` address `ts.example.com:9987`, channel `Ops/Briefing`, then fake `onConnectStatusChangeEvent(2, ESTABLISHED)` with own channel 10 → expect move(2,5,12)).
- [ ] **Step 2:** `scripts/build.sh harness` → FAIL (missing exports / symbols).
- [ ] **Step 3:** Implement bridge, ts3api, controller (timer + decide/apply loop; windows come in Task 6 — `openScheduler()` may show an empty placeholder until then), plugin.c wiring.
- [ ] **Step 4:** `scripts/build.sh test && scripts/build.sh harness` → both modes print `HARNESS OK`; import allowlist passes.

### Task 6: Windows — scheduler list, meeting dialog, warning pop-up

**Files:**
- Create: `src/meetings/schedulerwindow.{h,cpp}`, `src/meetings/meetingdialog.{h,cpp}`, `src/meetings/warnpopup.{h,cpp}`
- Modify: `src/meetings/meetingcontroller.cpp`, `tests/plugin_harness.cpp` (mode `screenshots`, `warn`)

**Interfaces:**
- `gf::SchedulerWindow : QDialog` — `SchedulerWindow(MeetingController*, QWidget* parent)`; columns On/Name/Server/Channel/Repeats/Next; buttons Add…/Edit…/Remove/Join now/Close; refreshes on `meetingsChanged` and every 30 s; `WA_DeleteOnClose`.
- `gf::MeetingDialog : QDialog` — `MeetingDialog(const Meeting& initial, bool isNew, QWidget* parent)`, `Meeting result() const`; layout per spec sketch; live "Next: … your time" preview; Save disabled while `!isValid(schedule)` or name/channel empty.
- `gf::WarnPopup : QDialog` — `WarnPopup(const Meeting&, const QDateTime& startUtc, QWidget* parent)`; signals `moveNowClicked()`, `dontMoveClicked()`; `Qt::WindowStaysOnTopHint`, countdown `m:ss` updated every 250 ms; `QApplication::alert` on show.
- Controller keeps `QPointer`s, deletes all in destructor; popup per occurrence closed when the occurrence advances.

- [ ] **Step 1:** Harness `screenshots <outdir>`: open scheduler (with 2 stored meetings), "Add meeting here" on channel 12, grab each top-level visible widget to `<outdir>/<objectName>.png`; `warn`: meeting WarnThenMove starting now+3 s → within 1 s a `WarnPopup` is visible (grab it), after 5 s expect move(1,5,12) recorded and popup gone.
- [ ] **Step 2:** `scripts/build.sh harness` → FAIL. **Step 3:** implement. **Step 4:** harness OK; inspect PNGs (layout readable, nothing clipped).

### Task 7: Menus, hotkeys, alarm hotkeys, thread safety

**Files:**
- Modify: `src/plugin.c`, `tests/plugin_harness.cpp` (mode `thread`)

**Interfaces:**
- Menus: existing 1001/1002 GLOBAL + `MENU_ID_GLOBAL_MEETINGS = 1003` "Meeting Scheduler…" (GLOBAL) + `MENU_ID_CHANNEL_ADD_MEETING = 1004` "Add meeting here…" (CHANNEL). `onMenuItemEvent` handles CHANNEL type.
- Hotkeys (keyword → description) exactly as spec table; `ts3plugin_onHotkeyEvent`: meeting keywords → `gf_meetings_handle_hotkey`; `gf_alarm_toggle` → same as menu toggle on `getCurrentServerConnectionHandlerID()`; `gf_find_alarm` → `ts3plugin_processCommand(current, g_alarm_query)` or print "[Alarm] No criteria set…".

- [ ] **Step 1:** Harness `thread`: install `qInstallMessageHandler` that fails on any message containing `thread`; call `ts3plugin_onHotkeyEvent("gf_open_meetings")` and `ts3plugin_onMenuItemEvent(1, CHANNEL, 1004, 12)` from a `std::thread`; pump 500 ms → scheduler and dialog visible, no thread warnings; `lifecycle` asserts 4 menu items and 5 hotkeys.
- [ ] **Step 2:** FAIL. **Step 3:** implement. **Step 4:** `scripts/build.sh all` → tests + all harness modes OK.

### Task 8: Package, docs, ship

**Files:**
- Modify: `scripts/build.sh` (`package`), `groupfinder/package.ini` (`Platforms = win64`, `Version = 1.3.0`, description mentions meetings), `README.md` (meetings, hotkeys, building), `CLAUDE.md` (build section → CMake/MSVC/WSL script, new layout, gotchas)

- [ ] **Step 1:** `package`: stage `package.ini` (Version rewritten from CMake version) + `plugins/groupfinder.dll` + `plugins/groupfinder/sound/default.wav` → `dist/groupfinder-1.3.0.ts3_plugin`; `unzip -t` passes.
- [ ] **Step 2:** `scripts/build.sh all && scripts/build.sh package` → exit 0; exports include the 17 old names + `ts3plugin_freeMemory`, `ts3plugin_initHotkeys`, `ts3plugin_onHotkeyEvent`, `ts3plugin_onServerErrorEvent`, `ts3plugin_offersConfigure`, `ts3plugin_configure`.
- [ ] **Step 3:** Copy package to `%USERPROFILE%\Downloads\` (check for existing file first). Hand the user the manual TS3 test checklist: install; Plugins menu entries; right-click channel; create a Warn meeting 3 min ahead; pop-up + sound; Don't move; Move now; meeting on a server not connected → new tab in channel; hotkeys bound in Options → Hotkeys.
