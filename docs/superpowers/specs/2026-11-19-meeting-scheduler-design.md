# Meeting Scheduler + Hotkeys — Design

Status: approved approach (Option A) 2026-11-19. Calls marked *(Claude's call)* were not discussed and can be changed.

## Intent

Let the user (and anyone who installs the `.ts3_plugin`) keep a list of recurring TeamSpeak meetings. At
meeting time the plugin puts them in the meeting's channel — moving them if they're already on that server,
opening a new connection tab straight into the channel if they're not. Optionally warn first with a pop-up
that counts down and lets them cancel. Plus plugin hotkeys. Stays inside the groupfinder addon for now; may
be split out later, so the meeting code lives in its own folder behind a small C interface.

## Goals

- Window ("Meeting Scheduler") to list / add / edit / remove meetings. Opened from: Plugins menu entry,
  plugin "Settings" button in TS3's addon list, and a hotkey. (The SDK has no toolbar-button hook.)
- Right-click a channel → "Add meeting here…" → edit dialog pre-filled with that server and channel.
- Per meeting: name, server, channel (+ optional channel password), nickname for new connections,
  start date, time, timezone (IANA, DST-aware), repeat (Once / Daily / Weekly on chosen weekdays /
  Monthly) with "every N", enabled flag, and action:
  - **Move at start** — silently move at the start time; doesn't care what the user is doing.
  - **Warn, then move** — pop-up N minutes before (default 2): "‹name› starts in ‹channel› in 1:47 — you
    will be moved automatically", buttons **Move now** / **Don't move me**. Countdown hits 0 → move.
- At start time: connected to that server → move self to the channel. Not connected (or connected
  elsewhere) → open a new tab connected to that server into that channel (`guiConnect`,
  `PLUGIN_CONNECT_TAB_NEW_IF_CURRENT_CONNECTED`).
- Hotkeys (bindable in TS3 Options → Hotkeys): open scheduler, join next meeting now, cancel pending
  meeting move, toggle connect alarm, list online users matching the alarm criteria.
- Looks like part of TS3: Qt widgets running inside TS3's own QApplication (inherits its style).
- Works for other users with just the `.ts3_plugin` (no extra DLLs; TS3 already ships Qt 5.15.2).

## Non-goals

- Meeting duration / end times, attendance, notifying other users, syncing meetings between users.
- Catching up on meetings that started while TS3 was closed (see grace rule below).
- 32-bit TS3 clients (package becomes `win64` only), Linux/macOS clients.
- Fixing the existing alarm's single-server limitation (separate work).

## Anti-goals

- Shipping Qt DLLs in the package, or anything that makes other users install software.
- Crashing or freezing TS3: no blocking calls on the GUI thread, all windows destroyed in `ts3plugin_shutdown`.
- Moving the user twice for one occurrence, or moving them for a meeting they cancelled.

## Constraints (verified on this machine 2026-11-19)

- TS3 client ships **Qt 5.15.2, MSVC 2019, x64** (`Qt5Core/Gui/Widgets.dll` in the install dir).
  Plugin must be built with MSVC (Build Tools 2022, toolset 14.44 — ABI-compatible with 2019) against
  Qt **5.15.2 msvc2019_64** headers/import libs, **Release** only (Debug links `Qt5Cored.dll`).
- Dev Qt installed with aqtinstall at `%USERPROFILE%\Qt\5.15.2\msvc2019_64` (qtbase only).
- CRT: `/MD` (same as Qt). Verify after each build that imports are limited to KERNEL32, Qt5Core/Gui/Widgets,
  VCRUNTIME140(_1), MSVCP140 (only if unavoidable) and `api-ms-win-crt-*`.
- Sources compiled with `/utf-8` (existing strings contain `—` and `•`).
- Plugin API version stays 26. MinGW/Makefile build is retired (cannot link MSVC-built Qt).
- Thread safety: TS3 callbacks may arrive on non-GUI threads; every GUI action is marshalled to a
  controller `QObject` living in `qApp->thread()` with `QMetaObject::invokeMethod(..., Qt::QueuedConnection)`.

## Approaches considered

| | Look | Install cost | Code cost |
|---|---|---|---|
| **A. Qt Widgets, C++, MSVC, TS3's own Qt** *(chosen)* | Matches TS3 (theme incl. dark) | Qt dev files (no admin) | Qt does timezones/DST, pickers, timers |
| B. Win32 dialog in C, MinGW | Classic grey Windows dialog | None | Hand-written layout, TZ, threads |
| C. HTML UI in Qt WebEngine | Most designable | Same as A | Heavy, slow to open, more moving parts |

User picked A.

## Design

### Schedule semantics *(Claude's call)*
- A meeting's wall-clock time is interpreted in its own timezone (default: system zone). Next occurrence
  is computed with `QTimeZone`, so DST changes keep "20:00 Europe/Berlin" at 20:00 Berlin time.
- Weekly with no weekday ticked is invalid (dialog blocks Save). Monthly on day 29–31 clamps to the
  month's last day. A time inside a DST gap shifts forward one hour.
- Times are tracked in UTC internally; the list's "Next" column and the dialog preview show *local* time.

### Firing rules *(Claude's call)*
- 1-second timer on the GUI thread. On plugin load each meeting's next occurrence is computed **after now**
  (no catch-up). After an occurrence fires (or is skipped), the next one is computed after it.
- If the PC slept through an occurrence, it's executed only if ≤ 5 minutes late; otherwise skipped.
- Warn mode: pop-up appears at start − N min (or immediately if a meeting is saved inside that window).
  Closing the pop-up with ✕ = dismiss, **still moves** (matches the pop-up text). "Don't move me" cancels
  only this occurrence. Pop-up flashes the taskbar and plays the plugin's `default.wav`.

### Executing a meeting
1. Find a connection tab whose `VIRTUALSERVER_UNIQUE_IDENTIFIER` equals the stored UID (fallback: same
   host+port from `getServerConnectInfo`) and status `STATUS_CONNECTION_ESTABLISHED`.
2. Found → resolve channel by stored path (`getChannelIDFromChannelNames`), fallback stored channel ID;
   already there → print note; else `requestClientMove(self)` with a plugin return code. Errors that come
   back on that return code (wrong password, no permission) are printed to that tab as `[Meetings] …`.
3. Not found → `guiConnect(PLUGIN_CONNECT_TAB_NEW_IF_CURRENT_CONNECTED, serverName, "host:port",
   serverPassword, nickname, channelPath, channelPassword, …"" defaults)`; remember the new handler; when it
   reaches `STATUS_CONNECTION_ESTABLISHED`, verify the channel and move if TS3 put us elsewhere.

### Storage *(Claude's call)*
`<TS3 config dir>/groupfinder_meetings.ini` via `QSettings(IniFormat)`, one group per meeting id.
Server/channel passwords are stored in plain text, like TS3's own bookmarks (local file, user's profile).

### UI

```
┌ Group Finder — Meetings ─────────────────────────────────────────────┐
│ On │ Name       │ Server        │ Channel       │ Repeats    │ Next   │
│ ☑  │ Weekly op  │ ArmaCommunity │ Ops/Briefing  │ Tue 20:00  │ Tue 25 Nov 20:00 (in 6 d) │
│ [Add…] [Edit…] [Remove]                             [Join now] [Close]│
└──────────────────────────────────────────────────────────────────────┘

┌ Edit meeting ──────────────────────────────────────┐
│ Name         [Weekly op                  ]          │
│ Server       [ArmaCommunity (ts.x.com:9987) ▼]      │
│ Channel      [  Ops/Briefing              ▼]        │
│ Channel pw   [••••      ]   Nickname [PhysicsGaunt] │
│ Date [2026-11-25 ▼]  Time [20:00]  Zone [Europe/Berlin ▼] │
│ Repeat [Weekly ▼] every [1] week(s)  ☐Mo ☑Tu ☐We ☐Th ☐Fr ☐Sa ☐Su │
│ At start  (•) Move me automatically                 │
│           ( ) Warn me [2] min before, then move     │
│ ☑ Enabled          Next: Tue 25 Nov 20:00 your time │
│                                   [Save] [Cancel]   │
└─────────────────────────────────────────────────────┘
```
Server combo lists connected tabs; a meeting whose server isn't connected shows its saved server/channel
as the only entry. "Add…" with no connected server shows "Connect to the meeting's server first".

### Hotkeys
| keyword | description |
|---|---|
| `gf_open_meetings` | Open meeting scheduler |
| `gf_join_next` | Join next meeting now |
| `gf_cancel_move` | Cancel pending meeting move |
| `gf_alarm_toggle` | Toggle connect alarm |
| `gf_find_alarm` | List online users matching alarm criteria |

### Code layout
`src/plugin.c` stays the only place with `ts3plugin_*` exports and keeps all existing groupfinder/alarm
logic. Meeting code lives in `src/meetings/` (C++/Qt) behind `src/gf_meetings.h` (C linkage), so it can be
split into its own plugin later.

### Packaging
Version **1.3.0** (single source: `project(VERSION)` in CMakeLists.txt → `GF_VERSION` define + package.ini
written at package time). `Platforms = win64`.

## Left to the builder
Widget-level layout details, wording of status/log messages, internal class structure inside `src/meetings/`.
