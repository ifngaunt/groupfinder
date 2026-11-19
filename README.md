# ts3 plugin to find online users by their server groups. Made by PhysicsGaunt

Install: double-click `groupfinder-<version>.ts3_plugin` (close TeamSpeak first if an older version is loaded),
then enable **Group Finder Plugin** in *Tools → Options → Addons → Plugins*. 64-bit TeamSpeak 3 client on Windows.

## Find users by group

In a channel chat, type

```
/findgroup "[group1]" "[group2]"
```

this will show all online clients which have all the server groups listed (IDs or names; names may be quoted).
`/findgroup help` shows all options.

![Example image 1](imgs/1.png)

![Example image 2](imgs/2.png)

![Example image 3](imgs/3.png)

![Example image 4](imgs/4.png)

## Connect alarm

`/findgroup alarm set "Head Administrator" Guest` then `/findgroup alarm on` — plays a sound and prints a
clickable name when a matching user connects. Also in the *Plugins* menu.

## Meeting scheduler

Open it from *Plugins → Meeting Scheduler…* (or the plugin's *Settings* button, or a hotkey). Add meetings with
**Add…**, or right-click any channel → **Add meeting here…**.

Each meeting has a channel, a start date and time in a chosen time zone (daylight saving handled), and a repeat
(once, every N days, weeks on chosen weekdays, or months). At the start time:

- **connected to that server** → you are moved into the channel;
- **not connected** (or on another server) → a new tab connects straight into the channel.

Choose per meeting whether that happens silently, or whether a pop-up warns you N minutes before
("starts in 1:47 — you will be moved automatically") with **Move now** / **Don't move me**. Closing the pop-up
keeps the automatic move. Meetings are stored in `%APPDATA%\TS3Client\groupfinder_meetings.ini`.

## Hotkeys

Bind them in *Options → Hotkeys → Add → Plugins → Group Finder Plugin*:

| Hotkey | Does |
|---|---|
| Open meeting scheduler | opens the list window |
| Join next meeting now | moves/connects you to the next upcoming meeting right away |
| Cancel pending meeting move | skips meetings being warned about or starting within 10 minutes (this time only) |
| Toggle connect alarm | same as `/findgroup alarm on/off` |
| List online users matching alarm criteria | runs `/findgroup` with your alarm criteria |

## Building

Windows x64 only, MSVC + Qt 5.15.2 (the Qt TeamSpeak ships). From WSL: `scripts/build.sh package`
→ `dist/groupfinder-<version>.ts3_plugin`. See `CLAUDE.md` for the toolchain setup.
