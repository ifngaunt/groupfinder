#pragma once
// Window helpers shared by every plugin window controller.
#include <QPointer>
#include <QVector>

class QWidget;

namespace gf {

// Parent for a new plugin window: the active modal dialog (e.g. TS3's Options, from which the plugin's
// Settings button is pressed) if any — windows outside it would be blocked — else TS3's main window.
QWidget* dialogParent();

// Tracks every top-level window a controller creates, so all of them (including closed ones whose
// deferred delete hasn't run) are destroyed before the plugin DLL is unloaded.
class WindowOwner {
public:
    ~WindowOwner() { deleteAll(); }
    // Also clears WA_QuitOnClose: closing a plugin window must never look like "the app's last window
    // closed" (with TS3 minimized to the tray that would quit TeamSpeak).
    void own(QWidget* w);
    void deleteAll();

private:
    QVector<QPointer<QWidget>> m_windows;
};

} // namespace gf
