#pragma once
// Moving work from TeamSpeak's callback threads onto Qt's GUI thread (header-only, no std::function so
// MSVCP140 stays out of the DLL's imports).
#include <QCoreApplication>
#include <QMetaObject>
#include <QThread>

namespace gf {

// Run fn(target) on target's thread after the current TS3 callback returns. No-op for a null target.
template <class T, class F>
void postTo(T* target, F fn)
{
    if (target)
        QMetaObject::invokeMethod(target, [target, fn] { fn(target); }, Qt::QueuedConnection);
}

// Objects created in a TS3 callback must live on the GUI thread (their timers and windows do).
inline void moveToGuiThread(QObject* o)
{
    QCoreApplication* app = QCoreApplication::instance();
    if (app && o->thread() != app->thread())
        o->moveToThread(app->thread());
}

// Delete o on its own (GUI) thread before returning; blocks if called from another thread.
template <class T>
void deleteOnItsThread(T* o)
{
    QCoreApplication* app = QCoreApplication::instance();
    if (!app || QThread::currentThread() == o->thread())
        delete o;
    else
        QMetaObject::invokeMethod(app, [o] { delete o; }, Qt::BlockingQueuedConnection);
}

} // namespace gf
