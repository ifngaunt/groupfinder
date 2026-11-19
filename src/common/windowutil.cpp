#include "common/windowutil.h"

#include <QApplication>
#include <QWidget>
#include <algorithm>

#include "common/ts3api.h"

namespace gf {

QWidget* dialogParent()
{
    if (QWidget* modal = QApplication::activeModalWidget())
        return modal;
    return ts3::mainWindow();
}

void WindowOwner::own(QWidget* w)
{
    w->setAttribute(Qt::WA_QuitOnClose, false);
    m_windows.erase(std::remove_if(m_windows.begin(), m_windows.end(), [](const QPointer<QWidget>& p) { return p.isNull(); }),
                    m_windows.end());
    m_windows << w;
}

void WindowOwner::deleteAll()
{
    const auto windows = m_windows;
    m_windows.clear();
    for (const QPointer<QWidget>& w : windows)
        delete w.data();
}

} // namespace gf
