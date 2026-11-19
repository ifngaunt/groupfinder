#pragma once
// "Meeting starts in m:ss — you will be moved automatically" pop-up with Move now / Don't move me.
#include <QDateTime>
#include <QDialog>

#include "meetings/meeting.h"

class QLabel;
class QTimer;

namespace gf {

class WarnPopup : public QDialog {
    Q_OBJECT
public:
    WarnPopup(const Meeting& m, const QDateTime& startUtc, QWidget* parent = nullptr);

signals:
    void moveNowClicked();
    void dontMoveClicked();

protected:
    void showEvent(QShowEvent* e) override;

private:
    void updateCountdown();

    QDateTime m_startUtc;
    QLabel*   m_countdown = nullptr;
    QTimer*   m_timer     = nullptr;
};

} // namespace gf
