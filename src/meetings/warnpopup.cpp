#include "meetings/warnpopup.h"

#include <QApplication>
#include <QHBoxLayout>
#include <QLabel>
#include <QPushButton>
#include <QTimer>
#include <QVBoxLayout>

namespace gf {

WarnPopup::WarnPopup(const Meeting& m, const QDateTime& startUtc, QWidget* parent)
    : QDialog(parent, Qt::Dialog | Qt::WindowStaysOnTopHint | Qt::WindowTitleHint | Qt::WindowCloseButtonHint),
      m_startUtc(startUtc)
{
    setObjectName(QStringLiteral("gfWarnPopup"));
    setAttribute(Qt::WA_DeleteOnClose);
    setWindowTitle(QStringLiteral("Meeting starting soon"));

    auto* title = new QLabel(m.name.toHtmlEscaped(), this);
    QFont tf = title->font();
    tf.setPointSizeF(tf.pointSizeF() * 1.35);
    tf.setBold(true);
    title->setFont(tf);

    m_countdown = new QLabel(this);
    m_countdown->setObjectName(QStringLiteral("gfCountdownLabel"));
    QFont cf = m_countdown->font();
    cf.setPointSizeF(cf.pointSizeF() * 2.0);
    m_countdown->setFont(cf);

    auto* where = new QLabel(QStringLiteral("Channel <b>%1</b> &middot; %2")
                                 .arg(channelDisplayName(m).toHtmlEscaped(), m.serverName.toHtmlEscaped()),
                             this);
    auto* hint = new QLabel(QStringLiteral("You will be moved automatically when the countdown ends."), this);
    hint->setWordWrap(true);

    auto* moveNow  = new QPushButton(QStringLiteral("Move now"), this);
    auto* dontMove = new QPushButton(QStringLiteral("Don't move me"), this);
    moveNow->setObjectName(QStringLiteral("gfMoveNowButton"));
    dontMove->setObjectName(QStringLiteral("gfDontMoveButton"));
    moveNow->setDefault(true);
    connect(moveNow, &QPushButton::clicked, this, [this] { emit moveNowClicked(); });
    connect(dontMove, &QPushButton::clicked, this, [this] { emit dontMoveClicked(); });

    auto* buttons = new QHBoxLayout;
    buttons->addStretch(1);
    buttons->addWidget(dontMove);
    buttons->addWidget(moveNow);

    auto* layout = new QVBoxLayout(this);
    layout->setContentsMargins(20, 16, 20, 16);
    layout->setSpacing(6);
    layout->addWidget(title);
    layout->addWidget(new QLabel(QStringLiteral("starts in"), this));
    layout->addWidget(m_countdown);
    layout->addWidget(where);
    layout->addSpacing(6);
    layout->addWidget(hint);
    layout->addSpacing(8);
    layout->addLayout(buttons);
    setMinimumWidth(340);

    m_timer = new QTimer(this);
    m_timer->setInterval(250);
    connect(m_timer, &QTimer::timeout, this, &WarnPopup::updateCountdown);
    m_timer->start();
    updateCountdown();
}

void WarnPopup::showEvent(QShowEvent* e)
{
    QDialog::showEvent(e);
    QApplication::alert(this);  // flash the taskbar entry if TeamSpeak is in the background
}

void WarnPopup::updateCountdown()
{
    const qint64 secs = QDateTime::currentDateTimeUtc().secsTo(m_startUtc);
    m_countdown->setText(secs > 0 ? QStringLiteral("%1:%2").arg(secs / 60).arg(secs % 60, 2, 10, QLatin1Char('0'))
                                  : QStringLiteral("now"));
}

} // namespace gf
