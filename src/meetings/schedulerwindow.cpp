#include "meetings/schedulerwindow.h"

#include <QHBoxLayout>
#include <QHeaderView>
#include <QLabel>
#include <QLocale>
#include <QMessageBox>
#include <QPushButton>
#include <QTableWidget>
#include <QTimer>
#include <QTimeZone>
#include <QVBoxLayout>

#include "meetings/meetingcontroller.h"

namespace gf {

namespace {
enum Column { ColOn, ColName, ColServer, ColChannel, ColRepeats, ColNext, ColCount };

QString nextText(const Meeting& m, const QDateTime& nextUtc)
{
    if (!m.enabled)
        return QStringLiteral("off");
    if (!nextUtc.isValid())
        return QStringLiteral("—");
    const qint64 secs = QDateTime::currentDateTimeUtc().secsTo(nextUtc);
    const QString in  = secs < 3600        ? QStringLiteral("in %1 min").arg(std::max<qint64>(1, secs / 60))
                        : secs < 36 * 3600 ? QStringLiteral("in %1 h").arg((secs + 1800) / 3600)
                                           : QStringLiteral("in %1 d").arg((secs + 43200) / 86400);
    return QStringLiteral("%1  ·  %2").arg(QLocale::system().toString(nextUtc.toLocalTime(), QStringLiteral("ddd d MMM, HH:mm")), in);
}

QString repeatText(const Meeting& m)
{
    QString t = describeRepeat(m.schedule) + QStringLiteral(" at ") + m.schedule.time.toString(QStringLiteral("HH:mm"));
    if (scheduleZone(m.schedule) != QTimeZone::systemTimeZone())
        t += QStringLiteral(" (%1)").arg(QString::fromUtf8(m.schedule.timeZoneId));
    if (m.action == Action::WarnThenMove)
        t += QStringLiteral(", warn %1 min").arg(m.warnMinutes);
    return t;
}
} // namespace

SchedulerWindow::SchedulerWindow(MeetingController* controller, QWidget* parent) : QDialog(parent), m_c(controller)
{
    setObjectName(QStringLiteral("gfSchedulerWindow"));
    setAttribute(Qt::WA_DeleteOnClose);
    setWindowTitle(QStringLiteral("Group Finder — Meetings"));
    setWindowFlag(Qt::WindowContextHelpButtonHint, false);
    resize(980, 400);

    auto* intro = new QLabel(QStringLiteral("At each meeting's start you are moved into its channel — or connected to its server in a new tab. "
                                            "Times are shown in your local time."),
                             this);
    intro->setWordWrap(true);

    m_table = new QTableWidget(0, ColCount, this);
    m_table->setObjectName(QStringLiteral("gfMeetingTable"));
    m_table->setHorizontalHeaderLabels({QStringLiteral("On"), QStringLiteral("Meeting"), QStringLiteral("Server"),
                                        QStringLiteral("Channel"), QStringLiteral("Repeats"), QStringLiteral("Next start")});
    m_table->verticalHeader()->hide();
    m_table->setSelectionBehavior(QAbstractItemView::SelectRows);
    m_table->setSelectionMode(QAbstractItemView::SingleSelection);
    m_table->setEditTriggers(QAbstractItemView::NoEditTriggers);
    m_table->setAlternatingRowColors(true);
    m_table->setShowGrid(false);
    m_table->setWordWrap(false);
    auto* header = m_table->horizontalHeader();
    header->setSectionResizeMode(QHeaderView::ResizeToContents);
    header->setSectionResizeMode(ColName, QHeaderView::Stretch);
    header->setHighlightSections(false);

    m_empty = new QLabel(QStringLiteral("No meetings yet. Right-click a channel and choose <b>Add meeting here…</b>, or click <b>Add…</b>."), this);
    m_empty->setObjectName(QStringLiteral("gfEmptyLabel"));
    m_empty->setAlignment(Qt::AlignCenter);
    m_empty->setWordWrap(true);

    auto* add = new QPushButton(QStringLiteral("Add…"), this);
    m_edit    = new QPushButton(QStringLiteral("Edit…"), this);
    m_remove  = new QPushButton(QStringLiteral("Remove"), this);
    m_join    = new QPushButton(QStringLiteral("Join now"), this);
    auto* close = new QPushButton(QStringLiteral("Close"), this);
    add->setObjectName(QStringLiteral("gfAddButton"));
    close->setObjectName(QStringLiteral("gfCloseButton"));
    m_edit->setObjectName(QStringLiteral("gfEditButton"));
    m_remove->setObjectName(QStringLiteral("gfRemoveButton"));
    m_join->setObjectName(QStringLiteral("gfJoinNowButton"));
    m_join->setToolTip(QStringLiteral("Move to (or connect to) this meeting's channel right now"));

    auto* buttons = new QHBoxLayout;
    buttons->addWidget(add);
    buttons->addWidget(m_edit);
    buttons->addWidget(m_remove);
    buttons->addStretch(1);
    buttons->addWidget(m_join);
    buttons->addWidget(close);

    auto* layout = new QVBoxLayout(this);
    layout->addWidget(intro);
    layout->addWidget(m_table, 1);
    layout->addWidget(m_empty, 1);
    layout->addLayout(buttons);

    connect(add, &QPushButton::clicked, m_c, &MeetingController::addMeetingFromCurrentTab);
    connect(m_edit, &QPushButton::clicked, this, [this] { m_c->editMeeting(selectedId()); });
    connect(m_table, &QTableWidget::cellDoubleClicked, this, [this] { m_c->editMeeting(selectedId()); });
    connect(m_remove, &QPushButton::clicked, this, &SchedulerWindow::confirmRemove);
    connect(m_join, &QPushButton::clicked, this, [this] { m_c->executeNow(selectedId()); });
    connect(close, &QPushButton::clicked, this, &QDialog::close);
    connect(m_table, &QTableWidget::itemSelectionChanged, this, &SchedulerWindow::updateButtons);
    connect(m_table, &QTableWidget::itemChanged, this, [this](QTableWidgetItem* item) {
        if (item->column() != ColOn)
            return;
        for (Meeting m : m_c->meetings())
            if (m.id == item->data(Qt::UserRole).toString() && m.enabled != (item->checkState() == Qt::Checked)) {
                m.enabled = item->checkState() == Qt::Checked;
                m_c->upsertMeeting(m);
                return;
            }
    });
    connect(m_c, &MeetingController::meetingsChanged, this, &SchedulerWindow::refresh);

    auto* clock = new QTimer(this);  // keeps "in N min" current
    clock->start(30 * 1000);
    connect(clock, &QTimer::timeout, this, &SchedulerWindow::refresh);

    refresh();
}

void SchedulerWindow::refresh()
{
    const QString keep = selectedId();
    QSignalBlocker block(m_table);
    const auto& meetings = m_c->meetings();
    m_table->setRowCount(meetings.size());
    for (int row = 0; row < meetings.size(); ++row) {
        const Meeting& m = meetings[row];
        auto* on = new QTableWidgetItem;
        on->setFlags(Qt::ItemIsEnabled | Qt::ItemIsSelectable | Qt::ItemIsUserCheckable);
        on->setCheckState(m.enabled ? Qt::Checked : Qt::Unchecked);
        on->setData(Qt::UserRole, m.id);
        m_table->setItem(row, ColOn, on);
        const QStringList cells{m.name, m.serverName, channelDisplayName(m), repeatText(m), nextText(m, m_c->nextStart(m.id))};
        for (int col = ColName; col < ColCount; ++col) {
            auto* item = new QTableWidgetItem(cells[col - ColName]);
            item->setFlags(Qt::ItemIsEnabled | Qt::ItemIsSelectable);
            if (col == ColChannel)
                item->setToolTip(m.channelPath);
            if (!m.enabled)
                item->setForeground(palette().brush(QPalette::Disabled, QPalette::Text));
            m_table->setItem(row, col, item);
        }
        if (m.id == keep)
            m_table->selectRow(row);
    }
    m_table->setVisible(!meetings.isEmpty());
    m_empty->setVisible(meetings.isEmpty());
    block.unblock();
    updateButtons();
}

QString SchedulerWindow::selectedId() const
{
    const auto rows = m_table->selectionModel() ? m_table->selectionModel()->selectedRows() : QModelIndexList();
    if (rows.isEmpty())
        return QString();
    const QTableWidgetItem* on = m_table->item(rows.first().row(), ColOn);
    return on ? on->data(Qt::UserRole).toString() : QString();
}

void SchedulerWindow::updateButtons()
{
    const bool has = !selectedId().isEmpty();
    m_edit->setEnabled(has);
    m_remove->setEnabled(has);
    m_join->setEnabled(has);
}

void SchedulerWindow::confirmRemove()
{
    const QString id = selectedId();
    QString name;
    for (const Meeting& m : m_c->meetings())
        if (m.id == id)
            name = m.name;
    if (id.isEmpty())
        return;
    auto* box = new QMessageBox(QMessageBox::Question, QStringLiteral("Remove meeting"),
                                QStringLiteral("Remove \"%1\"?").arg(name), QMessageBox::Yes | QMessageBox::No, this);
    box->setAttribute(Qt::WA_DeleteOnClose);
    box->setAttribute(Qt::WA_QuitOnClose, false);
    connect(box, &QMessageBox::finished, this, [this, id](int result) {
        if (result == QMessageBox::Yes)
            m_c->removeMeeting(id);
    });
    box->open();
}

} // namespace gf
