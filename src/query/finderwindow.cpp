#include "query/finderwindow.h"

#include <QComboBox>
#include <QFormLayout>
#include <QHBoxLayout>
#include <QHeaderView>
#include <QLabel>
#include <QPushButton>
#include <QSplitter>
#include <QTableWidget>
#include <QTimer>
#include <QVBoxLayout>

#include "query/groupchecklist.h"
#include "query/querycontroller.h"

namespace gf {

FinderWindow::FinderWindow(QueryController* controller, QWidget* parent) : QDialog(parent), m_c(controller)
{
    setObjectName(QStringLiteral("gfFinderWindow"));
    setAttribute(Qt::WA_DeleteOnClose);
    setWindowTitle(QStringLiteral("Group Finder — Find Users"));
    setWindowFlag(Qt::WindowContextHelpButtonHint, false);
    setWindowFlag(Qt::WindowMaximizeButtonHint, true);
    resize(820, 480);

    m_server = new QComboBox(this);
    m_server->setObjectName(QStringLiteral("gfFinderServerCombo"));

    m_groups = new GroupChecklist(QStringLiteral("gfGroup"), this);
    auto* groupsBox = new QWidget(this);
    auto* groupsLayout = new QVBoxLayout(groupsBox);
    groupsLayout->setContentsMargins(0, 0, 0, 0);
    groupsLayout->addWidget(new QLabel(QStringLiteral("<b>Groups</b> — users must be in <i>all</i> ticked groups"), groupsBox));
    groupsLayout->addWidget(m_groups, 1);

    m_results = new QTableWidget(0, 2, this);
    m_results->setObjectName(QStringLiteral("gfResultTable"));
    m_results->setHorizontalHeaderLabels({QStringLiteral("Online user"), QStringLiteral("Channel")});
    m_results->verticalHeader()->hide();
    m_results->setEditTriggers(QAbstractItemView::NoEditTriggers);
    m_results->setSelectionBehavior(QAbstractItemView::SelectRows);
    m_results->setAlternatingRowColors(true);
    m_results->setShowGrid(false);
    m_results->setSortingEnabled(false);
    m_results->horizontalHeader()->setSectionResizeMode(0, QHeaderView::ResizeToContents);
    m_results->horizontalHeader()->setSectionResizeMode(1, QHeaderView::Stretch);
    m_count = new QLabel(this);
    m_count->setObjectName(QStringLiteral("gfResultCount"));
    auto* resultsBox = new QWidget(this);
    auto* resultsLayout = new QVBoxLayout(resultsBox);
    resultsLayout->setContentsMargins(0, 0, 0, 0);
    resultsLayout->addWidget(m_count);
    resultsLayout->addWidget(m_results, 1);

    auto* split = new QSplitter(Qt::Horizontal, this);
    split->addWidget(groupsBox);
    split->addWidget(resultsBox);
    split->setStretchFactor(0, 2);
    split->setStretchFactor(1, 3);
    split->setChildrenCollapsible(false);

    m_chat    = new QPushButton(QStringLiteral("Show in chat"), this);
    m_toAlarm = new QPushButton(QStringLiteral("Set as connect alarm…"), this);
    auto* close = new QPushButton(QStringLiteral("Close"), this);
    m_chat->setObjectName(QStringLiteral("gfShowInChatButton"));
    m_toAlarm->setObjectName(QStringLiteral("gfUseAsAlarmButton"));
    m_chat->setToolTip(QStringLiteral("Print the results as clickable names in this server's chat tab"));
    // With groups ticked: make them this server's alarm. With none ticked: open the saved alarm as it is.
    auto* buttons = new QHBoxLayout;
    buttons->addWidget(m_chat);
    buttons->addWidget(m_toAlarm);
    buttons->addStretch(1);
    buttons->addWidget(close);

    auto* top = new QFormLayout;
    top->addRow(QStringLiteral("Server"), m_server);
    auto* layout = new QVBoxLayout(this);
    layout->addLayout(top);
    layout->addWidget(split, 1);
    layout->addLayout(buttons);

    connect(m_server, QOverload<int>::of(&QComboBox::currentIndexChanged), this, &FinderWindow::onServerChanged);
    connect(m_groups, &GroupChecklist::tickedChanged, this, &FinderWindow::refreshResults);
    connect(m_c, &QueryController::groupsChanged, this, [this](quint64 schid) {
        if (schid == currentSchid())
            refillGroups();
    });
    connect(m_chat, &QPushButton::clicked, this, &FinderWindow::showInChat);
    connect(m_toAlarm, &QPushButton::clicked, this, [this] {
        const QVector<GroupInfo> ticked = m_groups->tickedGroups();
        m_c->openAlarm(currentSchid(), ticked.isEmpty() ? nullptr : &ticked);
    });
    connect(close, &QPushButton::clicked, this, &QDialog::close);

    auto* live = new QTimer(this);  // people join, leave and move around
    live->start(3000);
    connect(live, &QTimer::timeout, this, &FinderWindow::refreshResults);

    fillServers();
}

quint64 FinderWindow::currentSchid() const
{
    const int i = m_server->currentData().toInt();
    return (i >= 0 && i < m_tabs.size()) ? m_tabs[i].schid : 0;
}

void FinderWindow::fillServers()
{
    m_tabs = ts3::connectedServers();
    const quint64 current = ts3::currentServer();
    QSignalBlocker block(m_server);
    m_server->clear();
    int select = 0;
    for (int i = 0; i < m_tabs.size(); ++i) {
        m_server->addItem(m_tabs[i].name, i);
        if (m_tabs[i].schid == current)
            select = i;
    }
    m_server->setCurrentIndex(m_tabs.isEmpty() ? -1 : select);
    block.unblock();
    onServerChanged();
}

void FinderWindow::onServerChanged()
{
    const quint64 schid = currentSchid();
    if (!schid) {
        m_groups->showMessage(QStringLiteral("Connect to a server first."));
    } else {
        m_c->ensureGroups(schid);
        refillGroups();
    }
    refreshResults();
}

void FinderWindow::refillGroups()
{
    const quint64 schid = currentSchid();
    if (!schid)
        return;
    if (m_c->hasGroups(schid))
        m_groups->setGroups(m_c->groups(schid));
    else
        m_groups->showMessage(QStringLiteral("Loading groups…"));
}

void FinderWindow::refreshResults()
{
    const QVector<GroupInfo> ticked = m_groups->tickedGroups();
    const auto matches = m_c->matching(currentSchid(), ticked);
    m_results->setRowCount(matches.size());
    for (int row = 0; row < matches.size(); ++row) {
        m_results->setItem(row, 0, new QTableWidgetItem(matches[row].client.nickname));
        m_results->setItem(row, 1, new QTableWidgetItem(matches[row].channel));
    }
    if (ticked.isEmpty())
        m_count->setText(QStringLiteral("Tick one or more groups on the left."));
    else
        m_count->setText(QStringLiteral("<b>%1</b> online user%2 in %3")
                             .arg(matches.size())
                             .arg(matches.size() == 1 ? QString() : QStringLiteral("s"))
                             .arg(m_groups->tickedNames().join(QStringLiteral(" + ")).toHtmlEscaped()));
    m_chat->setEnabled(!matches.isEmpty());
    m_toAlarm->setEnabled(currentSchid() != 0);
    m_toAlarm->setText(ticked.isEmpty() ? QStringLiteral("Connect alarm settings…") : QStringLiteral("Set as connect alarm…"));
    m_toAlarm->setToolTip(ticked.isEmpty() ? QStringLiteral("View or change this server's connect alarm")
                                           : QStringLiteral("Play a sound whenever someone in all ticked groups connects to this server"));
}

void FinderWindow::showInChat()
{
    const quint64 schid = currentSchid();
    const auto matches  = m_c->matching(schid, m_groups->tickedGroups());
    ts3::print(schid, QStringLiteral("Found %1 user(s) in %2:")
                          .arg(matches.size())
                          .arg(m_groups->tickedNames().join(QStringLiteral(" + "))));
    for (const OnlineMatch& m : matches)
        ts3::print(schid, QStringLiteral("[URL=client://%1/%2]%3[/URL]  —  %4")
                              .arg(m.client.clid)
                              .arg(m.client.uid, m.client.nickname, m.channel));
}

} // namespace gf
