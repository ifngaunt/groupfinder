#include "query/alarmwindow.h"

#include <QCheckBox>
#include <QComboBox>
#include <QDialogButtonBox>
#include <QDir>
#include <QFileDialog>
#include <QFileInfo>
#include <QFormLayout>
#include <QHBoxLayout>
#include <QKeyEvent>
#include <QLabel>
#include <QLineEdit>
#include <QPushButton>
#include <QTimer>
#include <QVBoxLayout>
#include <cstring>

#include "gf_alarm.h"
#include "query/groupchecklist.h"
#include "query/querycontroller.h"

namespace gf {

AlarmWindow::AlarmWindow(QueryController* controller, quint64 schid, const QVector<GroupInfo>* preset, QWidget* parent)
    : QDialog(parent), m_c(controller)
{
    setObjectName(QStringLiteral("gfAlarmWindow"));
    setAttribute(Qt::WA_DeleteOnClose);
    setWindowTitle(QStringLiteral("Group Finder — Connect Alarm"));
    setWindowFlag(Qt::WindowContextHelpButtonHint, false);
    resize(560, 560);
    if (preset) {
        for (const GroupInfo& g : *preset)
            m_presetNames << g.name;
        m_usePreset = true;
    }

    m_server = new QComboBox(this);
    m_server->setObjectName(QStringLiteral("gfAlarmServerCombo"));
    m_enabled = new QCheckBox(QStringLiteral("Alarm enabled on this server"), this);
    m_enabled->setObjectName(QStringLiteral("gfAlarmEnabled"));

    m_groups = new GroupChecklist(QStringLiteral("gfAlarmGroup"), this);
    m_unknown = new QLabel(this);
    m_unknown->setWordWrap(true);
    m_unknown->hide();

    m_sound = new QLineEdit(this);
    m_sound->setObjectName(QStringLiteral("gfAlarmSoundEdit"));
    m_sound->setPlaceholderText(QStringLiteral("default sound"));
    m_sound->setClearButtonEnabled(true);
    auto* browse = new QPushButton(QStringLiteral("Browse…"), this);
    auto* test   = new QPushButton(QStringLiteral("Test"), this);
    test->setObjectName(QStringLiteral("gfAlarmTestButton"));
    m_soundNote = new QLabel(this);
    auto* soundRow = new QHBoxLayout;
    soundRow->addWidget(m_sound, 1);
    soundRow->addWidget(browse);
    soundRow->addWidget(test);

    m_preview = new QLabel(this);
    m_preview->setObjectName(QStringLiteral("gfAlarmPreview"));
    m_preview->setWordWrap(true);

    auto* buttons = new QDialogButtonBox(QDialogButtonBox::Save | QDialogButtonBox::Cancel, this);
    m_save = buttons->button(QDialogButtonBox::Save);
    m_save->setObjectName(QStringLiteral("gfAlarmSaveButton"));

    auto* form = new QFormLayout;
    form->addRow(QStringLiteral("Server"), m_server);
    form->addRow(QString(), m_enabled);
    form->addRow(QStringLiteral("Sound"), soundRow);
    form->addRow(QString(), m_soundNote);

    auto* layout = new QVBoxLayout(this);
    layout->addLayout(form);
    layout->addWidget(new QLabel(QStringLiteral("<b>Alert when someone connects who is in <i>all</i> ticked groups</b>"), this));
    layout->addWidget(m_groups, 1);
    layout->addWidget(m_unknown);
    layout->addWidget(m_preview);
    layout->addWidget(buttons);

    connect(m_server, QOverload<int>::of(&QComboBox::currentIndexChanged), this, [this] {
        m_usePreset = false;  // the preset was for the server the window opened with
        loadServer();
    });
    connect(m_groups, &GroupChecklist::tickedChanged, this, &AlarmWindow::updatePreview);
    connect(m_enabled, &QCheckBox::toggled, this, &AlarmWindow::updatePreview);
    connect(m_c, &QueryController::groupsChanged, this, [this](quint64 changed) {
        if (changed == currentSchid())
            applyGroups();
    });
    connect(browse, &QPushButton::clicked, this, &AlarmWindow::browseSound);
    connect(test, &QPushButton::clicked, this, &AlarmWindow::testSound);
    connect(m_sound, &QLineEdit::textChanged, this, [this] { m_soundNote->clear(); });
    connect(buttons, &QDialogButtonBox::accepted, this, &AlarmWindow::save);
    connect(buttons, &QDialogButtonBox::rejected, this, &QDialog::close);

    auto* live = new QTimer(this);
    live->start(3000);
    connect(live, &QTimer::timeout, this, &AlarmWindow::updatePreview);

    // Servers: every connected tab; start on the one asked for.
    m_tabs = ts3::connectedServers();
    {
        QSignalBlocker block(m_server);
        int select = 0;
        for (int i = 0; i < m_tabs.size(); ++i) {
            m_server->addItem(m_tabs[i].name, i);
            if (m_tabs[i].schid == schid)
                select = i;
        }
        m_server->setCurrentIndex(m_tabs.isEmpty() ? -1 : select);
    }
    loadServer();
}

void AlarmWindow::keyPressEvent(QKeyEvent* e)
{
    if (e->key() == Qt::Key_Return || e->key() == Qt::Key_Enter) {
        e->accept();  // saving takes an explicit click on Save
        return;
    }
    QDialog::keyPressEvent(e);
}

quint64 AlarmWindow::currentSchid() const
{
    const int i = m_server->currentData().toInt();
    return (i >= 0 && i < m_tabs.size()) ? m_tabs[i].schid : 0;
}

void AlarmWindow::loadServer()
{
    const quint64 schid = currentSchid();
    if (!schid) {
        m_groups->showMessage(QStringLiteral("Connect to a server first."));
        m_save->setEnabled(false);
        return;
    }
    GfAlarmConfig cfg;
    gf_alarm_get(schid, &cfg);
    m_savedQuery = QString::fromUtf8(cfg.query);
    m_enabled->setChecked(m_usePreset ? true : cfg.enabled != 0);
    m_sound->setText(QDir::toNativeSeparators(QString::fromUtf8(cfg.sound)));
    m_c->ensureGroups(schid);
    applyGroups();
}

void AlarmWindow::applyGroups()
{
    const quint64 schid = currentSchid();
    if (!m_c->hasGroups(schid)) {
        m_groups->showMessage(QStringLiteral("Loading groups…"));
        m_save->setEnabled(false);  // saving now would wipe the stored groups
        updatePreview();
        return;
    }
    const QVector<GroupInfo> groups = m_c->groups(schid);
    m_groups->setGroups(groups);
    QStringList unresolved;
    QStringList names;
    if (m_usePreset) {
        names = m_presetNames;
    } else {
        for (int idx : resolveQuery(m_savedQuery, groups, &unresolved))
            names << groups[idx].name;
    }
    m_groups->setTickedNames(names);
    m_unknown->setVisible(!unresolved.isEmpty());
    m_unknown->setText(QStringLiteral("<i>Not on this server any more, will be removed when you save:</i> %1")
                           .arg(unresolved.join(QStringLiteral(", ")).toHtmlEscaped()));
    m_save->setEnabled(true);
    updatePreview();
}

void AlarmWindow::updatePreview()
{
    const quint64 schid = currentSchid();
    const QVector<GroupInfo> ticked = m_groups->tickedGroups();
    if (!schid || !m_c->hasGroups(schid)) {
        m_preview->clear();
        return;
    }
    if (ticked.isEmpty()) {
        m_preview->setText(QStringLiteral("No groups ticked — the alarm won't fire."));
        return;
    }
    QStringList names;
    for (const OnlineMatch& m : m_c->matching(schid, ticked))
        names << m.client.nickname.toHtmlEscaped();
    QString text = names.isEmpty() ? QStringLiteral("Nobody online right now matches.")
                                   : QStringLiteral("Online right now and matching (%1): %2").arg(names.size()).arg(names.join(QStringLiteral(", ")));
    if (!m_enabled->isChecked())
        text += QStringLiteral("<br><i>The alarm is off — tick “Alarm enabled” to use it.</i>");
    m_preview->setText(text);
}

void AlarmWindow::save()
{
    const quint64 schid = currentSchid();
    if (!schid || !m_c->hasGroups(schid))
        return;
    const QByteArray query = buildQuery(m_groups->tickedGroups()).toUtf8();
    const QByteArray sound = QDir::fromNativeSeparators(m_sound->text().trimmed()).toUtf8();
    GfAlarmConfig cfg{};
    if (query.size() >= int(sizeof(cfg.query)) || sound.size() >= int(sizeof(cfg.sound))) {
        m_preview->setText(QStringLiteral("<b>Too many groups or too long a sound path to save.</b>"));
        return;
    }
    cfg.enabled = m_enabled->isChecked() ? 1 : 0;
    memcpy(cfg.query, query.constData(), size_t(query.size()) + 1);
    memcpy(cfg.sound, sound.constData(), size_t(sound.size()) + 1);
    gf_alarm_set(schid, &cfg);  // saves to this server's file and prints the new status in its tab
    close();
}

void AlarmWindow::browseSound()
{
    const QString current = m_sound->text().trimmed();
    const QString dir     = current.isEmpty() ? QFileInfo(QString::fromUtf8(gf_alarm_default_sound())).absolutePath()
                                              : QFileInfo(current).absolutePath();
    auto* dlg = new QFileDialog(this, QStringLiteral("Choose alarm sound"), dir, QStringLiteral("WAV sounds (*.wav)"));
    dlg->setAttribute(Qt::WA_DeleteOnClose);
    dlg->setFileMode(QFileDialog::ExistingFile);
    connect(dlg, &QFileDialog::fileSelected, this, [this](const QString& file) { m_sound->setText(QDir::toNativeSeparators(file)); });
    dlg->open();  // non-blocking
}

void AlarmWindow::testSound()
{
    const quint64 schid = currentSchid();
    const QByteArray path = QDir::fromNativeSeparators(m_sound->text().trimmed()).toUtf8();
    if (!schid)
        return;
    m_soundNote->setText(gf_alarm_play(schid, path.constData()) ? QString() : QStringLiteral("<i>File not found.</i>"));
}

} // namespace gf
