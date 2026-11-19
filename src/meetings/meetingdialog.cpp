#include "meetings/meetingdialog.h"

#include <QCheckBox>
#include <QComboBox>
#include <QDateEdit>
#include <QDialogButtonBox>
#include <QFormLayout>
#include <QGroupBox>
#include <QHBoxLayout>
#include <QLabel>
#include <QLineEdit>
#include <QLocale>
#include <QPushButton>
#include <QRadioButton>
#include <QSpinBox>
#include <QTimeEdit>
#include <QTimeZone>
#include <QVBoxLayout>
#include <algorithm>

namespace gf {

namespace {
constexpr int kPathRole = Qt::UserRole + 1;

// "Europe/Berlin (UTC+01:00)" for every zone Qt knows; built once per session.
const QVector<QPair<QByteArray, QString>>& zoneList()
{
    static QVector<QPair<QByteArray, QString>> zones;
    if (zones.isEmpty()) {
        const QDateTime now = QDateTime::currentDateTimeUtc();
        QList<QByteArray> ids = QTimeZone::availableTimeZoneIds();
        std::sort(ids.begin(), ids.end());
        for (const QByteArray& id : ids) {
            const int off = QTimeZone(id).offsetFromUtc(now);
            const QString sign = off < 0 ? QStringLiteral("-") : QStringLiteral("+");
            zones.append({id, QStringLiteral("%1  (UTC%2%3:%4)")
                                  .arg(QString::fromUtf8(id), sign)
                                  .arg(qAbs(off) / 3600, 2, 10, QLatin1Char('0'))
                                  .arg((qAbs(off) % 3600) / 60, 2, 10, QLatin1Char('0'))});
        }
    }
    return zones;
}

QString relative(qint64 secs)
{
    if (secs < 90)
        return QStringLiteral("in %1 s").arg(secs);
    if (secs < 90 * 60)
        return QStringLiteral("in %1 min").arg(secs / 60);
    if (secs < 36 * 3600)
        return QStringLiteral("in %1 h").arg((secs + 1800) / 3600);
    return QStringLiteral("in %1 days").arg((secs + 43200) / 86400);
}
} // namespace

MeetingDialog::MeetingDialog(const Meeting& initial, bool isNew, QWidget* parent) : QDialog(parent), m_initial(initial)
{
    setObjectName(QStringLiteral("gfMeetingDialog"));
    setAttribute(Qt::WA_DeleteOnClose);
    setWindowTitle(isNew ? QStringLiteral("Add meeting") : QStringLiteral("Edit meeting"));

    // ---- Where
    m_name = new QLineEdit(initial.name, this);
    m_name->setObjectName(QStringLiteral("gfNameEdit"));
    m_name->setPlaceholderText(QStringLiteral("e.g. Weekly op"));
    m_server = new QComboBox(this);
    m_server->setObjectName(QStringLiteral("gfServerCombo"));
    m_channel = new QComboBox(this);
    m_channel->setObjectName(QStringLiteral("gfChannelCombo"));
    m_channel->setMinimumContentsLength(28);
    m_channelPw = new QLineEdit(initial.channelPassword, this);
    m_channelPw->setObjectName(QStringLiteral("gfChannelPwEdit"));
    m_channelPw->setEchoMode(QLineEdit::Password);
    m_channelPw->setPlaceholderText(QStringLiteral("only if the channel has one"));
    m_nickname = new QLineEdit(initial.nickname, this);
    m_nickname->setObjectName(QStringLiteral("gfNicknameEdit"));
    m_nickname->setPlaceholderText(QStringLiteral("used when a new connection is opened"));

    auto* where = new QGroupBox(QStringLiteral("Where"), this);
    auto* whereForm = new QFormLayout(where);
    whereForm->addRow(QStringLiteral("Name"), m_name);
    whereForm->addRow(QStringLiteral("Server"), m_server);
    whereForm->addRow(QStringLiteral("Channel"), m_channel);
    whereForm->addRow(QStringLiteral("Channel password"), m_channelPw);
    whereForm->addRow(QStringLiteral("Nickname"), m_nickname);

    // ---- When
    const Schedule& s = initial.schedule;
    m_date = new QDateEdit(s.startDate.isValid() ? s.startDate : QDate::currentDate(), this);
    m_date->setObjectName(QStringLiteral("gfDateEdit"));
    m_date->setCalendarPopup(true);
    m_date->setDisplayFormat(QStringLiteral("ddd dd MMM yyyy"));
    m_time = new QTimeEdit(s.time.isValid() ? s.time : QTime(20, 0), this);
    m_time->setObjectName(QStringLiteral("gfTimeEdit"));
    m_time->setDisplayFormat(QStringLiteral("HH:mm"));
    m_zone = new QComboBox(this);
    m_zone->setObjectName(QStringLiteral("gfZoneCombo"));
    for (const auto& z : zoneList())
        m_zone->addItem(z.second, z.first);
    // Show the zone the meeting actually runs in: unknown ids run on the system zone (see scheduleZone),
    // valid ids Qt didn't list are added. Never fall back to the first list entry.
    const QByteArray zoneId = scheduleZone(s).id();
    int zoneIndex = m_zone->findData(zoneId);
    if (zoneIndex < 0) {
        m_zone->insertItem(0, QString::fromUtf8(zoneId), zoneId);
        zoneIndex = 0;
    }
    m_zone->setCurrentIndex(zoneIndex);

    m_repeat = new QComboBox(this);
    m_repeat->setObjectName(QStringLiteral("gfRepeatCombo"));
    m_repeat->addItem(QStringLiteral("Once"), int(Repeat::Once));
    m_repeat->addItem(QStringLiteral("Daily"), int(Repeat::Daily));
    m_repeat->addItem(QStringLiteral("Weekly"), int(Repeat::Weekly));
    m_repeat->addItem(QStringLiteral("Monthly"), int(Repeat::Monthly));
    m_repeat->setCurrentIndex(m_repeat->findData(int(s.repeat)));

    m_interval = new QSpinBox(this);
    m_interval->setObjectName(QStringLiteral("gfIntervalSpin"));
    m_interval->setRange(1, 52);
    m_interval->setValue(std::max(1, s.interval));
    m_unit = new QLabel(this);
    m_everyRow = new QWidget(this);
    auto* everyLayout = new QHBoxLayout(m_everyRow);
    everyLayout->setContentsMargins(0, 0, 0, 0);
    everyLayout->addWidget(new QLabel(QStringLiteral("every"), m_everyRow));
    everyLayout->addWidget(m_interval);
    everyLayout->addWidget(m_unit);
    everyLayout->addStretch(1);

    m_daysRow = new QWidget(this);
    auto* daysLayout = new QHBoxLayout(m_daysRow);
    daysLayout->setContentsMargins(0, 0, 0, 0);
    for (int i = 0; i < 7; ++i) {
        m_days[i] = new QCheckBox(QLocale::system().dayName(i + 1, QLocale::ShortFormat), m_daysRow);
        m_days[i]->setObjectName(QStringLiteral("gfDay%1").arg(i + 1));
        m_days[i]->setChecked(s.weekdays & (1u << i));
        daysLayout->addWidget(m_days[i]);
    }
    daysLayout->addStretch(1);

    auto* dateTime = new QHBoxLayout;
    dateTime->addWidget(m_date, 1);
    dateTime->addWidget(m_time);
    auto* repeatRow = new QHBoxLayout;
    repeatRow->addWidget(m_repeat);
    repeatRow->addWidget(m_everyRow, 1);

    auto* when = new QGroupBox(QStringLiteral("When"), this);
    auto* whenForm = new QFormLayout(when);
    whenForm->addRow(QStringLiteral("Starts"), dateTime);
    whenForm->addRow(QStringLiteral("Time zone"), m_zone);
    whenForm->addRow(QStringLiteral("Repeat"), repeatRow);
    whenForm->addRow(QString(), m_daysRow);

    // ---- At start
    m_moveRadio = new QRadioButton(QStringLiteral("Move me into the channel automatically"), this);
    m_moveRadio->setObjectName(QStringLiteral("gfMoveRadio"));
    m_warnRadio = new QRadioButton(QStringLiteral("Warn me first, then move me unless I cancel"), this);
    m_warnRadio->setObjectName(QStringLiteral("gfWarnRadio"));
    m_warn = new QSpinBox(this);
    m_warn->setObjectName(QStringLiteral("gfWarnSpin"));
    m_warn->setRange(1, 60);
    m_warn->setValue(initial.warnMinutes);
    m_warn->setSuffix(QStringLiteral(" min before"));
    (initial.action == Action::WarnThenMove ? m_warnRadio : m_moveRadio)->setChecked(true);
    auto* warnRow = new QHBoxLayout;
    warnRow->addWidget(m_warnRadio);
    warnRow->addWidget(m_warn);
    warnRow->addStretch(1);
    m_enabled = new QCheckBox(QStringLiteral("Enabled"), this);
    m_enabled->setObjectName(QStringLiteral("gfEnabledCheck"));
    m_enabled->setChecked(initial.enabled);

    auto* atStart = new QGroupBox(QStringLiteral("At start"), this);
    auto* atStartLayout = new QVBoxLayout(atStart);
    atStartLayout->addWidget(m_moveRadio);
    atStartLayout->addLayout(warnRow);
    atStartLayout->addWidget(m_enabled);

    // ---- Preview + buttons
    m_preview = new QLabel(this);
    m_preview->setObjectName(QStringLiteral("gfPreviewLabel"));
    m_preview->setWordWrap(true);
    auto* buttons = new QDialogButtonBox(QDialogButtonBox::Save | QDialogButtonBox::Cancel, this);
    m_save = buttons->button(QDialogButtonBox::Save);
    m_save->setObjectName(QStringLiteral("gfSaveButton"));
    connect(buttons, &QDialogButtonBox::accepted, this, &QDialog::accept);
    connect(buttons, &QDialogButtonBox::rejected, this, &QDialog::reject);

    auto* layout = new QVBoxLayout(this);
    layout->addWidget(where);
    layout->addWidget(when);
    layout->addWidget(atStart);
    layout->addWidget(m_preview);
    layout->addWidget(buttons);

    // ---- Behaviour
    connect(m_server, QOverload<int>::of(&QComboBox::currentIndexChanged), this, &MeetingDialog::onServerChanged);
    connect(m_channel, QOverload<int>::of(&QComboBox::currentIndexChanged), this, &MeetingDialog::onChannelChanged);
    connect(m_repeat, QOverload<int>::of(&QComboBox::currentIndexChanged), this, &MeetingDialog::onRepeatChanged);
    connect(m_name, &QLineEdit::textChanged, this, &MeetingDialog::updatePreview);
    connect(m_date, &QDateEdit::dateChanged, this, &MeetingDialog::updatePreview);
    connect(m_time, &QTimeEdit::timeChanged, this, &MeetingDialog::updatePreview);
    connect(m_zone, QOverload<int>::of(&QComboBox::currentIndexChanged), this, &MeetingDialog::updatePreview);
    connect(m_interval, QOverload<int>::of(&QSpinBox::valueChanged), this, &MeetingDialog::onRepeatChanged);
    for (QCheckBox* d : m_days)
        connect(d, &QCheckBox::toggled, this, &MeetingDialog::updatePreview);
    connect(m_warnRadio, &QRadioButton::toggled, m_warn, &QWidget::setEnabled);
    connect(m_enabled, &QCheckBox::toggled, this, &MeetingDialog::updatePreview);
    m_warn->setEnabled(m_warnRadio->isChecked());

    fillServers();
    onRepeatChanged();
    m_name->setFocus();
    m_name->selectAll();
}

void MeetingDialog::fillServers()
{
    m_tabs = ts3::connectedServers();
    QSignalBlocker block(m_server);
    m_server->clear();
    int select = -1;
    for (int i = 0; i < m_tabs.size(); ++i) {
        const auto& t = m_tabs[i];
        m_server->addItem(QStringLiteral("%1  (%2:%3)").arg(t.name, t.host).arg(t.port), i);
        const bool same = !m_initial.serverUid.isEmpty() ? t.uid == m_initial.serverUid
                                                         : (t.host.compare(m_initial.host, Qt::CaseInsensitive) == 0 && t.port == m_initial.port);
        if (same && select < 0)
            select = i;
    }
    if (select < 0 && (!m_initial.serverUid.isEmpty() || !m_initial.host.isEmpty())) {
        m_server->insertItem(0, QStringLiteral("%1  (%2:%3) — not connected").arg(m_initial.serverName, m_initial.host).arg(m_initial.port), -1);
        select = 0;
    }
    m_server->setCurrentIndex(std::max(0, select));
    block.unblock();
    onServerChanged();
}

void MeetingDialog::onServerChanged()
{
    QSignalBlocker block(m_channel);
    m_channel->clear();
    const int tab = m_server->currentData().toInt();
    if (m_server->currentIndex() < 0) {
        // nothing connected and nothing saved
    } else if (tab < 0) {  // saved server that isn't connected: keep the stored channel
        m_channel->addItem(m_initial.channelPath.isEmpty() ? channelDisplayName(m_initial) : m_initial.channelPath,
                           QVariant::fromValue<qulonglong>(m_initial.channelId));
        m_channel->setItemData(0, m_initial.channelPath, kPathRole);
    } else {
        const quint64 schid = m_tabs[tab].schid;
        const quint64 own   = ts3::ownChannel(schid);
        int byId = -1, byPath = -1, byOwn = -1;
        for (const auto& c : ts3::channels(schid)) {
            m_channel->addItem(QString(c.depth * 4, QLatin1Char(' ')) + c.name, QVariant::fromValue<qulonglong>(c.id));
            const int row = m_channel->count() - 1;
            m_channel->setItemData(row, c.path, kPathRole);
            if (c.id == m_initial.channelId)
                byId = row;
            if (!m_initial.channelPath.isEmpty() && c.path == m_initial.channelPath)
                byPath = row;
            if (c.id == own)
                byOwn = row;
        }
        m_channel->setCurrentIndex(byPath >= 0 ? byPath : byId >= 0 ? byId : byOwn >= 0 ? byOwn : 0);
        if (m_nickname->text().isEmpty())
            m_nickname->setText(m_tabs[tab].nickname);
    }
    block.unblock();
    onChannelChanged();
}

void MeetingDialog::onChannelChanged()
{
    const int tab = m_server->currentData().toInt();
    if (tab >= 0 && tab < m_tabs.size() && m_channelPw->text().isEmpty() && m_channel->currentIndex() >= 0)
        m_channelPw->setText(ts3::channelPassword(m_tabs[tab].schid, m_channel->currentData().toULongLong()));
    updatePreview();
}

void MeetingDialog::onRepeatChanged()
{
    const auto r = Repeat(m_repeat->currentData().toInt());
    const bool plural = m_interval->value() > 1;
    m_everyRow->setVisible(r != Repeat::Once);
    m_daysRow->setVisible(r == Repeat::Weekly);
    m_unit->setText(r == Repeat::Daily ? (plural ? QStringLiteral("days") : QStringLiteral("day"))
                    : r == Repeat::Weekly ? (plural ? QStringLiteral("weeks") : QStringLiteral("week"))
                                          : (plural ? QStringLiteral("months") : QStringLiteral("month")));
    if (r == Repeat::Weekly && std::none_of(std::begin(m_days), std::end(m_days), [](QCheckBox* d) { return d->isChecked(); }))
        m_days[m_date->date().dayOfWeek() - 1]->setChecked(true);
    updatePreview();
}

Schedule MeetingDialog::currentSchedule() const
{
    Schedule s;
    s.startDate  = m_date->date();
    s.time       = m_time->time();
    s.timeZoneId = m_zone->currentData().toByteArray();
    s.repeat     = Repeat(m_repeat->currentData().toInt());
    s.interval   = m_interval->value();
    for (int i = 0; i < 7; ++i)
        if (m_days[i]->isChecked())
            s.weekdays |= quint8(1u << i);
    return s;
}

void MeetingDialog::updatePreview()
{
    const Schedule s = currentSchedule();
    QString text;
    bool ok = isValid(s);
    if (!ok) {
        text = s.repeat == Repeat::Weekly ? QStringLiteral("Pick at least one weekday.") : QStringLiteral("The date or time is incomplete.");
    } else {
        const QDateTime now  = QDateTime::currentDateTimeUtc();
        const QDateTime next = nextOccurrence(s, now);
        if (!next.isValid()) {
            text = QStringLiteral("This date is in the past — the meeting will not run.");
        } else {
            const QDateTime local = next.toLocalTime();
            text = QStringLiteral("Next: <b>%1</b> your time (%2)")
                       .arg(QLocale::system().toString(local, QStringLiteral("dddd d MMM yyyy, HH:mm")), relative(now.secsTo(next)));
            if (scheduleZone(s) != QTimeZone::systemTimeZone())
                text += QStringLiteral(" — %1 in %2").arg(next.toTimeZone(scheduleZone(s)).toString(QStringLiteral("HH:mm")),
                                                          QString::fromUtf8(s.timeZoneId));
        }
    }
    if (!m_enabled->isChecked())
        text += QStringLiteral("<br><i>Disabled — it won't run until you enable it.</i>");
    m_preview->setText(text);

    const bool haveChannel = m_channel->currentIndex() >= 0;
    m_save->setEnabled(ok && haveChannel && !m_name->text().trimmed().isEmpty());
}

Meeting MeetingDialog::result() const
{
    Meeting m = m_initial;
    m.name    = m_name->text().trimmed();
    const int tab = m_server->currentData().toInt();
    if (tab >= 0 && tab < m_tabs.size()) {
        const auto& t   = m_tabs[tab];
        const bool same = t.uid == m_initial.serverUid;
        m.serverName     = t.name;
        m.serverUid      = t.uid;
        m.host           = t.host;
        m.port           = t.port;
        m.serverPassword = !t.password.isEmpty() ? t.password : same ? m_initial.serverPassword : QString();
    }
    if (m_channel->currentIndex() >= 0) {
        m.channelId   = m_channel->currentData().toULongLong();
        m.channelPath = m_channel->currentData(kPathRole).toString();
    }
    m.channelPassword = m_channelPw->text();
    m.nickname        = m_nickname->text().trimmed();
    m.schedule        = currentSchedule();
    m.action          = m_warnRadio->isChecked() ? Action::WarnThenMove : Action::MoveAtStart;
    m.warnMinutes     = m_warn->value();
    m.enabled         = m_enabled->isChecked();
    return m;
}

} // namespace gf
