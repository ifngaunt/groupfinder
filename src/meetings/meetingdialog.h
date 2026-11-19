#pragma once
// Add / edit one meeting: where (server, channel), when (date, time, zone, repeat), what happens at start.
#include <QDialog>
#include <QVector>

#include "meetings/meeting.h"
#include "meetings/ts3api.h"

class QCheckBox;
class QComboBox;
class QDateEdit;
class QLabel;
class QLineEdit;
class QPushButton;
class QRadioButton;
class QSpinBox;
class QTimeEdit;

namespace gf {

class MeetingDialog : public QDialog {
    Q_OBJECT
public:
    MeetingDialog(const Meeting& initial, bool isNew, QWidget* parent = nullptr);
    Meeting result() const;

private:
    void fillServers();
    void onServerChanged();
    void onChannelChanged();
    void onRepeatChanged();
    void updatePreview();
    Schedule currentSchedule() const;

    Meeting                m_initial;
    QVector<ts3::ServerTab> m_tabs;
    QLineEdit*    m_name      = nullptr;
    QComboBox*    m_server    = nullptr;
    QComboBox*    m_channel   = nullptr;
    QLineEdit*    m_channelPw = nullptr;
    QLineEdit*    m_nickname  = nullptr;
    QDateEdit*    m_date      = nullptr;
    QTimeEdit*    m_time      = nullptr;
    QComboBox*    m_zone      = nullptr;
    QComboBox*    m_repeat    = nullptr;
    QSpinBox*     m_interval  = nullptr;
    QLabel*       m_unit      = nullptr;
    QWidget*      m_everyRow  = nullptr;
    QWidget*      m_daysRow   = nullptr;
    QCheckBox*    m_days[7]   = {};
    QRadioButton* m_moveRadio = nullptr;
    QRadioButton* m_warnRadio = nullptr;
    QSpinBox*     m_warn      = nullptr;
    QCheckBox*    m_enabled   = nullptr;
    QLabel*       m_preview   = nullptr;
    QPushButton*  m_save      = nullptr;
};

} // namespace gf
