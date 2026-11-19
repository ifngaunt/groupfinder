#pragma once
// "Connect Alarm Settings": per server — on/off, which groups, which sound; live preview of who matches.
#include <QDialog>
#include <QStringList>
#include <QVector>

#include "common/ts3api.h"
#include "query/groupquery.h"

class QCheckBox;
class QComboBox;
class QLabel;
class QLineEdit;
class QPushButton;

namespace gf {

class GroupChecklist;
class QueryController;

class AlarmWindow : public QDialog {
    Q_OBJECT
public:
    // `preset` (from Find Users → "Set as connect alarm…") replaces the stored groups and enables the alarm.
    AlarmWindow(QueryController* controller, quint64 schid, const QVector<GroupInfo>* preset, QWidget* parent = nullptr);

protected:
    void keyPressEvent(QKeyEvent* e) override;  // Enter (e.g. in the filter) must not mean "Save"

private:
    quint64 currentSchid() const;
    void    loadServer();      // read the selected server's saved alarm
    void    applyGroups();     // (re)tick groups once the server's group list is known
    void    updatePreview();
    void    save();
    void    browseSound();
    void    testSound();

    QueryController*        m_c;
    QVector<ts3::ServerTab> m_tabs;
    QString                 m_savedQuery;   // query of the selected server as stored
    QStringList             m_presetNames;  // ticks to apply instead of the stored query
    bool                    m_usePreset = false;
    QComboBox*              m_server    = nullptr;
    QCheckBox*              m_enabled   = nullptr;
    GroupChecklist*         m_groups    = nullptr;
    QLabel*                 m_unknown   = nullptr;
    QLineEdit*              m_sound     = nullptr;
    QLabel*                 m_soundNote = nullptr;
    QLabel*                 m_preview   = nullptr;
    QPushButton*            m_save      = nullptr;
};

} // namespace gf
