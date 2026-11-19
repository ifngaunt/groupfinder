#pragma once
// "Find Users by Group": tick server groups, see who is online in all of them (live).
#include <QDialog>
#include <QVector>

#include "common/ts3api.h"

class QComboBox;
class QLabel;
class QPushButton;
class QTableWidget;

namespace gf {

class GroupChecklist;
class QueryController;

class FinderWindow : public QDialog {
    Q_OBJECT
public:
    FinderWindow(QueryController* controller, QWidget* parent = nullptr);

private:
    quint64 currentSchid() const;
    void    fillServers();
    void    onServerChanged();
    void    refillGroups();
    void    refreshResults();
    void    showInChat();

    QueryController*        m_c;
    QVector<ts3::ServerTab> m_tabs;
    QComboBox*              m_server  = nullptr;
    GroupChecklist*         m_groups  = nullptr;
    QTableWidget*           m_results = nullptr;
    QLabel*                 m_count   = nullptr;
    QPushButton*            m_chat    = nullptr;
    QPushButton*            m_toAlarm = nullptr;
};

} // namespace gf
