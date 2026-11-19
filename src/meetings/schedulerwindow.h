#pragma once
// The "Meeting Scheduler" list: every meeting with its next start (local time), plus add/edit/remove/join.
#include <QDialog>

class QLabel;
class QPushButton;
class QTableWidget;

namespace gf {

class MeetingController;

class SchedulerWindow : public QDialog {
    Q_OBJECT
public:
    SchedulerWindow(MeetingController* controller, QWidget* parent = nullptr);

private:
    void    refresh();
    void    updateButtons();
    QString selectedId() const;
    void    confirmRemove();

    MeetingController* m_c;
    QTableWidget*      m_table  = nullptr;
    QLabel*            m_empty  = nullptr;
    QPushButton*       m_edit   = nullptr;
    QPushButton*       m_remove = nullptr;
    QPushButton*       m_join   = nullptr;
};

} // namespace gf
