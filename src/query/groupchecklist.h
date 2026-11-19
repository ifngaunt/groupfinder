#pragma once
// Filterable tick-list of a server's groups (one row per group name). Used by both query windows.
#include <QStringList>
#include <QWidget>

#include "query/groupquery.h"

class QLineEdit;
class QListWidget;

namespace gf {

class GroupChecklist : public QWidget {
    Q_OBJECT
public:
    // Child objectNames: <prefix>List and <prefix>Filter (the test harness finds them by name).
    GroupChecklist(const QString& objectPrefix, QWidget* parent = nullptr);

    void setGroups(const QVector<GroupInfo>& groups);  // keeps ticks by name
    void showMessage(const QString& text);              // e.g. "Loading groups…" instead of the list
    void setTickedNames(const QStringList& names);
    QStringList        tickedNames() const;
    QVector<GroupInfo> tickedGroups() const;
    bool               hasGroups() const { return !m_groups.isEmpty(); }

signals:
    void tickedChanged();

private:
    void applyFilter();

    QLineEdit*         m_filter = nullptr;
    QListWidget*       m_list   = nullptr;
    QVector<GroupInfo> m_groups;
};

} // namespace gf
