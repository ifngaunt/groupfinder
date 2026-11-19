#include "query/groupchecklist.h"

#include <QLineEdit>
#include <QListWidget>
#include <QSignalBlocker>
#include <QVBoxLayout>

namespace gf {

namespace {
constexpr int kIndexRole = Qt::UserRole;
constexpr int kNameRole  = Qt::UserRole + 1;

QString idsText(const GroupInfo& g)
{
    QStringList ids;
    for (quint64 id : g.ids)
        ids << QString::number(id);
    return ids.join(QStringLiteral(", "));
}
} // namespace

GroupChecklist::GroupChecklist(const QString& objectPrefix, QWidget* parent) : QWidget(parent)
{
    m_filter = new QLineEdit(this);
    m_filter->setObjectName(objectPrefix + QStringLiteral("Filter"));
    m_filter->setPlaceholderText(QStringLiteral("Filter groups…"));
    m_filter->setClearButtonEnabled(true);
    m_list = new QListWidget(this);
    m_list->setObjectName(objectPrefix + QStringLiteral("List"));
    m_list->setUniformItemSizes(true);

    auto* layout = new QVBoxLayout(this);
    layout->setContentsMargins(0, 0, 0, 0);
    layout->addWidget(m_filter);
    layout->addWidget(m_list, 1);

    connect(m_filter, &QLineEdit::textChanged, this, &GroupChecklist::applyFilter);
    connect(m_list, &QListWidget::itemChanged, this, [this](QListWidgetItem* item) {
        if (item->data(kNameRole).isValid())
            emit tickedChanged();
    });
}

void GroupChecklist::setGroups(const QVector<GroupInfo>& groups)
{
    const QStringList keep = tickedNames();
    {
        QSignalBlocker block(m_list);
        m_groups = groups;
        m_list->clear();
        for (int i = 0; i < groups.size(); ++i) {
            auto* item = new QListWidgetItem(QStringLiteral("%1    (%2)").arg(groups[i].name, idsText(groups[i])), m_list);
            item->setFlags(Qt::ItemIsEnabled | Qt::ItemIsUserCheckable);
            item->setCheckState(keep.contains(groups[i].name) ? Qt::Checked : Qt::Unchecked);
            item->setData(kIndexRole, i);
            item->setData(kNameRole, groups[i].name);
            item->setToolTip(groups[i].ids.size() > 1 ? QStringLiteral("Several server groups share this name — any of them counts")
                                                      : QString());
        }
    }
    applyFilter();
    if (keep != tickedNames())
        emit tickedChanged();
}

void GroupChecklist::showMessage(const QString& text)
{
    QSignalBlocker block(m_list);
    m_groups.clear();
    m_list->clear();
    auto* item = new QListWidgetItem(text, m_list);
    item->setFlags(Qt::NoItemFlags);
}

void GroupChecklist::setTickedNames(const QStringList& names)
{
    {
        QSignalBlocker block(m_list);
        for (int i = 0; i < m_list->count(); ++i) {
            QListWidgetItem* item = m_list->item(i);
            if (item->data(kNameRole).isValid())
                item->setCheckState(names.contains(item->data(kNameRole).toString()) ? Qt::Checked : Qt::Unchecked);
        }
    }
    emit tickedChanged();
}

QStringList GroupChecklist::tickedNames() const
{
    QStringList out;
    for (int i = 0; i < m_list->count(); ++i) {
        const QListWidgetItem* item = m_list->item(i);
        if (item->data(kNameRole).isValid() && item->checkState() == Qt::Checked)
            out << item->data(kNameRole).toString();
    }
    return out;
}

QVector<GroupInfo> GroupChecklist::tickedGroups() const
{
    QVector<GroupInfo> out;
    for (int i = 0; i < m_list->count(); ++i) {
        const QListWidgetItem* item = m_list->item(i);
        if (item->data(kNameRole).isValid() && item->checkState() == Qt::Checked)
            out << m_groups.value(item->data(kIndexRole).toInt());
    }
    return out;
}

void GroupChecklist::applyFilter()
{
    const QString f = m_filter->text().trimmed();
    for (int i = 0; i < m_list->count(); ++i) {
        QListWidgetItem* item = m_list->item(i);
        item->setHidden(!f.isEmpty() && !item->text().contains(f, Qt::CaseInsensitive) && item->checkState() != Qt::Checked);
    }
}

} // namespace gf
