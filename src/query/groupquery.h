#pragma once
// Server-group matching shared by the Find Users and Connect Alarm windows. Pure logic on QtCore
// (tests/test_groupquery.cpp). Semantics match plugin.c's /findgroup: a user matches when they are in
// EVERY required group; a group name that several server groups share matches ANY of their IDs.
#include <QPair>
#include <QString>
#include <QStringList>
#include <QVector>

namespace gf {

struct GroupInfo {
    QString          name;
    QVector<quint64> ids;  // ascending; >1 when several server groups share the name
};

// One entry per distinct name, sorted case-insensitively by name; duplicate (id, name) pairs ignored.
QVector<GroupInfo> mergeGroupsByName(const QVector<QPair<quint64, QString>>& raw);
// CLIENT_SERVERGROUPS value "6,13,62" -> {6, 13, 62}; non-numbers are skipped.
QVector<quint64> parseGroupCsv(const QString& csv);
// AND over `required`, OR within each entry. No requirements -> false.
bool clientMatches(const QVector<quint64>& clientGroups, const QVector<QVector<quint64>>& required);
// Same tokenizer as plugin.c's split_quoted_args: spaces separate, "double quotes" group.
QStringList splitQueryTokens(const QString& query);
// Alarm query text for ticked groups: each name quoted; a name containing '"' is written as its first ID.
QString buildQuery(const QVector<GroupInfo>& ticked);
// Indexes into `groups` that a stored query refers to (numeric token = group holding that ID; name =
// exact match, else case-insensitive). Tokens that match nothing are appended to `unresolved`.
QVector<int> resolveQuery(const QString& query, const QVector<GroupInfo>& groups, QStringList* unresolved = nullptr);

} // namespace gf
