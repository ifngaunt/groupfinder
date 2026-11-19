#include "query/groupquery.h"

#include <algorithm>

namespace gf {

QVector<GroupInfo> mergeGroupsByName(const QVector<QPair<quint64, QString>>& raw)
{
    QVector<GroupInfo> out;
    for (const auto& p : raw) {
        auto it = std::find_if(out.begin(), out.end(), [&](const GroupInfo& g) { return g.name == p.second; });
        if (it == out.end())
            out.append(GroupInfo{p.second, {p.first}});
        else if (!it->ids.contains(p.first))
            it->ids.append(p.first);
    }
    for (GroupInfo& g : out)
        std::sort(g.ids.begin(), g.ids.end());
    std::stable_sort(out.begin(), out.end(), [](const GroupInfo& a, const GroupInfo& b) {
        return a.name.compare(b.name, Qt::CaseInsensitive) < 0;
    });
    return out;
}

QVector<quint64> parseGroupCsv(const QString& csv)
{
    QVector<quint64> out;
    for (const QString& part : csv.split(QLatin1Char(','), Qt::SkipEmptyParts)) {
        bool ok = false;
        const quint64 id = part.trimmed().toULongLong(&ok);
        if (ok)
            out.append(id);
    }
    return out;
}

bool clientMatches(const QVector<quint64>& clientGroups, const QVector<QVector<quint64>>& required)
{
    if (required.isEmpty())
        return false;
    for (const auto& anyOf : required)
        if (std::none_of(anyOf.begin(), anyOf.end(), [&](quint64 id) { return clientGroups.contains(id); }))
            return false;
    return true;
}

QStringList splitQueryTokens(const QString& query)
{
    QStringList out;
    int i = 0;
    const int n = query.size();
    while (i < n) {
        while (i < n && query.at(i) == QLatin1Char(' '))
            ++i;
        if (i >= n)
            break;
        QString tok;
        if (query.at(i) == QLatin1Char('"')) {
            ++i;
            while (i < n && query.at(i) != QLatin1Char('"'))
                tok += query.at(i++);
            if (i < n)
                ++i;  // closing quote
        } else {
            while (i < n && query.at(i) != QLatin1Char(' '))
                tok += query.at(i++);
        }
        if (!tok.isEmpty())
            out << tok;
    }
    return out;
}

QString buildQuery(const QVector<GroupInfo>& ticked)
{
    QStringList parts;
    for (const GroupInfo& g : ticked) {
        if (g.name.contains(QLatin1Char('"')) || g.name.isEmpty())
            parts << (g.ids.isEmpty() ? QString() : QString::number(g.ids.first()));
        else
            parts << QLatin1Char('"') + g.name + QLatin1Char('"');
    }
    parts.removeAll(QString());
    return parts.join(QLatin1Char(' '));
}

QVector<int> resolveQuery(const QString& query, const QVector<GroupInfo>& groups, QStringList* unresolved)
{
    QVector<int> out;
    auto add = [&](int idx) {
        if (!out.contains(idx))
            out.append(idx);
    };
    for (const QString& tok : splitQueryTokens(query)) {
        bool isNumber = false;
        const quint64 id = tok.toULongLong(&isNumber);
        QVector<int> hits;
        if (isNumber && id > 0) {
            for (int i = 0; i < groups.size(); ++i)
                if (groups[i].ids.contains(id))
                    hits << i;
        } else {
            for (int i = 0; i < groups.size(); ++i)
                if (groups[i].name == tok)
                    hits << i;
            if (hits.isEmpty())
                for (int i = 0; i < groups.size(); ++i)
                    if (groups[i].name.compare(tok, Qt::CaseInsensitive) == 0)
                        hits << i;
        }
        if (hits.isEmpty() && unresolved)
            unresolved->append(tok);
        for (int h : hits)
            add(h);
    }
    return out;
}

} // namespace gf
