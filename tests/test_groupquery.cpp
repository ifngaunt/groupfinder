#include <QtTest>

#include "query/groupquery.h"
#include "tests.h"

using gf::GroupInfo;

namespace {
QVector<GroupInfo> sampleGroups()
{
    return gf::mergeGroupsByName({{62, QStringLiteral("Head Administrator")},
                                  {9, QStringLiteral("Admin")},
                                  {10, QStringLiteral("Admin")},
                                  {6, QStringLiteral("Guest")}});
}
} // namespace

class TestGroupQuery : public QObject {
    Q_OBJECT
private slots:
    void merge_byNameSortedWithIds()
    {
        const auto g = gf::mergeGroupsByName({{62, QStringLiteral("Head Administrator")},
                                              {10, QStringLiteral("Admin")},
                                              {9, QStringLiteral("Admin")},
                                              {6, QStringLiteral("Guest")},
                                              {9, QStringLiteral("Admin")}});
        QCOMPARE(g.size(), 3);
        QCOMPARE(g[0].name, QStringLiteral("Admin"));
        QCOMPARE(g[0].ids, (QVector<quint64>{9, 10}));
        QCOMPARE(g[1].name, QStringLiteral("Guest"));
        QCOMPARE(g[2].name, QStringLiteral("Head Administrator"));
        QCOMPARE(g[2].ids, (QVector<quint64>{62}));
    }
    void merge_sortIgnoresCase()
    {
        const auto g = gf::mergeGroupsByName({{1, QStringLiteral("bravo")}, {2, QStringLiteral("Alpha")}});
        QCOMPARE(g[0].name, QStringLiteral("Alpha"));
        QCOMPARE(g[1].name, QStringLiteral("bravo"));
    }
    void csv_cases()
    {
        QCOMPARE(gf::parseGroupCsv(QStringLiteral("6,13,62")), (QVector<quint64>{6, 13, 62}));
        QCOMPARE(gf::parseGroupCsv(QString()), QVector<quint64>());
        QCOMPARE(gf::parseGroupCsv(QStringLiteral("6,,x,7")), (QVector<quint64>{6, 7}));
    }
    void matches_andAcrossOrWithin()
    {
        const QVector<quint64> client{6, 62};
        QVERIFY(gf::clientMatches(client, {{62}}));
        QVERIFY(gf::clientMatches(client, {{62}, {6}}));
        QVERIFY(!gf::clientMatches(client, {{62}, {9, 10}}));
        QVERIFY(gf::clientMatches({10}, {{9, 10}}));
        QVERIFY(!gf::clientMatches(client, {}));
    }
    void tokens_likeFindgroup()
    {
        QCOMPARE(gf::splitQueryTokens(QStringLiteral("  \"Head Administrator\" Guest  62 ")),
                 (QStringList{"Head Administrator", "Guest", "62"}));
        QCOMPARE(gf::splitQueryTokens(QString()), QStringList());
    }
    void build_quotesNamesAndFallsBackToId()
    {
        const auto g = sampleGroups();
        QCOMPARE(gf::buildQuery({g[2], g[1]}), QStringLiteral("\"Head Administrator\" \"Guest\""));
        GroupInfo quoted{QStringLiteral("My \"VIP\""), {7}};
        QCOMPARE(gf::buildQuery({quoted}), QStringLiteral("7"));
        QCOMPARE(gf::buildQuery({}), QString());
    }
    void resolve_namesIdsAndUnknown()
    {
        const auto g = sampleGroups();  // 0 Admin{9,10}, 1 Guest{6}, 2 Head Administrator{62}
        QStringList unresolved;
        const auto idx = gf::resolveQuery(QStringLiteral("\"Head Administrator\" guest 9 999 Nope"), g, &unresolved);
        QCOMPARE(idx, (QVector<int>{2, 1, 0}));
        QCOMPARE(unresolved, (QStringList{"999", "Nope"}));
    }
    void resolve_roundTripsBuild()
    {
        const auto g = sampleGroups();
        QCOMPARE(gf::resolveQuery(gf::buildQuery({g[0], g[2]}), g), (QVector<int>{0, 2}));
    }
};

QObject* createTestGroupQuery() { return new TestGroupQuery; }

#include "test_groupquery.moc"
