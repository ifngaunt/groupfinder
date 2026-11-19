#include <QCoreApplication>
#include <QDir>
#include <QtTest>
#include <memory>

#include "tests.h"

// Runs every test class. With GF_TEST_OUT=<dir>, each class writes <dir>/<Class>.txt
// (QtTest's -o file is reopened per qExec, so one shared file would keep only the last class).
int main(int argc, char** argv)
{
    QCoreApplication app(argc, argv);
    const QString outDir = qEnvironmentVariable("GF_TEST_OUT");
    int status = 0;
    for (auto factory : {createTestSchedule, createTestMeeting, createTestFiring, createTestGroupQuery}) {
        std::unique_ptr<QObject> test(factory());
        QStringList args{QString::fromLocal8Bit(argv[0])};
        if (!outDir.isEmpty())
            args << QStringLiteral("-o")
                 << QDir(outDir).filePath(QString::fromLatin1(test->metaObject()->className()) + QStringLiteral(".txt,txt"));
        status |= QTest::qExec(test.get(), args);
    }
    return status;
}
