#include <QDateTime>
#include <QDir>
#include <QFile>
#include <QTemporaryDir>
#include <QtTest>

#include "backend.h"
#include "logmodel.h"
#include "policy.h"
#include "theme.h"
#include "translator.h"

static const char *kUserRules =
    "*filter\n"
    "### RULES ###\n\n"
    "### tuple ### allow tcp 22 0.0.0.0/0 any 0.0.0.0/0 in\n"
    "-A ufw-user-input -p tcp --dport 22 -j ACCEPT\n\n"
    "### tuple ### allow tcp 7878 0.0.0.0/0 any 192.168.0.0/16 in comment=4c414e206f6e6c79\n"
    "### tuple ### deny_log udp 137:139 0.0.0.0/0 any 0.0.0.0/0 in_eth0\n"
    "### tuple ### limit tcp 2222 0.0.0.0/0 any 0.0.0.0/0 in\n"
    "### tuple ### route:allow any any 0.0.0.0/0 any 0.0.0.0/0 in_usb0!out_wlan0\n"
    "### tuple ### deny any any 10.0.0.9 any 0.0.0.0/0 out\n"
    "### END RULES ###\n";

static const char *kUser6Rules =
    "### tuple ### allow tcp 22 ::/0 any ::/0 in\n"
    "### tuple ### allow tcp 61500 ::/0 any fe80::/10 in_eth1\n";

static const char *kBlock =
    "[UFW BLOCK] IN=eth0 OUT= MAC=aa:bb SRC=10.1.2.3 DST=10.1.2.4 LEN=52 TOS=0x00 PREC=0x00 TTL=126 "
    "ID=1 DF PROTO=TCP SPT=50000 DPT=7680 WINDOW=65535 RES=0x00 SYN URGP=0 ";

class BastionTests : public QObject {
    Q_OBJECT

private slots:
    void parsesTuples()
    {
        Rule r;
        QVERIFY(Policy::parseTuple("### tuple ### allow tcp 7878 0.0.0.0/0 any 192.168.0.0/16 in comment=4c414e206f6e6c79", false, &r));
        QCOMPARE(r.action, QString("allow"));
        QCOMPARE(r.proto, QString("tcp"));
        QCOMPARE(r.dport, QString("7878"));
        QCOMPARE(r.dst, QString("any"));
        QCOMPARE(r.src, QString("192.168.0.0/16"));
        QCOMPARE(r.comment, QString("LAN only"));
        QCOMPARE(r.chain, QString("input"));

        QVERIFY(Policy::parseTuple("### tuple ### deny_log udp 137:139 0.0.0.0/0 any 0.0.0.0/0 in_eth0", false, &r));
        QCOMPARE(r.action, QString("deny"));
        QVERIFY(r.log);
        QCOMPARE(r.inIface, QString("eth0"));

        QVERIFY(Policy::parseTuple("### tuple ### route:allow any any 0.0.0.0/0 any 0.0.0.0/0 in_usb0!out_wlan0", false, &r));
        QCOMPARE(r.chain, QString("forward"));
        QCOMPARE(r.inIface, QString("usb0"));
        QCOMPARE(r.outIface, QString("wlan0"));

        QVERIFY(Policy::parseTuple("### tuple ### allow any 22 0.0.0.0/0 any 0.0.0.0/0 OpenSSH - in", false, &r));
        QCOMPARE(r.dapp, QString("OpenSSH"));
        QVERIFY(r.sapp.isEmpty());

        QVERIFY(!Policy::parseTuple("-A ufw-user-input -p tcp --dport 22 -j ACCEPT", false, &r));
    }

    void mergesFamiliesAndOrdersByChain()
    {
        QTemporaryDir dir;
        write(dir.filePath("user.rules"), kUserRules);
        write(dir.filePath("user6.rules"), kUser6Rules);
        const auto rules = Policy::merge(Policy::readRulesFile(dir.filePath("user.rules"), false),
                                         Policy::readRulesFile(dir.filePath("user6.rules"), true));
        QCOMPARE(rules.size(), 7);
        QVERIFY(rules[0].v4 && rules[0].v6);                 // ssh, written for both
        QCOMPARE(rules[4].dport, QString("61500"));         // v6 only, still incoming
        QVERIFY(!rules[4].v4 && rules[4].v6);
        QCOMPARE(rules[5].chain, QString("output"));
        QCOMPARE(rules[6].chain, QString("forward"));
        QCOMPARE(rules[6].number, 7);
    }

    void parsesImpliedRules()
    {
        Rule r;
        QVERIFY(Policy::parseIptables("-A ufw-before-input -p udp -d 224.0.0.251 --dport 5353 -j ACCEPT", &r));
        QCOMPARE(r.dst, QString("224.0.0.251"));
        QCOMPARE(r.dport, QString("5353"));
        QVERIFY(Policy::parseIptables("-A ufw-before-input -m conntrack --ctstate INVALID -j DROP", &r));
        QCOMPARE(r.action, QString("deny"));
        QCOMPARE(r.extra, QString("INVALID"));
        QVERIFY(!Policy::parseIptables("-A ufw-before-input -j ufw-not-local", &r));
    }

    void parsesLogLines()
    {
        LogEntry e;
        QVERIFY(Policy::parseLog(kBlock, 1000, &e));
        QCOMPARE(e.action, QString("BLOCK"));
        QVERIFY(e.blocked());
        QCOMPARE(e.chain(), QString("input"));
        QCOMPARE(e.src, QString("10.1.2.3"));
        QCOMPARE(e.dpt, 7680);
        QCOMPARE(e.proto, QString("tcp"));
        QCOMPARE(e.flags, QString("SYN"));
        QVERIFY(Policy::parseLog("[UFW LIMIT BLOCK] IN=eth0 OUT=wlan0 SRC=1.1.1.1 DST=2.2.2.2 PROTO=UDP", 0, &e));
        QCOMPARE(e.action, QString("LIMIT BLOCK"));
        QCOMPARE(e.chain(), QString("forward"));
        QVERIFY(!Policy::parseLog("usb 1-1: new device", 0, &e));
    }

    void matchesRules()
    {
        QVERIFY(Policy::portMatches("any", 5));
        QVERIFY(Policy::portMatches("137:139", 138));
        QVERIFY(Policy::portMatches("80,443", 443));
        QVERIFY(!Policy::portMatches("80", -1));
        QVERIFY(Policy::addressMatches("192.168.0.0/16", "192.168.12.140"));
        QVERIFY(!Policy::addressMatches("192.168.0.0/16", "10.0.0.1"));
        QVERIFY(Policy::addressMatches("fe80::/10", "fe80::1"));

        QTemporaryDir dir;
        write(dir.filePath("user.rules"), kUserRules);
        const auto rules = Policy::merge(Policy::readRulesFile(dir.filePath("user.rules"), false), {});
        LogEntry e;
        Policy::parseLog(kBlock, 0, &e);
        QCOMPARE(Policy::matchRule(rules, e), -1);  // nothing allows 7680: cleanup
        Policy::parseLog("[UFW BLOCK] IN=eth0 OUT= SRC=1.1.1.1 DST=2.2.2.2 PROTO=UDP SPT=5 DPT=138", 0, &e);
        QCOMPARE(Policy::matchRule(rules, e), 2);   // the logged deny on eth0
        Policy::parseLog("[UFW LIMIT BLOCK] IN=eth0 OUT= SRC=1.1.1.1 DST=2.2.2.2 PROTO=TCP SPT=5 DPT=2222", 0, &e);
        QCOMPARE(Policy::matchRule(rules, e), 3);
    }

    void judgesExposure()
    {
        QTemporaryDir dir;
        write(dir.filePath("user.rules"), kUserRules);
        const auto rules = Policy::merge(Policy::readRulesFile(dir.filePath("user.rules"), false), {});
        int n = 0;
        QCOMPARE(Backend::exposure(rules, "DROP", "tcp", "0.0.0.0", 22, &n), QString("open"));
        QCOMPARE(n, 1);
        QCOMPARE(Backend::exposure(rules, "DROP", "tcp", "*", 7878, &n), QString("restricted"));
        QCOMPARE(Backend::exposure(rules, "DROP", "tcp", "127.0.0.1", 631, &n), QString("local"));
        QCOMPARE(Backend::exposure(rules, "DROP", "udp", "127.0.0.53%lo", 53, &n), QString("local"));
        QCOMPARE(Backend::exposure(rules, "DROP", "tcp", "0.0.0.0", 8080, &n), QString("blocked"));
        QCOMPARE(Backend::exposure(rules, "ACCEPT", "tcp", "0.0.0.0", 8080, &n), QString("open"));
        QCOMPARE(Backend::exposure(rules, "DROP", "udp", "0.0.0.0", 5353, &n), QString("implied"));
    }

    void backendReadsPolicyAndJournal()
    {
        QTemporaryDir dir;
        write(dir.filePath("user.rules"), kUserRules);
        write(dir.filePath("user6.rules"), kUser6Rules);
        write(dir.filePath("ufw.conf"), "ENABLED=yes\nLOGLEVEL=medium\n");
        write(dir.filePath("defaults"), "DEFAULT_INPUT_POLICY=\"REJECT\"\nIPV6=yes\n");
        Backend backend(dir.path(), dir.filePath("defaults"), false);
        QCOMPARE(backend.rules().size(), 7);
        QCOMPARE(backend.defaults()["input"].toString(), QString("REJECT"));
        QCOMPARE(backend.defaults()["output"].toString(), QString("ACCEPT"));
        QCOMPARE(backend.defaults()["loglevel"].toString(), QString("medium"));
        const auto second = backend.rules()[1].toMap();
        QCOMPARE(second["name"].toString(), QString("LAN only"));
        QCOMPARE(second["action"].toString(), QString("Accept"));
        QCOMPARE(second["command"].toString(),
                 QString("ufw allow proto tcp from 192.168.0.0/16 to any port 7878 comment 'LAN only'"));
        QCOMPARE(backend.rules()[6].toMap()["command"].toString(),
                 QString("ufw route allow in on usb0 out on wlan0 from any to any"));

        const qint64 now = QDateTime::currentMSecsSinceEpoch();
        const QByteArray json = "{\"MESSAGE\":\"" + QByteArray(kBlock) + "\",\"__REALTIME_TIMESTAMP\":\""
                                + QByteArray::number(now * 1000) + "\"}";
        LogModel::Item item;
        QVERIFY(backend.ingestJson(json, &item));
        QCOMPARE(item.rule, -1);
        QCOMPARE(item.ruleName, QString("Cleanup · Incoming"));
        QVERIFY(!backend.ingestJson("{\"MESSAGE\":\"hello\"}", &item));

        backend.ingestJson(json, &item);
        backend.logs()->append(item);
        backend.recomputeStats();
        QCOMPARE(backend.stats()["blocked"].toInt(), 1);
        QCOMPARE(backend.hits()["cleanup-input"].toInt(), 1);
    }

    void logQueryFilters()
    {
        LogModel model;
        const qint64 now = QDateTime::currentMSecsSinceEpoch();
        QList<LogModel::Item> items;
        auto add = [&](const QString &line, qint64 age, int rule) {
            LogModel::Item item;
            Policy::parseLog(line, now - age, &item.entry);
            item.rule = rule;
            items << item;
        };
        add(kBlock, 1000, -1);
        add("[UFW ALLOW] IN=eth0 OUT= SRC=192.168.1.5 DST=10.1.2.4 PROTO=TCP SPT=1 DPT=22", 2000, 0);
        add("[UFW BLOCK] IN=eth0 OUT= SRC=10.9.9.9 DST=10.1.2.4 PROTO=UDP SPT=1 DPT=137", 3LL * 24 * 3600 * 1000, -1);
        model.setItems(items);
        QCOMPARE(model.count(), 2);                 // 24 hours by default
        model.setHours(0);
        QCOMPARE(model.count(), 3);
        QCOMPARE(model.get(0)["src"].toString(), QString("10.1.2.3"));  // newest first
        model.setQuery("action:drop");
        QCOMPARE(model.count(), 2);
        model.setQuery("action:drop !proto:udp");
        QCOMPARE(model.count(), 1);
        model.setQuery("src:192.168.0.0/16");
        QCOMPARE(model.count(), 1);
        model.setQuery("port:7680");
        QCOMPARE(model.count(), 1);
        model.setQuery("rule:cleanup");
        QCOMPARE(model.count(), 2);
        model.setQuery("rule:1");
        QCOMPARE(model.count(), 1);
        model.setQuery("dir:in 10.9.9");
        QCOMPARE(model.count(), 1);
    }

    void themeFallsBack()
    {
        QTemporaryDir dir;
        Theme theme(dir.path());
        QCOMPARE(theme.accent(), QString("#FFD60A"));
        QCOMPARE(theme.accentForeground(), QString("black"));
    }

    void themeReadsAccent()
    {
        QTemporaryDir dir;
        QDir(dir.path()).mkpath("theme");
        write(dir.path() + "/theme/colors.toml", "accent = \"#112233\"\n");
        Theme theme(dir.path());
        QCOMPARE(theme.accent(), QString("#112233"));
        QCOMPARE(theme.accentForeground(), QString("white"));
    }

    void translatorFallsBackToEnglish()
    {
        QTemporaryDir dir;
        Translator translator(dir.path() + "/language", dir.path());
        QCOMPARE(translator.language(), QString("en"));
        QVERIFY(translator.translate("Main", "Save").isNull());
    }

private:
    static void write(const QString &path, const QByteArray &contents)
    {
        QFile file(path);
        QVERIFY(file.open(QIODevice::WriteOnly));
        file.write(contents);
    }
};

QTEST_MAIN(BastionTests)
#include "bastion_tests.moc"
