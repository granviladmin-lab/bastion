#pragma once

#include <QHash>
#include <QList>
#include <QString>
#include <QVariantMap>

// One UFW rule, read from the "### tuple ###" lines ufw writes into
// user.rules and user6.rules, or from an iptables line in before.rules for
// the implied rules ufw adds on its own.
struct Rule {
    QString chain = "input";   // input, output or forward
    QString action = "allow";  // allow, deny, reject or limit
    bool log = false;
    QString proto = "any";
    QString dport = "any";
    QString sport = "any";
    QString src = "any";       // "any" for 0.0.0.0/0 and ::/0
    QString dst = "any";
    QString inIface;
    QString outIface;
    QString dapp;
    QString sapp;
    QString comment;
    QString extra;             // conntrack state or ICMP type on implied rules
    bool v4 = false;
    bool v6 = false;
    int number = 0;            // position in the displayed rulebase, from 1

    QString key() const;
};

// A packet the kernel logged with a "[UFW ...]" prefix.
struct LogEntry {
    qint64 time = 0;           // milliseconds since the epoch
    QString action;            // BLOCK, ALLOW, LIMIT BLOCK, AUDIT
    QString in, out, src, dst, proto, mac, flags, message;
    int spt = -1, dpt = -1, len = 0, ttl = 0;
    QString chain() const;     // input, output or forward, from IN and OUT
    bool blocked() const { return action.contains("BLOCK"); }
};

namespace Policy {

bool parseTuple(const QString &line, bool v6, Rule *rule);
QList<Rule> readRulesFile(const QString &path, bool v6);
// The same rule written once for IPv4 and once for IPv6 shows as one row.
QList<Rule> merge(const QList<Rule> &v4, const QList<Rule> &v6);

bool parseIptables(const QString &line, Rule *rule);
QList<Rule> readImplied(const QString &path);

QHash<QString, QString> readKeyValues(const QString &path);

bool parseLog(const QString &message, qint64 time, LogEntry *entry);
bool matches(const Rule &rule, const LogEntry &entry);
bool portMatches(const QString &spec, int port);
bool addressMatches(const QString &spec, const QString &address);
// Index of the user rule that decided this packet, or -1 for the chain's
// default policy (Check Point's "cleanup rule").
int matchRule(const QList<Rule> &rules, const LogEntry &entry);

// Port and protocol to the name in /etc/services, e.g. 443/tcp -> https.
QString serviceName(int port, const QString &proto);

}
