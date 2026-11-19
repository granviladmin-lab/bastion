#include "policy.h"

#include <QFile>
#include <QHostAddress>
#include <QRegularExpression>

QString Rule::key() const {
    return QStringList{chain, action, QString::number(log), proto, dport, sport, src, dst,
                       inIface, outIface, dapp, sapp, comment}.join('|');
}

QString LogEntry::chain() const {
    if (!in.isEmpty() && !out.isEmpty())
        return "forward";
    return out.isEmpty() ? "input" : "output";
}

namespace Policy {

static QString anyAddress(const QString &address) {
    return address == "0.0.0.0/0" || address == "::/0" ? QString("any") : address;
}

// ufw writes "action proto dport dst sport src [dapp sapp] direction
// [comment=hex]", where action may carry "route:" and "_log"/"_log-all", and
// direction is in/out with an optional "_iface" ("in_a!out_b" when routed).
bool parseTuple(const QString &line, bool v6, Rule *rule) {
    const int at = line.indexOf("### tuple ###");
    if (at < 0)
        return false;
    QStringList tokens = line.mid(at + 13).split(' ', Qt::SkipEmptyParts);

    Rule r;
    for (int i = tokens.size() - 1; i >= 0; --i)
        if (tokens[i].startsWith("comment=")) {
            r.comment = QString::fromUtf8(QByteArray::fromHex(tokens[i].mid(8).toLatin1()));
            tokens.removeAt(i);
        }
    if (tokens.size() < 7)
        return false;

    QString action = tokens[0];
    const bool route = action.startsWith("route:");
    if (route)
        action = action.mid(6);
    if (action.contains("_log")) {
        r.log = true;
        action = action.section('_', 0, 0);
    }
    r.action = action;
    r.proto = tokens[1];
    r.dport = tokens[2];
    r.dst = anyAddress(tokens[3]);
    r.sport = tokens[4];
    r.src = anyAddress(tokens[5]);
    if (tokens.size() >= 9) {
        r.dapp = tokens[6] == "-" ? QString() : tokens[6];
        r.sapp = tokens[7] == "-" ? QString() : tokens[7];
    }

    const QString direction = tokens.last();
    for (const QString &part : direction.split('!')) {
        const QString side = part.section('_', 0, 0);
        const QString iface = part.section('_', 1);
        if (side == "in")
            r.inIface = iface;
        else if (side == "out")
            r.outIface = iface;
    }
    r.chain = route ? "forward" : direction.startsWith("out") ? "output" : "input";
    r.v4 = !v6;
    r.v6 = v6;
    *rule = r;
    return true;
}

QList<Rule> readRulesFile(const QString &path, bool v6) {
    QList<Rule> rules;
    QFile file(path);
    if (!file.open(QIODevice::ReadOnly))
        return rules;
    for (const QString &line : QString::fromUtf8(file.readAll()).split('\n')) {
        Rule rule;
        if (parseTuple(line, v6, &rule))
            rules << rule;
    }
    return rules;
}

QList<Rule> merge(const QList<Rule> &v4, const QList<Rule> &v6) {
    QList<Rule> rules = v4;
    for (const Rule &rule : v6) {
        bool merged = false;
        for (Rule &existing : rules)
            if (existing.key() == rule.key()) {
                existing.v6 = true;
                merged = true;
                break;
            }
        if (!merged)
            rules << rule;
    }
    // ufw evaluates each chain on its own, so group them the way Check Point
    // groups a rulebase into sections, keeping the order within each.
    QList<Rule> ordered;
    for (const char *chain : {"input", "output", "forward"})
        for (const Rule &rule : rules)
            if (rule.chain == QLatin1String(chain))
                ordered << rule;
    for (int i = 0; i < ordered.size(); ++i)
        ordered[i].number = i + 1;
    return ordered;
}

// Reads the handful of iptables options ufw's before.rules uses. Lines that
// jump to another ufw chain instead of deciding are not rules a reader needs.
bool parseIptables(const QString &line, Rule *rule) {
    static const QRegularExpression head(R"(^-A ufw6?-before-(input|output|forward)\s)");
    const auto match = head.match(line);
    if (!match.hasMatch())
        return false;
    Rule r;
    r.chain = match.captured(1);
    const QStringList t = line.split(' ', Qt::SkipEmptyParts);
    QString target;
    QStringList extra;
    for (int i = 2; i < t.size(); ++i) {
        const QString o = t[i];
        const QString v = i + 1 < t.size() ? t[i + 1] : QString();
        if (o == "-p") { r.proto = v; ++i; }
        else if (o == "-s") { r.src = v; ++i; }
        else if (o == "-d") { r.dst = v; ++i; }
        else if (o == "-i") { r.inIface = v; ++i; }
        else if (o == "-o") { r.outIface = v; ++i; }
        else if (o == "--dport") { r.dport = v; ++i; }
        else if (o == "--sport") { r.sport = v; ++i; }
        else if (o == "--ctstate") { extra << v; ++i; }
        else if (o == "--icmp-type" || o == "--icmpv6-type") { extra << v; ++i; }
        else if (o == "-j") { target = v; ++i; }
    }
    if (target == "ACCEPT") r.action = "allow";
    else if (target == "DROP") r.action = "deny";
    else if (target == "REJECT") r.action = "reject";
    else return false;
    r.extra = extra.join(' ');
    r.v4 = true;
    *rule = r;
    return true;
}

QList<Rule> readImplied(const QString &path) {
    QList<Rule> rules;
    QFile file(path);
    if (!file.open(QIODevice::ReadOnly))
        return rules;
    for (const QString &line : QString::fromUtf8(file.readAll()).split('\n')) {
        Rule rule;
        if (parseIptables(line.trimmed(), &rule))
            rules << rule;
    }
    for (int i = 0; i < rules.size(); ++i)
        rules[i].number = i + 1;
    return rules;
}

QHash<QString, QString> readKeyValues(const QString &path) {
    QHash<QString, QString> values;
    QFile file(path);
    if (!file.open(QIODevice::ReadOnly))
        return values;
    for (QString line : QString::fromUtf8(file.readAll()).split('\n')) {
        line = line.trimmed();
        if (line.isEmpty() || line.startsWith('#') || !line.contains('='))
            continue;
        QString value = line.section('=', 1).trimmed();
        if (value.size() >= 2 && (value.startsWith('"') || value.startsWith('\'')))
            value = value.mid(1, value.size() - 2);
        values.insert(line.section('=', 0, 0).trimmed(), value);
    }
    return values;
}

bool parseLog(const QString &message, qint64 time, LogEntry *entry) {
    static const QRegularExpression prefix(R"(\[UFW ([A-Z ]+)\])");
    const auto match = prefix.match(message);
    if (!match.hasMatch())
        return false;
    LogEntry e;
    e.time = time;
    e.action = match.captured(1).trimmed();
    e.message = message.trimmed();
    QStringList flags;
    for (const QString &token : message.mid(match.capturedEnd()).split(' ', Qt::SkipEmptyParts)) {
        const int eq = token.indexOf('=');
        if (eq < 0) {
            flags << token;
            continue;
        }
        const QString k = token.left(eq), v = token.mid(eq + 1);
        if (k == "IN") e.in = v;
        else if (k == "OUT") e.out = v;
        else if (k == "SRC") e.src = v;
        else if (k == "DST") e.dst = v;
        else if (k == "PROTO") e.proto = v.toLower();
        else if (k == "SPT") e.spt = v.toInt();
        else if (k == "DPT") e.dpt = v.toInt();
        else if (k == "LEN") e.len = v.toInt();
        else if (k == "TTL" || k == "HOPLIMIT") e.ttl = v.toInt();
        else if (k == "MAC") e.mac = v;
    }
    flags.removeAll("DF");
    e.flags = flags.join(' ');
    *entry = e;
    return true;
}

bool portMatches(const QString &spec, int port) {
    if (spec.isEmpty() || spec == "any")
        return true;
    if (port < 0)
        return false;
    for (const QString &part : spec.split(',')) {
        if (part.contains(':')) {
            if (port >= part.section(':', 0, 0).toInt() && port <= part.section(':', 1).toInt())
                return true;
        } else if (part.toInt() == port) {
            return true;
        }
    }
    return false;
}

bool addressMatches(const QString &spec, const QString &address) {
    if (spec.isEmpty() || spec == "any")
        return true;
    const QHostAddress host(address);
    if (host.isNull())
        return false;
    if (!spec.contains('/'))
        return QHostAddress(spec).isEqual(host);
    const auto subnet = QHostAddress::parseSubnet(spec);
    return host.isInSubnet(subnet);
}

bool matches(const Rule &rule, const LogEntry &entry) {
    if (rule.chain != entry.chain())
        return false;
    if (rule.proto != "any" && rule.proto != entry.proto)
        return false;
    if (!rule.inIface.isEmpty() && rule.inIface != entry.in)
        return false;
    if (!rule.outIface.isEmpty() && rule.outIface != entry.out)
        return false;
    return portMatches(rule.dport, entry.dpt) && portMatches(rule.sport, entry.spt)
        && addressMatches(rule.src, entry.src) && addressMatches(rule.dst, entry.dst);
}

int matchRule(const QList<Rule> &rules, const LogEntry &entry) {
    // A logged block that no deny rule explains fell through to the default
    // policy; an allow log comes from an allow rule with logging on.
    for (int i = 0; i < rules.size(); ++i) {
        const Rule &rule = rules[i];
        if (!matches(rule, entry))
            continue;
        const bool ruleBlocks = rule.action != "allow";
        if (entry.action == "LIMIT BLOCK" && rule.action == "limit")
            return i;
        if (ruleBlocks == entry.blocked() && rule.action != "limit")
            return i;
        return -1;
    }
    return -1;
}

QString serviceName(int port, const QString &proto) {
    static QHash<QString, QString> names;
    if (names.isEmpty()) {
        QFile file("/etc/services");
        if (file.open(QIODevice::ReadOnly)) {
            static const QRegularExpression line(R"(^([A-Za-z0-9_.+-]+)\s+(\d+)/(tcp|udp))");
            for (const QString &l : QString::fromUtf8(file.readAll()).split('\n')) {
                const auto m = line.match(l);
                if (m.hasMatch()) {
                    const QString key = m.captured(2) + "/" + m.captured(3);
                    if (!names.contains(key))
                        names.insert(key, m.captured(1));
                }
            }
        }
        names.insert("_", "_"); // Keeps a missing file from being re-read.
    }
    return names.value(QString::number(port) + "/" + proto.toLower());
}

}
