#include "backend.h"

#include <QDateTime>
#include <QFileInfo>
#include <QHostAddress>
#include <QJsonDocument>
#include <QJsonObject>
#include <QNetworkInterface>
#include <QRegularExpression>
#include <QStandardPaths>
#include <QSysInfo>
#include <algorithm>

Backend::Backend(const QString &ufwDirectory, const QString &defaultsFile, bool watchJournal, QObject *parent)
    : QObject(parent), m_ufwDirectory(ufwDirectory), m_defaultsFile(defaultsFile), m_watchJournal(watchJournal) {
    // `ufw allow` rewrites user.rules by renaming over it, which drops the file
    // from the watch, so watch the directory and re-arm on every reload.
    m_policyDebounce.setSingleShot(true);
    m_policyDebounce.setInterval(150);
    connect(&m_watcher, &QFileSystemWatcher::directoryChanged, this, [this] { m_policyDebounce.start(); });
    connect(&m_watcher, &QFileSystemWatcher::fileChanged, this, [this] { m_policyDebounce.start(); });
    connect(&m_policyDebounce, &QTimer::timeout, this, &Backend::reloadPolicy);

    m_statsDebounce.setSingleShot(true);
    m_statsDebounce.setInterval(400);
    connect(&m_statsDebounce, &QTimer::timeout, this, &Backend::recomputeStats);

    connect(&m_history, &QProcess::finished, this, [this](int code, QProcess::ExitStatus) {
        QList<LogModel::Item> items;
        for (const QByteArray &line : m_history.readAllStandardOutput().split('\n')) {
            LogModel::Item item;
            if (ingestJson(line, &item))
                items << item;
        }
        // journalctl exits 1 when --grep finds nothing, which is not an error.
        const QString err = QString::fromUtf8(m_history.readAllStandardError()).trimmed();
        if (code != 0 && !err.isEmpty() && !err.contains("No entries"))
            addProblem(tr("Could not read the kernel log: %1").arg(err));
        m_logs.setItems(items);
        recomputeStats();
        emit liveChanged();
        startFollow();
    });
    connect(&m_history, &QProcess::errorOccurred, this, [this](QProcess::ProcessError e) {
        if (e == QProcess::FailedToStart)
            addProblem(tr("journalctl is not installed, so there are no logs to show."));
        emit liveChanged();
    });

    connect(&m_follow, &QProcess::readyReadStandardOutput, this, [this] {
        m_followBuffer += m_follow.readAllStandardOutput();
        int nl;
        while ((nl = m_followBuffer.indexOf('\n')) >= 0) {
            const QByteArray line = m_followBuffer.left(nl);
            m_followBuffer.remove(0, nl + 1);
            LogModel::Item item;
            if (!ingestJson(line, &item))
                continue;
            if (m_paused)
                m_held << item;
            else
                m_logs.append(item);
            m_statsDebounce.start();
        }
    });
    connect(&m_follow, &QProcess::stateChanged, this, &Backend::liveChanged);

    connect(&m_ss, &QProcess::finished, this, [this] {
        QVariantList rows;
        const QString policy = m_defaults.value("input").toString();
        for (const QString &line : QString::fromUtf8(m_ss.readAllStandardOutput()).split('\n')) {
            const QStringList t = line.split(' ', Qt::SkipEmptyParts);
            if (t.size() < 5)
                continue;
            const QString local = t[4];
            const int colon = local.lastIndexOf(':');
            QString address = local.left(colon);
            const int port = local.mid(colon + 1).toInt();
            static const QRegularExpression procName(R"re(users:\(\("([^"]+)")re");
            const auto pm = procName.match(line);
            QVariantMap row;
            row["proto"] = t[0];
            row["address"] = address;
            row["port"] = port;
            row["service"] = Policy::serviceName(port, t[0]);
            row["process"] = pm.hasMatch() ? pm.captured(1) : QString();
            int ruleNumber = 0;
            row["exposure"] = exposure(m_rules, policy, t[0], address, port, &ruleNumber);
            row["rule"] = ruleNumber;
            rows << row;
        }
        std::sort(rows.begin(), rows.end(), [](const QVariant &a, const QVariant &b) {
            return a.toMap()["port"].toInt() < b.toMap()["port"].toInt();
        });
        m_listening = rows;
        emit gatewayChanged();
    });
    connect(&m_systemctl, &QProcess::finished, this, [this] {
        m_gateway["service"] = QString::fromUtf8(m_systemctl.readAllStandardOutput()).trimmed();
        emit gatewayChanged();
    });

    m_gatewayPoll.setInterval(10000);
    connect(&m_gatewayPoll, &QTimer::timeout, this, &Backend::loadGateway);

    reloadPolicy();
    if (m_watchJournal) {
        loadGateway();
        m_gatewayPoll.start();
        loadHistory();
    }
}

Backend::~Backend() {
    for (QProcess *p : {&m_history, &m_follow, &m_ss, &m_systemctl})
        if (p->state() != QProcess::NotRunning) {
            p->kill();
            p->waitForFinished(1000);
        }
}

void Backend::addProblem(const QString &text) {
    if (m_problem.contains(text))
        return;
    m_problem = m_problem.isEmpty() ? text : m_problem + "\n" + text;
    emit problemChanged();
}

static QString actionLabel(const QString &action) {
    if (action == "allow") return "Accept";
    if (action == "deny") return "Drop";
    if (action == "reject") return "Reject";
    if (action == "limit") return "Limit";
    return action;
}

static QString servicesLabel(const Rule &r) {
    if (!r.dapp.isEmpty())
        return r.dapp;
    QStringList parts;
    if (r.dport == "any") {
        if (r.proto == "any") parts << "Any";
        else if (r.proto == "icmp" || r.proto == "ipv6-icmp") parts << (r.extra.isEmpty() ? "icmp" : "icmp " + r.extra);
        else parts << r.proto;
    } else {
        for (const QString &p : r.dport.split(',')) {
            const QString protos = r.proto == "any" ? "tcp+udp" : r.proto;
            const QString port = QString(p).replace(':', '-');
            QString name = p.contains(':') ? QString() : Policy::serviceName(p.toInt(), r.proto == "any" ? "tcp" : r.proto);
            if (name.isEmpty() && r.proto == "any" && !p.contains(':'))
                name = Policy::serviceName(p.toInt(), "udp");
            parts << (name.isEmpty() ? QString("%1/%2").arg(protos, port) : QString("%1 (%2/%3)").arg(name, protos, port));
        }
    }
    QString label = parts.join(", ");
    if (r.sport != "any")
        label += QString(" ← %1").arg(r.sport);
    return label;
}

QVariantMap Backend::ruleMap(const Rule &r) {
    QVariantMap m;
    m["number"] = r.number;
    m["chain"] = r.chain;
    m["name"] = r.comment;
    m["source"] = r.src == "any" ? QString("Any") : r.src;
    m["destination"] = r.dst == "any" ? QString("Any") : r.dst;
    if (!r.sapp.isEmpty()) m["source"] = r.sapp;
    m["services"] = servicesLabel(r);
    m["action"] = actionLabel(r.action);
    m["track"] = r.log ? "Log" : "None";
    m["inIface"] = r.inIface;
    m["outIface"] = r.outIface;
    m["family"] = r.v4 && r.v6 ? "IPv4 + IPv6" : r.v6 ? "IPv6" : "IPv4";
    m["extra"] = r.extra;
    m["proto"] = r.proto;
    m["dport"] = r.dport;
    m["sport"] = r.sport;
    m["key"] = QString::number(r.number);

    // The ufw command that would write this rule, so it can be copied or
    // compared with `sudo ufw status numbered`.
    QString cmd = r.chain == "forward" ? "ufw route " : "ufw ";
    cmd += r.action + (r.log ? " log" : "");
    if (!r.inIface.isEmpty()) cmd += " in on " + r.inIface;
    if (!r.outIface.isEmpty()) cmd += " out on " + r.outIface;
    if (r.chain == "output" && r.outIface.isEmpty()) cmd += " out";
    if (r.proto != "any" && r.dapp.isEmpty()) cmd += " proto " + r.proto;
    cmd += " from " + r.src;
    if (r.sport != "any") cmd += " port " + r.sport;
    cmd += " to " + r.dst;
    if (!r.dapp.isEmpty()) cmd += " app " + r.dapp;
    else if (r.dport != "any") cmd += " port " + r.dport;
    if (!r.comment.isEmpty()) cmd += " comment '" + r.comment + "'";
    m["command"] = cmd;
    return m;
}

void Backend::reloadPolicy() {
    const auto paths = m_watcher.files() + m_watcher.directories();
    if (!paths.isEmpty())
        m_watcher.removePaths(paths);
    for (const QString &p : {m_ufwDirectory, m_ufwDirectory + "/user.rules", m_ufwDirectory + "/user6.rules",
                             m_ufwDirectory + "/ufw.conf", m_defaultsFile})
        if (QFileInfo::exists(p))
            m_watcher.addPath(p);

    const QString v4 = m_ufwDirectory + "/user.rules";
    if (!QFileInfo::exists(v4))
        addProblem(tr("No UFW rules at %1. Is ufw installed?").arg(v4));
    else if (!QFileInfo(v4).isReadable())
        addProblem(tr("%1 is not readable by this user.").arg(v4));

    m_rules = Policy::merge(Policy::readRulesFile(v4, false),
                            Policy::readRulesFile(m_ufwDirectory + "/user6.rules", true));
    m_implied = Policy::readImplied(m_ufwDirectory + "/before.rules");

    const auto defaults = Policy::readKeyValues(m_defaultsFile);
    const auto conf = Policy::readKeyValues(m_ufwDirectory + "/ufw.conf");
    m_defaults = {
        {"input", defaults.value("DEFAULT_INPUT_POLICY", "DROP")},
        {"output", defaults.value("DEFAULT_OUTPUT_POLICY", "ACCEPT")},
        {"forward", defaults.value("DEFAULT_FORWARD_POLICY", "DROP")},
        {"ipv6", defaults.value("IPV6", "yes")},
        {"enabled", conf.value("ENABLED", "no")},
        {"loglevel", conf.value("LOGLEVEL", "low")},
    };

    m_ruleMaps.clear();
    for (const Rule &r : m_rules)
        m_ruleMaps << ruleMap(r);
    m_impliedMaps.clear();
    for (const Rule &r : m_implied)
        m_impliedMaps << ruleMap(r);

    // Rule numbers may have moved, so logs are re-matched to the new rulebase.
    QList<LogModel::Item> items = m_logs.items();
    for (auto &item : items)
        item = itemFor(item.entry);
    if (!items.isEmpty())
        m_logs.setItems(items);

    emit policyChanged();
    recomputeStats();
    if (m_watchJournal)
        loadGateway();
}

void Backend::loadGateway() {
    m_gateway["hostname"] = QSysInfo::machineHostName();
    m_gateway["os"] = QSysInfo::prettyProductName();
    m_gateway["kernel"] = QSysInfo::kernelVersion();
    m_gateway["rules"] = m_rules.size();

    QVariantList ifaces;
    for (const QNetworkInterface &i : QNetworkInterface::allInterfaces()) {
        QStringList addrs;
        for (const auto &e : i.addressEntries())
            addrs << QString("%1/%2").arg(e.ip().toString().section('%', 0, 0)).arg(e.prefixLength());
        ifaces << QVariantMap{{"name", i.name()},
                              {"up", bool(i.flags() & QNetworkInterface::IsRunning)},
                              {"loopback", bool(i.flags() & QNetworkInterface::IsLoopBack)},
                              {"mac", i.hardwareAddress()},
                              {"addresses", addrs.join("  ")}};
    }
    m_gateway["interfaces"] = ifaces;
    emit gatewayChanged();

    if (m_ss.state() == QProcess::NotRunning)
        m_ss.start("ss", {"-tulnHp"});
    if (m_systemctl.state() == QProcess::NotRunning)
        m_systemctl.start("systemctl", {"is-active", "ufw"});
}

LogModel::Item Backend::itemFor(const LogEntry &entry) const {
    LogModel::Item item;
    item.entry = entry;
    item.rule = Policy::matchRule(m_rules, entry);
    if (item.rule >= 0) {
        const Rule &r = m_rules[item.rule];
        item.ruleName = r.comment.isEmpty() ? tr("Rule %1").arg(r.number) : QString("%1 · %2").arg(r.number).arg(r.comment);
    } else {
        const QString chain = entry.chain();
        item.ruleName = chain == "input" ? tr("Cleanup · Incoming") : chain == "output" ? tr("Cleanup · Outgoing")
                                                                                         : tr("Cleanup · Forwarded");
    }
    return item;
}

bool Backend::ingestJson(const QByteArray &line, LogModel::Item *item) const {
    if (line.trimmed().isEmpty())
        return false;
    const QJsonObject o = QJsonDocument::fromJson(line).object();
    const QString message = o.value("MESSAGE").toString();
    const qint64 time = o.value("__REALTIME_TIMESTAMP").toString().toLongLong() / 1000;
    LogEntry entry;
    if (!Policy::parseLog(message, time, &entry))
        return false;
    *item = itemFor(entry);
    return true;
}

void Backend::loadHistory() {
    if (QStandardPaths::findExecutable("journalctl").isEmpty()) {
        addProblem(tr("journalctl is not installed, so there are no logs to show."));
        return;
    }
    m_history.start("journalctl", {"-k", "-o", "json", "--no-pager", "-q", "-S", "-7d", "-n", "20000", "-g", "UFW "});
    emit liveChanged();
}

void Backend::startFollow() {
    if (m_follow.state() != QProcess::NotRunning)
        return;
    m_follow.start("journalctl", {"-k", "-o", "json", "--no-pager", "-q", "-f", "-n", "0", "-g", "UFW "});
}

void Backend::setPaused(bool paused) {
    if (paused == m_paused)
        return;
    m_paused = paused;
    if (!paused) {
        for (const auto &item : std::as_const(m_held))
            m_logs.append(item);
        m_held.clear();
    }
    emit pausedChanged();
}

void Backend::refresh() {
    m_problem.clear();
    emit problemChanged();
    reloadPolicy();
    if (m_watchJournal && m_history.state() == QProcess::NotRunning) {
        if (m_follow.state() != QProcess::NotRunning) {
            m_follow.kill();
            m_follow.waitForFinished(1000);
        }
        m_followBuffer.clear();
        loadHistory();
    }
}

// What reaches a listening socket from the network, judged the way ufw would
// for a new inbound connection from anywhere.
QString Backend::exposure(const QList<Rule> &rules, const QString &policy, const QString &proto,
                          const QString &address, int port, int *ruleNumber) {
    *ruleNumber = 0;
    const QString host = address.section('%', 0, 0).remove('[').remove(']');
    const QHostAddress a(host);
    if (address.contains("%lo") || a.isLoopback())
        return "local";
    for (const Rule &r : rules) {
        if (r.chain != "input" || (r.proto != "any" && r.proto != proto) || !Policy::portMatches(r.dport, port))
            continue;
        if (!r.dst.isEmpty() && r.dst != "any" && host != "*" && host != "0.0.0.0" && host != "::"
            && !Policy::addressMatches(r.dst, host))
            continue;
        *ruleNumber = r.number;
        if (r.action == "allow" || r.action == "limit")
            return r.src == "any" && r.inIface.isEmpty() ? "open" : "restricted";
        return "blocked";
    }
    if (proto == "udp" && (port == 5353 || port == 1900 || port == 68))
        return "implied";
    return policy == "ACCEPT" ? "open" : "blocked";
}

void Backend::recomputeStats() {
    const qint64 now = QDateTime::currentMSecsSinceEpoch();
    const qint64 day = now - 24LL * 3600 * 1000;
    QList<int> hourly(24, 0), hourlyAllowed(24, 0);
    QHash<QString, int> sources, ports, ifaces, hits;
    int blocked = 0, allowed = 0, total = 0;
    for (const auto &item : m_logs.items()) {
        const LogEntry &e = item.entry;
        hits[item.rule >= 0 ? QString::number(m_rules.value(item.rule).number) : "cleanup-" + e.chain()]++;
        if (e.time < day)
            continue;
        ++total;
        const int bucket = std::clamp(int((e.time - day) / (3600 * 1000)), 0, 23);
        if (e.blocked()) {
            ++blocked;
            ++hourly[bucket];
            sources[e.src]++;
            if (e.dpt >= 0) {
                const QString name = Policy::serviceName(e.dpt, e.proto);
                ports[QString("%1/%2").arg(e.proto).arg(e.dpt) + (name.isEmpty() ? "" : "  " + name)]++;
            }
            ifaces[e.in.isEmpty() ? e.out : e.in]++;
        } else {
            ++allowed;
            ++hourlyAllowed[bucket];
        }
    }
    auto top = [](const QHash<QString, int> &counts, int n) {
        QList<QPair<QString, int>> list;
        for (auto it = counts.begin(); it != counts.end(); ++it)
            list << qMakePair(it.key(), it.value());
        std::sort(list.begin(), list.end(), [](auto &a, auto &b) { return a.second > b.second || (a.second == b.second && a.first < b.first); });
        QVariantList out;
        for (int i = 0; i < list.size() && i < n; ++i)
            out << QVariantMap{{"label", list[i].first}, {"count", list[i].second}};
        return out;
    };
    QVariantList hourlyList, hourlyAllowedList;
    int peak = 1;
    for (int i = 0; i < 24; ++i) {
        hourlyList << hourly[i];
        hourlyAllowedList << hourlyAllowed[i];
        peak = std::max(peak, hourly[i] + hourlyAllowed[i]);
    }
    m_stats = {{"total", total}, {"blocked", blocked}, {"allowed", allowed}, {"sources", sources.size()},
               {"hourly", hourlyList}, {"hourlyAllowed", hourlyAllowedList}, {"peak", peak},
               {"topSources", top(sources, 6)}, {"topPorts", top(ports, 6)}, {"topIfaces", top(ifaces, 4)},
               {"stored", m_logs.total()}};
    m_hits.clear();
    for (auto it = hits.begin(); it != hits.end(); ++it)
        m_hits.insert(it.key(), it.value());
    emit statsChanged();
}
