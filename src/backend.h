#pragma once

#include <QFileSystemWatcher>
#include <QObject>
#include <QProcess>
#include <QTimer>
#include <QVariantList>
#include <QVariantMap>

#include "logmodel.h"
#include "policy.h"

// Reads this machine's UFW firewall the way Check Point SmartConsole shows a
// gateway: the rulebase, the logs, and the gateway itself. Everything comes
// from files and tools a normal user can read, so it never needs root and
// never changes the firewall.
class Backend : public QObject {
    Q_OBJECT
    Q_PROPERTY(QVariantList rules READ rules NOTIFY policyChanged)
    Q_PROPERTY(QVariantList implied READ implied NOTIFY policyChanged)
    Q_PROPERTY(QVariantMap defaults READ defaults NOTIFY policyChanged)
    Q_PROPERTY(QVariantMap gateway READ gateway NOTIFY gatewayChanged)
    Q_PROPERTY(QVariantList listening READ listening NOTIFY gatewayChanged)
    Q_PROPERTY(QVariantMap hits READ hits NOTIFY statsChanged)
    Q_PROPERTY(QVariantMap stats READ stats NOTIFY statsChanged)
    Q_PROPERTY(LogModel *logs READ logs CONSTANT)
    Q_PROPERTY(bool paused READ paused WRITE setPaused NOTIFY pausedChanged)
    Q_PROPERTY(bool live READ live NOTIFY liveChanged)
    Q_PROPERTY(bool loadingLogs READ loadingLogs NOTIFY liveChanged)
    Q_PROPERTY(QString problem READ problem NOTIFY problemChanged)

public:
    explicit Backend(const QString &ufwDirectory = "/etc/ufw", const QString &defaultsFile = "/etc/default/ufw",
                     bool watchJournal = true, QObject *parent = nullptr);
    ~Backend() override;

    QVariantList rules() const { return m_ruleMaps; }
    QVariantList implied() const { return m_impliedMaps; }
    QVariantMap defaults() const { return m_defaults; }
    QVariantMap gateway() const { return m_gateway; }
    QVariantList listening() const { return m_listening; }
    QVariantMap hits() const { return m_hits; }
    QVariantMap stats() const { return m_stats; }
    LogModel *logs() { return &m_logs; }
    bool paused() const { return m_paused; }
    void setPaused(bool paused);
    bool live() const { return m_follow.state() == QProcess::Running; }
    bool loadingLogs() const { return m_history.state() != QProcess::NotRunning; }
    QString problem() const { return m_problem; }

    Q_INVOKABLE void refresh();
    Q_INVOKABLE void reloadPolicy();

    // Turns one line of `journalctl -o json` into a log item; for tests too.
    bool ingestJson(const QByteArray &line, LogModel::Item *item) const;
    static QVariantMap ruleMap(const Rule &rule);
    static QString exposure(const QList<Rule> &rules, const QString &policy, const QString &proto,
                            const QString &address, int port, int *ruleNumber);
    void recomputeStats();

signals:
    void policyChanged();
    void gatewayChanged();
    void statsChanged();
    void pausedChanged();
    void liveChanged();
    void problemChanged();

private:
    void loadGateway();
    void loadHistory();
    void startFollow();
    void addProblem(const QString &text);
    LogModel::Item itemFor(const LogEntry &entry) const;

    QString m_ufwDirectory, m_defaultsFile;
    bool m_watchJournal;
    QList<Rule> m_rules, m_implied;
    QVariantList m_ruleMaps, m_impliedMaps, m_listening;
    QVariantMap m_defaults, m_gateway, m_hits, m_stats;
    LogModel m_logs;
    QProcess m_history, m_follow, m_ss, m_systemctl;
    QByteArray m_followBuffer;
    QList<LogModel::Item> m_held;
    bool m_paused = false;
    QString m_problem;
    QFileSystemWatcher m_watcher;
    QTimer m_policyDebounce, m_statsDebounce, m_gatewayPoll;
};
