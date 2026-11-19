#pragma once

#include <QAbstractListModel>
#include <QList>

#include "policy.h"

// Logged packets, newest first, behind a Check Point style query:
// "src:10.0.0.5 dport:22 action:block" plus free text, "!" to negate a term.
class LogModel : public QAbstractListModel {
    Q_OBJECT
    Q_PROPERTY(QString query READ query WRITE setQuery NOTIFY queryChanged)
    Q_PROPERTY(int hours READ hours WRITE setHours NOTIFY hoursChanged)
    Q_PROPERTY(int count READ count NOTIFY countChanged)
    Q_PROPERTY(int total READ total NOTIFY countChanged)

public:
    enum Roles {
        TimeRole = Qt::UserRole + 1, ActionRole, BlockedRole, ChainRole, InRole, OutRole,
        SrcRole, DstRole, ProtoRole, SptRole, DptRole, ServiceRole, LenRole, TtlRole,
        FlagsRole, MacRole, MessageRole, RuleRole, RuleNameRole
    };

    explicit LogModel(QObject *parent = nullptr);

    int rowCount(const QModelIndex &parent = {}) const override;
    QVariant data(const QModelIndex &index, int role) const override;
    QHash<int, QByteArray> roleNames() const override;

    QString query() const { return m_query; }
    void setQuery(const QString &query);
    int hours() const { return m_hours; }
    void setHours(int hours);
    int count() const { return m_visible.size(); }
    int total() const { return m_entries.size(); }

    Q_INVOKABLE QVariantMap get(int row) const;

    // Entries carry the rulebase index they matched (-1 = cleanup rule) and
    // that rule's display name, so the table and filter can show them.
    struct Item {
        LogEntry entry;
        int rule = -1;
        QString ruleName;
    };
    void setItems(const QList<Item> &items);   // any order; kept oldest first
    void append(const Item &item);
    const QList<Item> &items() const { return m_entries; }

    bool accepts(const Item &item, qint64 now) const;

signals:
    void queryChanged();
    void hoursChanged();
    void countChanged();

private:
    void refilter();

    QList<Item> m_entries;   // oldest first
    QList<int> m_visible;    // indexes into m_entries, newest first
    QString m_query;
    int m_hours = 24;
};
