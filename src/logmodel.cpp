#include "logmodel.h"

#include <QDateTime>
#include <algorithm>

LogModel::LogModel(QObject *parent) : QAbstractListModel(parent) {}

int LogModel::rowCount(const QModelIndex &parent) const {
    return parent.isValid() ? 0 : m_visible.size();
}

static QString serviceLabel(const LogEntry &e) {
    if (e.dpt < 0)
        return e.proto.toUpper();
    const QString name = Policy::serviceName(e.dpt, e.proto);
    const QString port = QString("%1/%2").arg(e.proto).arg(e.dpt);
    return name.isEmpty() ? port : QString("%1 (%2)").arg(name, port);
}

QVariant LogModel::data(const QModelIndex &index, int role) const {
    if (!index.isValid() || index.row() >= m_visible.size())
        return {};
    const Item &item = m_entries[m_visible[index.row()]];
    const LogEntry &e = item.entry;
    switch (role) {
    case TimeRole: return QDateTime::fromMSecsSinceEpoch(e.time);
    case ActionRole: return e.action;
    case BlockedRole: return e.blocked();
    case ChainRole: return e.chain();
    case InRole: return e.in;
    case OutRole: return e.out;
    case SrcRole: return e.src;
    case DstRole: return e.dst;
    case ProtoRole: return e.proto;
    case SptRole: return e.spt;
    case DptRole: return e.dpt;
    case ServiceRole: return serviceLabel(e);
    case LenRole: return e.len;
    case TtlRole: return e.ttl;
    case FlagsRole: return e.flags;
    case MacRole: return e.mac;
    case MessageRole: return e.message;
    case RuleRole: return item.rule;
    case RuleNameRole: return item.ruleName;
    }
    return {};
}

QHash<int, QByteArray> LogModel::roleNames() const {
    return {{TimeRole, "time"}, {ActionRole, "action"}, {BlockedRole, "blocked"}, {ChainRole, "chain"},
            {InRole, "inIface"}, {OutRole, "outIface"}, {SrcRole, "src"}, {DstRole, "dst"},
            {ProtoRole, "proto"}, {SptRole, "spt"}, {DptRole, "dpt"}, {ServiceRole, "service"},
            {LenRole, "len"}, {TtlRole, "ttl"}, {FlagsRole, "flags"}, {MacRole, "mac"},
            {MessageRole, "message"}, {RuleRole, "rule"}, {RuleNameRole, "ruleName"}};
}

QVariantMap LogModel::get(int row) const {
    QVariantMap map;
    if (row < 0 || row >= m_visible.size())
        return map;
    const auto names = roleNames();
    for (auto it = names.begin(); it != names.end(); ++it)
        map.insert(QString::fromLatin1(it.value()), data(index(row), it.key()));
    return map;
}

void LogModel::setQuery(const QString &query) {
    if (query == m_query)
        return;
    m_query = query;
    emit queryChanged();
    refilter();
}

void LogModel::setHours(int hours) {
    if (hours == m_hours)
        return;
    m_hours = hours;
    emit hoursChanged();
    refilter();
}

static bool termMatches(const QString &term, const LogModel::Item &item) {
    const LogEntry &e = item.entry;
    const int colon = term.indexOf(':');
    const QString key = colon > 0 ? term.left(colon).toLower() : QString();
    const QString value = colon > 0 ? term.mid(colon + 1) : term;
    auto addr = [&](const QString &a) {
        return value.contains('/') ? Policy::addressMatches(value, a) : a.startsWith(value);
    };
    if (key == "src" || key == "source") return addr(e.src);
    if (key == "dst" || key == "destination") return addr(e.dst);
    if (key == "ip") return addr(e.src) || addr(e.dst);
    if (key == "port" || key == "dport" || key == "service")
        return Policy::portMatches(value, e.dpt) || serviceLabel(e).contains(value, Qt::CaseInsensitive);
    if (key == "sport") return Policy::portMatches(value, e.spt);
    if (key == "proto") return e.proto.compare(value, Qt::CaseInsensitive) == 0;
    if (key == "action") {
        const QString v = value.toLower();
        if (v == "drop" || v == "block" || v == "deny") return e.blocked();
        if (v == "accept" || v == "allow") return !e.blocked();
        return e.action.contains(value, Qt::CaseInsensitive);
    }
    if (key == "in" || key == "iface" || key == "interface")
        return e.in.startsWith(value) || e.out.startsWith(value);
    if (key == "dir" || key == "direction") {
        const QString v = value.toLower();
        const QString chain = v.startsWith("in") ? "input" : v.startsWith("out") ? "output" : "forward";
        return e.chain() == chain;
    }
    if (key == "rule")
        return value.toLower() == "cleanup" ? item.rule < 0 : QString::number(item.rule + 1) == value
                                                                 || item.ruleName.contains(value, Qt::CaseInsensitive);
    return e.message.contains(term, Qt::CaseInsensitive) || item.ruleName.contains(term, Qt::CaseInsensitive)
        || serviceLabel(e).contains(term, Qt::CaseInsensitive);
}

bool LogModel::accepts(const Item &item, qint64 now) const {
    if (m_hours > 0 && item.entry.time < now - qint64(m_hours) * 3600 * 1000)
        return false;
    for (QString term : m_query.split(' ', Qt::SkipEmptyParts)) {
        bool negate = term.startsWith('!') || term.startsWith('-');
        if (negate)
            term = term.mid(1);
        if (term.isEmpty())
            continue;
        if (termMatches(term, item) == negate)
            return false;
    }
    return true;
}

void LogModel::refilter() {
    const qint64 now = QDateTime::currentMSecsSinceEpoch();
    beginResetModel();
    m_visible.clear();
    for (int i = m_entries.size() - 1; i >= 0; --i)
        if (accepts(m_entries[i], now))
            m_visible << i;
    endResetModel();
    emit countChanged();
}

void LogModel::setItems(const QList<Item> &items) {
    m_entries = items;
    std::stable_sort(m_entries.begin(), m_entries.end(),
                     [](const Item &a, const Item &b) { return a.entry.time < b.entry.time; });
    refilter();
}

void LogModel::append(const Item &item) {
    m_entries << item;
    if (accepts(item, QDateTime::currentMSecsSinceEpoch())) {
        beginInsertRows({}, 0, 0);
        m_visible.prepend(m_entries.size() - 1);
        endInsertRows();
    }
    emit countChanged();
}
