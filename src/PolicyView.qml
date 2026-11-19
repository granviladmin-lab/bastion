import QtQuick
import QtQuick.Controls
import QtQuick.Controls.Material
import QtQuick.Layouts

// The rulebase, laid out like Check Point's Access Control policy: one
// section per chain, each ending in its cleanup rule (ufw's default policy).
Item {
    id: root
    property bool showImplied: false
    property var selected: null

    function focusSearch() { search.forceActiveFocus(); search.selectAll() }
    function dismiss() {
        if (search.text !== "") search.text = ""
        else if (selected) { selected = null; table.currentIndex = -1 }
        search.focus = false
        table.forceActiveFocus()
    }

    // Columns, shared by the header and every row.
    readonly property var cols: [
        { key: "no", title: qsTr("No."), w: 56 },
        { key: "hits", title: qsTr("Hits"), w: 64 },
        { key: "name", title: qsTr("Name"), w: 180 },
        { key: "source", title: qsTr("Source"), w: 160 },
        { key: "destination", title: qsTr("Destination"), w: 130 },
        { key: "services", title: qsTr("Services & Applications"), w: -1 },
        { key: "action", title: qsTr("Action"), w: 104 },
        { key: "track", title: qsTr("Track"), w: 72 },
        { key: "direction", title: qsTr("Direction"), w: 200 },
        { key: "family", title: qsTr("IP Version"), w: 110 }
    ]
    function colWidth(i, total) {
        // Fixed columns shrink together when the window is narrow, so the
        // flexible column keeps its minimum and nothing runs off the edge.
        let kept = 0, scalable = 0
        for (let k = 0; k < cols.length; ++k)
            if (cols[k].w > 0) { if (cols[k].keep) kept += cols[k].w; else scalable += cols[k].w }
        const factor = Math.min(1, Math.max(0.6, (total - 180 - kept) / scalable))
        if (cols[i].w > 0) return cols[i].keep ? cols[i].w : Math.floor(cols[i].w * factor)
        return Math.max(180, total - kept - Math.floor(scalable * factor))
    }

    function chainTitle(chain) {
        return chain === "input" ? qsTr("Incoming traffic") : chain === "output" ? qsTr("Outgoing traffic")
             : qsTr("Forwarded traffic")
    }
    function policyAction(p) {
        return p === "ACCEPT" ? "Accept" : p === "REJECT" ? "Reject" : "Drop"
    }
    function directionLabel(r) {
        if (r.chain === "forward")
            return (r.inIface || qsTr("any")) + "  →  " + (r.outIface || qsTr("any"))
        const base = r.chain === "input" ? qsTr("Inbound") : qsTr("Outbound")
        const iface = r.chain === "input" ? r.inIface : r.outIface
        return iface ? qsTr("%1 on %2").arg(base).arg(iface) : base
    }
    function matchesSearch(r) {
        const q = search.text.trim().toLowerCase()
        if (q === "") return true
        const hay = [r.number, r.name, r.source, r.destination, r.services, r.action, r.track,
                     r.inIface, r.outIface, r.family, r.extra, r.command].join(" ").toLowerCase()
        return q.split(/\s+/).every(t => hay.indexOf(t) >= 0)
    }

    // Flatten sections, rules and cleanup rules into one list of rows.
    readonly property var rows: {
        const out = []
        if (showImplied) {
            out.push({ kind: "section", title: qsTr("Implied rules"), note: qsTr("from /etc/ufw/before.rules, evaluated first") })
            for (const r of backend.implied) {
                if (!matchesSearch(r)) continue
                const row = Object.assign({}, r)
                row.kind = "implied"
                row.no = "i" + r.number
                row.direction = directionLabel(r)
                if (r.extra && r.proto !== "icmp") row.name = r.extra.toLowerCase().replace(",", ", ")
                row.family = "IPv4"
                out.push(row)
            }
        }
        for (const chain of ["input", "output", "forward"]) {
            const list = backend.rules.filter(r => r.chain === chain)
            const first = list.length ? list[0].number : 0
            const last = list.length ? list[list.length - 1].number : 0
            out.push({ kind: "section", title: chainTitle(chain),
                       note: !list.length ? qsTr("no rules") : first === last ? qsTr("rule %1").arg(first)
                                                         : qsTr("rules %1–%2").arg(first).arg(last) })
            for (const r of list) {
                if (!matchesSearch(r)) continue
                const row = Object.assign({}, r)
                row.kind = "rule"
                row.no = r.number
                row.direction = directionLabel(r)
                row.family = r.family
                out.push(row)
            }
            const p = backend.defaults[chain]
            const cleanup = {
                kind: "cleanup", chain: chain, no: "", key: "cleanup-" + chain,
                name: qsTr("Cleanup rule"), source: "Any", destination: "Any", services: "Any",
                action: policyAction(p),
                track: p !== "ACCEPT" && backend.defaults.loglevel !== "off" && chain !== "output" ? "Log" : "None",
                direction: directionLabel({ chain: chain }),
                family: backend.defaults.ipv6 === "yes" ? "IPv4 + IPv6" : "IPv4",
                command: "ufw default " + (p === "ACCEPT" ? "allow" : p === "REJECT" ? "reject" : "deny")
                         + " " + (chain === "input" ? "incoming" : chain === "output" ? "outgoing" : "routed")
            }
            if (matchesSearch(cleanup)) out.push(cleanup)
        }
        return out
    }

    ColumnLayout {
        anchors.fill: parent
        spacing: 0

        // Toolbar.
        Rectangle {
            Layout.fillWidth: true
            Layout.preferredHeight: 70
            color: c.bg
            RowLayout {
                anchors { fill: parent; leftMargin: 18; rightMargin: 18 }
                spacing: 14
                Column {
                    Text { text: qsTr("Access Control"); color: c.dim; font.pixelSize: 11 }
                    Text { text: qsTr("Policy"); color: c.text; font.pixelSize: 18; font.bold: true }
                }
                Item { Layout.preferredWidth: 10 }
                TextField {
                    id: search
                    Layout.preferredWidth: 340
                    placeholderText: qsTr("Search for IP, port, name… (/)")
                    selectByMouse: true
                    Keys.onDownPressed: { table.forceActiveFocus(); table.currentIndex = root.nextRule(-1, 1) }
                }
                Text { text: qsTr("%n rules", "", backend.rules.length); color: c.dim; font.pixelSize: 12 }
                Item { Layout.fillWidth: true }
                Switch {
                    text: qsTr("Implied rules (I)")
                    checked: root.showImplied
                    onToggled: root.showImplied = checked
                }
            }
        }

        // Header row.
        Rectangle {
            Layout.fillWidth: true
            Layout.preferredHeight: 34
            color: c.raised
            Row {
                anchors.fill: parent
                Repeater {
                    model: root.cols
                    delegate: Item {
                        required property var modelData
                        required property int index
                        width: root.colWidth(index, parent.width); height: 34
                        Text {
                            anchors { verticalCenter: parent.verticalCenter; left: parent.left; leftMargin: 12 }
                            text: modelData.title; color: c.dim; font.pixelSize: 12; font.bold: true
                        }
                        Rectangle { anchors.right: parent.right; width: 1; height: parent.height; color: c.line }
                    }
                }
            }
            Rectangle { anchors.bottom: parent.bottom; width: parent.width; height: 1; color: c.line }
        }

        ListView {
            id: table
            Layout.fillWidth: true
            Layout.fillHeight: true
            clip: true
            model: root.rows
            currentIndex: -1
            boundsBehavior: Flickable.StopAtBounds
            ScrollBar.vertical: ScrollBar { }
            keyNavigationEnabled: false
            focus: true

            Keys.onUpPressed: { const i = root.nextRule(currentIndex, -1); if (i >= 0) currentIndex = i }
            Keys.onDownPressed: { const i = root.nextRule(currentIndex, 1); if (i >= 0) currentIndex = i }
            onCurrentIndexChanged: root.selected = currentIndex >= 0 ? root.rows[currentIndex] : null

            delegate: Loader {
                required property var modelData
                required property int index
                width: ListView.view.width
                sourceComponent: modelData.kind === "section" ? sectionRow : ruleRow
                property var row: modelData
                property int rowIndex: index

                // Declared inside the delegate so they see row and rowIndex.
            Component {
                id: sectionRow
                Rectangle {
                    height: 32
                    color: Qt.rgba(Material.accentColor.r, Material.accentColor.g, Material.accentColor.b, 0.10)
                    Rectangle { width: 3; height: parent.height; color: theme.accent }
                    Row {
                        anchors { verticalCenter: parent.verticalCenter; left: parent.left; leftMargin: 16 }
                        spacing: 12
                        Text { text: row.title; color: c.text; font.pixelSize: 13; font.bold: true }
                        Text { text: row.note; color: c.dim; font.pixelSize: 12; anchors.baseline: parent.children[0].baseline }
                    }
                    Rectangle { anchors.bottom: parent.bottom; width: parent.width; height: 1; color: c.line }
                }
            }

            Component {
                id: ruleRow
                Rectangle {
                    id: rr
                    readonly property bool current: table.currentIndex === rowIndex
                    height: 40
                    color: current ? "#25252e" : rowHover.hovered ? "#18181d" : row.kind === "cleanup" ? "#121215" : c.bg
                    HoverHandler { id: rowHover }
                    TapHandler { onTapped: { table.currentIndex = rowIndex; table.forceActiveFocus() } }
                    Rectangle { visible: rr.current; width: 3; height: parent.height; color: theme.accent }

                    Row {
                        anchors.fill: parent
                        Repeater {
                            model: root.cols
                            delegate: Item {
                                required property var modelData
                                required property int index
                                width: root.colWidth(index, rr.width); height: rr.height
                                clip: true

                                // Plain text cells.
                                Text {
                                    visible: ["action", "hits", "track"].indexOf(modelData.key) < 0
                                    anchors { verticalCenter: parent.verticalCenter; left: parent.left; right: parent.right; leftMargin: 12; rightMargin: 8 }
                                    elide: Text.ElideRight
                                    text: {
                                        const v = row[modelData.key]
                                        return v === undefined || v === null ? "" : String(v)
                                    }
                                    color: modelData.key === "no" || modelData.key === "family" ? c.dim
                                         : (modelData.key === "source" || modelData.key === "destination") && row[modelData.key] === "Any" ? c.dim
                                         : c.text
                                    font.pixelSize: 13
                                    font.family: ["source", "destination"].indexOf(modelData.key) >= 0 && row[modelData.key] !== "Any" ? c.mono : Qt.application.font.family
                                    font.italic: modelData.key === "name" && row.kind === "cleanup"
                                }
                                // Hits.
                                Text {
                                    visible: modelData.key === "hits"
                                    anchors { verticalCenter: parent.verticalCenter; left: parent.left; leftMargin: 12 }
                                    readonly property int n: root.hitsFor(row)
                                    text: row.kind === "implied" ? "" : n.toLocaleString(Qt.locale(), 'f', 0)
                                    color: n > 0 ? c.info : c.dim
                                    font.pixelSize: 12; font.family: c.mono
                                }
                                // Action with an icon, colored the Check Point way.
                                Row {
                                    visible: modelData.key === "action"
                                    anchors { verticalCenter: parent.verticalCenter; left: parent.left; leftMargin: 12 }
                                    spacing: 7
                                    Text {
                                        text: row.action === "Accept" ? "" : row.action === "Limit" ? "" : ""
                                        font.family: c.icons; font.pixelSize: 13
                                        color: c.actionColor(row.action)
                                    }
                                    Text { text: row.action || ""; color: c.actionColor(row.action); font.pixelSize: 13; font.bold: true }
                                }
                                // Track.
                                Row {
                                    visible: modelData.key === "track"
                                    anchors { verticalCenter: parent.verticalCenter; left: parent.left; leftMargin: 12 }
                                    spacing: 6
                                    Text {
                                        text: row.track === "Log" ? "" : "—"
                                        font.family: c.icons; font.pixelSize: 12
                                        color: row.track === "Log" ? c.text : c.dim
                                    }
                                    Text { visible: row.track === "Log"; text: qsTr("Log"); color: c.text; font.pixelSize: 13 }
                                }
                            }
                        }
                    }
                    Rectangle { anchors.bottom: parent.bottom; width: parent.width; height: 1; color: c.line; opacity: 0.6 }
                }
            }
            }
        }

        // Details of the selected rule, like SmartConsole's summary pane.
        Rectangle {
            Layout.fillWidth: true
            Layout.preferredHeight: root.selected ? detail.implicitHeight + 28 : 0
            visible: root.selected !== null
            color: c.panel
            Rectangle { width: parent.width; height: 1; color: c.line }
            ColumnLayout {
                id: detail
                anchors { left: parent.left; right: parent.right; top: parent.top; margins: 16 }
                spacing: 8
                RowLayout {
                    spacing: 12
                    Text {
                        text: root.selected ? (root.selected.kind === "cleanup" ? qsTr("Cleanup rule")
                              : root.selected.kind === "implied" ? qsTr("Implied rule %1").arg(root.selected.number)
                              : qsTr("Rule %1").arg(root.selected.number)) : ""
                        color: c.text; font.pixelSize: 15; font.bold: true
                    }
                    Text { text: root.selected && root.selected.name ? root.selected.name : ""; color: c.dim; font.pixelSize: 14 }
                    Pill {
                        visible: root.selected !== null
                        text: root.selected ? root.selected.action : ""
                        tint: c.actionColor(root.selected ? root.selected.action : "")
                    }
                    Item { Layout.fillWidth: true }
                    Text {
                        visible: root.selected !== null && root.selected.kind !== "implied"
                        text: qsTr("%n hits", "", root.hitsFor(root.selected)) + "  " + qsTr("in the logged traffic")
                        color: c.dim; font.pixelSize: 12
                    }
                    ToolButton { text: ""; font.family: c.icons; onClicked: root.dismiss() }
                }
                Text {
                    Layout.fillWidth: true
                    wrapMode: Text.Wrap
                    color: c.text; font.pixelSize: 13
                    text: root.selected ? root.explain(root.selected) : ""
                }
                RowLayout {
                    visible: root.selected !== null && root.selected.command !== undefined
                    spacing: 10
                    Text { text: qsTr("ufw equivalent"); color: c.dim; font.pixelSize: 12 }
                    TextEdit {
                        text: root.selected && root.selected.command ? "sudo " + root.selected.command : ""
                        readOnly: true; selectByMouse: true
                        color: theme.accent; font.family: c.mono; font.pixelSize: 12
                    }
                    Item { Layout.fillWidth: true }
                    Button {
                        flat: true
                        visible: root.selected !== null && root.selected.kind !== "implied"
                        text: qsTr("Show matching logs")
                        onClicked: win.openLogs(root.selected.kind === "cleanup" ? "rule:cleanup dir:" + root.selected.chain
                                                                                 : "rule:" + root.selected.number)
                    }
                }
            }
        }
    }

    function hitsFor(r) {
        if (!r) return 0
        const k = r.kind === "cleanup" ? "cleanup-" + r.chain : String(r.number)
        return backend.hits[k] || 0
    }
    function nextRule(from, step) {
        for (let i = from + step; i >= 0 && i < rows.length; i += step)
            if (rows[i].kind !== "section") return i
        return -1
    }
    function explain(r) {
        const verb = r.action === "Accept" ? qsTr("accepts") : r.action === "Limit" ? qsTr("rate-limits (6 connections in 30 s, then rejects)")
                   : r.action === "Reject" ? qsTr("rejects") : qsTr("silently drops")
        const what = r.services === "Any" ? qsTr("all traffic") : r.services
        const from = r.source === "Any" ? qsTr("any source") : r.source
        const to = r.destination === "Any" ? qsTr("any destination") : r.destination
        let text = qsTr("%1 %2 %3 from %4 to %5.").arg(r.direction).arg(verb).arg(what).arg(from).arg(to)
        if (r.kind === "cleanup")
            text += " " + qsTr("This is ufw's default policy: anything no rule above matched ends here.")
        if (r.extra) text += " " + qsTr("Match: %1.").arg(r.extra)
        if (r.kind === "rule") text += " " + qsTr("Applies to %1.").arg(r.family)
        if (r.track === "Log") text += " " + qsTr("Matches are logged to the kernel log.")
        return text
    }

}
