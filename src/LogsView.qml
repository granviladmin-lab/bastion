import QtQuick
import QtQuick.Controls
import QtQuick.Controls.Material
import QtQuick.Layouts

// Logs & Monitor: every packet ufw logged, newest first, with a query bar,
// a 24 hour timeline, and a log card for the selected entry.
Item {
    id: root
    property var selected: null

    function focusSearch() { query.forceActiveFocus(); query.selectAll() }
    function dismiss() {
        if (selected) { selected = null; table.currentIndex = -1 }
        else if (query.text !== "") backend.logs.query = ""
        query.focus = false
        table.forceActiveFocus()
    }
    function addTerm(term) {
        const q = backend.logs.query.trim()
        backend.logs.query = q === "" ? term : q + " " + term
    }

    readonly property var cols: [
        { title: qsTr("Time"), w: 150, keep: true },
        { title: qsTr("Action"), w: 96 },
        { title: qsTr("Direction"), w: 96 },
        { title: qsTr("Interface"), w: 130 },
        { title: qsTr("Source"), w: 150 },
        { title: qsTr("Destination"), w: 150 },
        { title: qsTr("Service"), w: -1 },
        { title: qsTr("Rule"), w: 170 }
    ]
    function colWidth(i, total) {
        // Fixed columns shrink together when the window is narrow, so the
        // flexible column keeps its minimum and nothing runs off the edge.
        let kept = 0, scalable = 0
        for (let k = 0; k < cols.length; ++k)
            if (cols[k].w > 0) { if (cols[k].keep) kept += cols[k].w; else scalable += cols[k].w }
        const factor = Math.min(1, Math.max(0.6, (total - 150 - kept) / scalable))
        if (cols[i].w > 0) return cols[i].keep ? cols[i].w : Math.floor(cols[i].w * factor)
        return Math.max(150, total - kept - Math.floor(scalable * factor))
    }
    function chainLabel(ch) {
        return ch === "input" ? qsTr("Inbound") : ch === "output" ? qsTr("Outbound") : qsTr("Forward")
    }
    function actionLabel(a) {
        return a === "BLOCK" ? qsTr("Drop") : a === "ALLOW" ? qsTr("Accept") : a === "LIMIT BLOCK" ? qsTr("Limit") : a
    }

    ColumnLayout {
        anchors.fill: parent
        spacing: 0

        // Query bar.
        Rectangle {
            Layout.fillWidth: true
            Layout.preferredHeight: 70
            color: c.bg
            RowLayout {
                anchors { fill: parent; leftMargin: 18; rightMargin: 18 }
                spacing: 14
                Column {
                    Text { text: qsTr("Logs & Monitor"); color: c.dim; font.pixelSize: 11 }
                    Text { text: qsTr("Logs"); color: c.text; font.pixelSize: 18; font.bold: true }
                }
                Item { Layout.preferredWidth: 10 }
                ComboBox {
                    id: range
                    Layout.preferredWidth: 170
                    textRole: "text"
                    valueRole: "hours"
                    model: [
                        { text: qsTr("Last hour"), hours: 1 },
                        { text: qsTr("Last 24 hours"), hours: 24 },
                        { text: qsTr("Last 7 days"), hours: 0 }
                    ]
                    Component.onCompleted: currentIndex = indexOfValue(backend.logs.hours)
                    onActivated: backend.logs.hours = currentValue
                }
                TextField {
                    id: query
                    Layout.fillWidth: true
                    placeholderText: qsTr("Enter search query, e.g. src:10.0.0.5 port:22 action:drop !proto:udp  (/)")
                    text: backend.logs.query
                    selectByMouse: true
                    font.family: text !== "" ? c.mono : Qt.application.font.family
                    onTextEdited: backend.logs.query = text
                    Keys.onDownPressed: { table.forceActiveFocus(); if (table.count) table.currentIndex = 0 }
                }
                Text {
                    text: qsTr("%1 of %2").arg(backend.logs.count.toLocaleString(Qt.locale(), 'f', 0))
                                          .arg(backend.logs.total.toLocaleString(Qt.locale(), 'f', 0))
                    color: c.dim; font.pixelSize: 12
                }
                Button {
                    flat: true
                    text: (backend.paused ? "  " + qsTr("Resume") : "  " + qsTr("Pause"))
                    font.family: c.icons
                    onClicked: backend.paused = !backend.paused
                    ToolTip.visible: hovered; ToolTip.text: qsTr("Pause live logs (Space)")
                }
            }
        }

        // Timeline of the last 24 hours, drops stacked over accepts.
        Rectangle {
            Layout.fillWidth: true
            Layout.preferredHeight: 74
            color: c.panel
            Rectangle { width: parent.width; height: 1; color: c.line }
            Text {
                anchors { left: parent.left; top: parent.top; leftMargin: 18; topMargin: 8 }
                text: qsTr("Timeline · last 24 hours")
                color: c.dim; font.pixelSize: 11
            }
            Row {
                anchors { left: parent.left; right: parent.right; bottom: parent.bottom; leftMargin: 18; rightMargin: 18; bottomMargin: 18 }
                height: 38
                spacing: 3
                Repeater {
                    model: 24
                    delegate: Item {
                        required property int index
                        readonly property int dropped: (backend.stats.hourly || [])[index] || 0
                        readonly property int accepted: (backend.stats.hourlyAllowed || [])[index] || 0
                        readonly property real unit: 38 / (backend.stats.peak || 1)
                        width: (parent.width - 23 * 3) / 24
                        height: 38
                        Rectangle { anchors.bottom: parent.bottom; width: parent.width; height: 1; color: c.line }
                        Rectangle {
                            id: dropBar
                            anchors.bottom: parent.bottom
                            width: parent.width
                            height: dropped > 0 ? Math.max(2, dropped * unit) : 0
                            color: c.drop; opacity: 0.85
                            radius: Math.min(2, theme.radius)
                        }
                        Rectangle {
                            anchors.bottom: dropBar.top
                            width: parent.width
                            height: accepted > 0 ? Math.max(2, accepted * unit) : 0
                            color: c.accept; opacity: 0.85
                        }
                        HoverHandler { id: barHover }
                        ToolTip.visible: barHover.hovered
                        ToolTip.text: qsTr("%1 h ago: %2 dropped, %3 accepted").arg(24 - index).arg(dropped).arg(accepted)
                    }
                }
            }
            Text {
                anchors { right: parent.right; bottom: parent.bottom; rightMargin: 18; bottomMargin: 3 }
                text: qsTr("now"); color: c.dim; font.pixelSize: 10
            }
            Text {
                anchors { left: parent.left; bottom: parent.bottom; leftMargin: 18; bottomMargin: 3 }
                text: qsTr("24 h ago"); color: c.dim; font.pixelSize: 10
            }
        }

        RowLayout {
            Layout.fillWidth: true
            Layout.fillHeight: true
            spacing: 0

            ColumnLayout {
                Layout.fillWidth: true
                Layout.fillHeight: true
                spacing: 0

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
                    model: backend.logs
                    currentIndex: -1
                    focus: true
                    boundsBehavior: Flickable.StopAtBounds
                    highlightMoveDuration: 0
                    ScrollBar.vertical: ScrollBar { }
                    reuseItems: true
                    onCurrentIndexChanged: root.selected = currentIndex >= 0 ? backend.logs.get(currentIndex) : null

                    Connections {
                        target: backend.logs
                        // A filter change rebuilds the rows, so the old selection is gone.
                        function onModelReset() { table.currentIndex = -1 }
                    }

                    Text {
                        anchors.centerIn: parent
                        visible: table.count === 0
                        color: c.dim; font.pixelSize: 14
                        horizontalAlignment: Text.AlignHCenter
                        text: backend.loadingLogs ? qsTr("Reading the kernel log…")
                            : backend.logs.total === 0 ? qsTr("No firewall logs in the last 7 days.\nufw logs blocked packets while logging is on (sudo ufw logging low).")
                            : qsTr("No logs match this query and time range.")
                    }

                    delegate: Rectangle {
                        id: lr
                        required property int index
                        required property var time
                        required property string action
                        required property bool blocked
                        required property string chain
                        required property string inIface
                        required property string outIface
                        required property string src
                        required property string dst
                        required property string service
                        required property string ruleName
                        readonly property bool current: ListView.isCurrentItem

                        width: ListView.view.width
                        height: 32
                        color: current ? "#25252e" : logHover.hovered ? "#18181d" : index % 2 ? "#111114" : c.bg
                        HoverHandler { id: logHover }
                        TapHandler { onTapped: { table.currentIndex = lr.index; table.forceActiveFocus() } }
                        Rectangle { visible: lr.current; width: 3; height: parent.height; color: theme.accent }

                        readonly property var cells: [
                            Qt.formatDateTime(time, "MM-dd HH:mm:ss"),
                            root.actionLabel(action),
                            root.chainLabel(chain),
                            chain === "forward" ? inIface + " → " + outIface : (inIface || outIface),
                            src, dst, service, ruleName
                        ]
                        Row {
                            anchors.fill: parent
                            Repeater {
                                model: root.cols.length
                                delegate: Item {
                                    required property int index
                                    width: root.colWidth(index, lr.width); height: lr.height
                                    clip: true
                                    Row {
                                        anchors { verticalCenter: parent.verticalCenter; left: parent.left; leftMargin: 12 }
                                        spacing: 7
                                        Text {
                                            visible: index === 1
                                            text: lr.blocked ? "" : ""
                                            font.family: c.icons; font.pixelSize: 12
                                            color: lr.blocked ? c.drop : c.accept
                                        }
                                        Text {
                                            width: Math.max(0, root.colWidth(index, lr.width) - (index === 1 ? 40 : 20))
                                            elide: Text.ElideRight
                                            text: lr.cells[index]
                                            font.pixelSize: 13
                                            font.family: index === 0 || index === 4 || index === 5 ? c.mono : Qt.application.font.family
                                            font.bold: index === 1
                                            color: index === 1 ? (lr.blocked ? c.drop : c.accept)
                                                 : index === 0 || index === 2 || index === 7 ? c.dim : c.text
                                        }
                                    }
                                }
                            }
                        }
                    }
                }
            }

            // Log card.
            Rectangle {
                Layout.preferredWidth: root.selected ? 340 : 0
                Layout.fillHeight: true
                visible: root.selected !== null
                color: c.panel
                Rectangle { width: 1; height: parent.height; color: c.line }

                Flickable {
                    anchors { fill: parent; margins: 18 }
                    contentHeight: card.implicitHeight
                    clip: true
                    ColumnLayout {
                        id: card
                        width: parent.width
                        spacing: 12
                        RowLayout {
                            Layout.fillWidth: true
                            Text {
                                text: root.selected ? (root.selected.blocked ? "" : "") : ""
                                font.family: c.icons; font.pixelSize: 22
                                color: root.selected && root.selected.blocked ? c.drop : c.accept
                            }
                            Column {
                                Layout.fillWidth: true
                                Text {
                                    text: root.selected ? root.actionLabel(root.selected.action) + "  ·  " + root.chainLabel(root.selected.chain) : ""
                                    color: c.text; font.pixelSize: 16; font.bold: true
                                }
                                Text {
                                    text: root.selected ? root.selected.time.toLocaleString(Qt.locale(), "ddd d MMM yyyy  HH:mm:ss") : ""
                                    color: c.dim; font.pixelSize: 12
                                }
                            }
                            ToolButton { text: ""; font.family: c.icons; onClicked: root.dismiss() }
                        }

                        Repeater {
                            model: root.selected ? [
                                [qsTr("Source"), root.selected.src + (root.selected.spt >= 0 ? "  :" + root.selected.spt : ""), "src:" + root.selected.src],
                                [qsTr("Destination"), root.selected.dst, "dst:" + root.selected.dst],
                                [qsTr("Service"), root.selected.service, root.selected.dpt >= 0 ? "port:" + root.selected.dpt : "proto:" + root.selected.proto],
                                [qsTr("Interface"), root.selected.chain === "forward" ? root.selected.inIface + " → " + root.selected.outIface
                                                      : (root.selected.inIface || root.selected.outIface), "iface:" + (root.selected.inIface || root.selected.outIface)],
                                [qsTr("Rule"), root.selected.ruleName, root.selected.rule >= 0 ? "rule:" + (root.selected.rule + 1) : "rule:cleanup"],
                                [qsTr("Origin"), backend.gateway.hostname, ""],
                                [qsTr("Packet"), qsTr("%1 bytes · TTL %2").arg(root.selected.len).arg(root.selected.ttl)
                                                 + (root.selected.flags ? " · " + root.selected.flags : ""), ""],
                                [qsTr("MAC"), root.selected.mac, ""]
                            ] : []
                            delegate: RowLayout {
                                required property var modelData
                                Layout.fillWidth: true
                                visible: modelData[1] !== ""
                                spacing: 10
                                Text { text: modelData[0]; color: c.dim; font.pixelSize: 12; Layout.preferredWidth: 84 }
                                TextEdit {
                                    Layout.fillWidth: true
                                    text: modelData[1]; readOnly: true; selectByMouse: true
                                    wrapMode: TextEdit.WrapAnywhere
                                    color: c.text; font.pixelSize: 13
                                    font.family: modelData[0] === qsTr("Rule") || modelData[0] === qsTr("Service") ? Qt.application.font.family : c.mono
                                }
                                ToolButton {
                                    visible: modelData[2] !== ""
                                    text: ""; font.family: c.icons; font.pixelSize: 12
                                    implicitWidth: 30; implicitHeight: 30
                                    onClicked: root.addTerm(modelData[2])
                                    ToolTip.visible: hovered; ToolTip.text: qsTr("Filter by %1").arg(modelData[2])
                                }
                            }
                        }
                        Text { text: qsTr("Raw log"); color: c.dim; font.pixelSize: 12; topPadding: 6 }
                        Rectangle {
                            Layout.fillWidth: true
                            implicitHeight: raw.implicitHeight + 20
                            color: c.bg; border.color: c.line
                            radius: Math.min(4, theme.radius)
                            TextEdit {
                                id: raw
                                anchors { fill: parent; margins: 10 }
                                text: root.selected ? root.selected.message : ""
                                readOnly: true; selectByMouse: true
                                wrapMode: TextEdit.WrapAnywhere
                                color: c.dim; font.family: c.mono; font.pixelSize: 11
                            }
                        }
                    }
                }
            }
        }
    }

    Keys.forwardTo: [table]
}
