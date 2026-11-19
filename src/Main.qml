import QtQuick
import QtQuick.Controls
import QtQuick.Controls.Material
import QtQuick.Layouts

ApplicationWindow {
    id: win
    width: 1380
    height: 840
    minimumWidth: 1120
    minimumHeight: 600
    visible: true
    title: "Bastion"
    color: c.bg

    Material.theme: Material.Dark
    Material.accent: theme.accent
    Material.roundedScale: theme.radius

    // One dark palette for every view; the accent is the Omarchy theme's.
    QtObject {
        id: c
        readonly property color bg: "#0e0e10"
        readonly property color panel: "#141418"
        readonly property color raised: "#1b1b21"
        readonly property color line: "#2a2a32"
        readonly property color text: "#e7e7ea"
        readonly property color dim: "#8d8d98"
        readonly property color accept: "#4ade80"
        readonly property color drop: "#f87171"
        readonly property color reject: "#fb923c"
        readonly property color limit: "#fbbf24"
        readonly property color info: "#60a5fa"
        readonly property string icons: "JetBrainsMono Nerd Font"
        readonly property string mono: "JetBrainsMono Nerd Font"
        function actionColor(a) {
            return a === "Accept" ? accept : a === "Drop" ? drop : a === "Reject" ? reject
                 : a === "Limit" ? limit : dim
        }
    }

    property int view: 0
    property bool helpVisible: false

    function openLogs(query) {
        backend.logs.query = query
        view = 2
    }

    Shortcut { sequence: "?"; context: Qt.ApplicationShortcut; onActivated: win.helpVisible = !win.helpVisible }
    Shortcut { sequence: "Q"; context: Qt.ApplicationShortcut; onActivated: Qt.quit() }
    Shortcut { sequence: "1"; context: Qt.ApplicationShortcut; onActivated: win.view = 0 }
    Shortcut { sequence: "2"; context: Qt.ApplicationShortcut; onActivated: win.view = 1 }
    Shortcut { sequence: "3"; context: Qt.ApplicationShortcut; onActivated: win.view = 2 }
    Shortcut { sequence: "R"; context: Qt.ApplicationShortcut; onActivated: backend.refresh() }
    Shortcut { sequence: "Space"; context: Qt.ApplicationShortcut; onActivated: backend.paused = !backend.paused }
    Shortcut { sequence: "I"; context: Qt.ApplicationShortcut; onActivated: policyView.showImplied = !policyView.showImplied }
    Shortcut {
        sequences: ["/", StandardKey.Find]
        context: Qt.ApplicationShortcut
        onActivated: win.view === 2 ? logsView.focusSearch() : (win.view = 1, policyView.focusSearch())
    }
    Shortcut {
        sequence: "Escape"
        context: Qt.ApplicationShortcut
        onActivated: {
            if (win.helpVisible) win.helpVisible = false
            else if (win.view === 2) logsView.dismiss()
            else if (win.view === 1) policyView.dismiss()
        }
    }

    Item {
        anchors.fill: parent
        LayoutMirroring.enabled: Qt.application.layoutDirection === Qt.RightToLeft
        LayoutMirroring.childrenInherit: true

        // Top bar: what is being looked at, and whether the firewall is on.
        Rectangle {
            id: topBar
            anchors { left: parent.left; right: parent.right; top: parent.top }
            height: 46
            color: c.panel
            Rectangle { anchors { left: parent.left; right: parent.right; bottom: parent.bottom } height: 1; color: c.line }

            RowLayout {
                anchors { fill: parent; leftMargin: 16; rightMargin: 16 }
                spacing: 12
                Text { text: ""; font.family: c.icons; font.pixelSize: 20; color: theme.accent }
                Text { text: "Bastion"; color: c.text; font.pixelSize: 16; font.bold: true }
                Rectangle { width: 1; height: 20; color: c.line }
                Text { text: ""; font.family: c.icons; font.pixelSize: 14; color: c.dim }
                Text { text: backend.gateway.hostname || ""; color: c.text; font.pixelSize: 14 }
                Pill {
                    readonly property bool on: backend.defaults.enabled === "yes"
                    text: on ? qsTr("UFW enabled") : qsTr("UFW disabled")
                    tint: on ? c.accept : c.drop
                }
                Pill {
                    visible: backend.gateway.service !== undefined && backend.gateway.service !== "active"
                    text: qsTr("service %1").arg(backend.gateway.service || "")
                    tint: c.reject
                }
                Item { Layout.fillWidth: true }
                Pill { text: qsTr("Read only"); tint: c.dim }
                Pill {
                    text: backend.loadingLogs ? qsTr("Loading logs…") : backend.paused ? qsTr("Paused")
                        : backend.live ? qsTr("Live") : qsTr("Offline")
                    tint: backend.paused ? c.limit : backend.live ? c.accept : c.dim
                    dot: true
                }
                ToolButton {
                    text: ""; font.family: c.icons; font.pixelSize: 15
                    onClicked: backend.refresh()
                    ToolTip.visible: hovered; ToolTip.text: qsTr("Refresh (R)")
                }
                ToolButton {
                    text: "?"; font.pixelSize: 15
                    onClicked: win.helpVisible = !win.helpVisible
                    ToolTip.visible: hovered; ToolTip.text: qsTr("Shortcuts (?)")
                }
            }
        }

        // Left navigation, SmartConsole style.
        Rectangle {
            id: nav
            anchors { left: parent.left; top: topBar.bottom; bottom: statusBar.top }
            width: 96
            color: c.panel
            Rectangle { anchors { right: parent.right; top: parent.top; bottom: parent.bottom } width: 1; color: c.line }
            Column {
                anchors { left: parent.left; right: parent.right; top: parent.top; topMargin: 8 }
                spacing: 2
                NavButton { glyph: ""; label: qsTr("Gateway"); selected: win.view === 0; onClicked: win.view = 0 }
                NavButton { glyph: ""; label: qsTr("Security\nPolicies"); selected: win.view === 1; onClicked: win.view = 1 }
                NavButton { glyph: ""; label: qsTr("Logs &\nMonitor"); selected: win.view === 2; onClicked: win.view = 2 }
            }
        }

        StackLayout {
            anchors { left: nav.right; right: parent.right; top: topBar.bottom; bottom: statusBar.top }
            currentIndex: win.view
            GatewayView { id: gatewayView }
            PolicyView { id: policyView }
            LogsView { id: logsView }
        }

        // Status bar, with any problem reading the firewall said plainly.
        Rectangle {
            id: statusBar
            anchors { left: parent.left; right: parent.right; bottom: parent.bottom }
            height: problemText.visible ? Math.max(28, problemText.implicitHeight + 10) : 28
            color: c.panel
            Rectangle { anchors { left: parent.left; right: parent.right; top: parent.top } height: 1; color: c.line }
            RowLayout {
                anchors { fill: parent; leftMargin: 14; rightMargin: 14 }
                spacing: 18
                Text {
                    id: problemText
                    visible: backend.problem !== ""
                    text: "  " + backend.problem
                    color: c.reject; font.pixelSize: 12
                    Layout.fillWidth: true
                    wrapMode: Text.Wrap
                }
                Text {
                    visible: !problemText.visible
                    text: qsTr("Policy: ufw on %1").arg(backend.gateway.hostname || "")
                    color: c.dim; font.pixelSize: 12
                }
                Text {
                    visible: !problemText.visible
                    text: qsTr("%n rules", "", backend.rules.length)
                    color: c.dim; font.pixelSize: 12
                }
                Item { Layout.fillWidth: !problemText.visible }
                Text {
                    text: qsTr("%n logs", "", backend.stats.stored || 0) + "  ·  " + qsTr("last 7 days")
                    color: c.dim; font.pixelSize: 12
                }
                Text { text: qsTr("? for shortcuts"); color: c.dim; font.pixelSize: 12 }
            }
        }

        // Shortcut overlay.
        Rectangle {
            anchors.fill: parent
            visible: win.helpVisible
            color: "#cc000000"
            MouseArea { anchors.fill: parent; onClicked: win.helpVisible = false }
            Rectangle {
                anchors.centerIn: parent
                width: 440
                height: helpColumn.implicitHeight + 40
                radius: theme.radius
                color: c.raised
                border.color: c.line
                Column {
                    id: helpColumn
                    anchors { fill: parent; margins: 20 }
                    spacing: 9
                    Text { text: qsTr("Keyboard shortcuts"); color: c.text; font.pixelSize: 17; font.bold: true; bottomPadding: 6 }
                    Repeater {
                        model: [
                            ["1  2  3", qsTr("Gateway, Security Policies, Logs")],
                            ["/  Ctrl+F", qsTr("Search the policy or the logs")],
                            ["Esc", qsTr("Clear the search or close details")],
                            ["↑  ↓", qsTr("Move through rules or logs")],
                            ["Space", qsTr("Pause or resume live logs")],
                            ["I", qsTr("Show or hide implied rules")],
                            ["R", qsTr("Reload rules and logs")],
                            ["?", qsTr("This help")],
                            ["Q", qsTr("Quit")]
                        ]
                        delegate: Row {
                            required property var modelData
                            spacing: 14
                            Rectangle {
                                width: 96; height: 24
                                radius: Math.min(4, theme.radius)
                                color: c.panel; border.color: c.line
                                Text { anchors.centerIn: parent; text: modelData[0]; color: theme.accent; font.family: c.mono; font.pixelSize: 12 }
                            }
                            Text { anchors.verticalCenter: parent.verticalCenter; text: modelData[1]; color: c.text; font.pixelSize: 13 }
                        }
                    }
                }
            }
        }
    }
}
