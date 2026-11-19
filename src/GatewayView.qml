import QtQuick
import QtQuick.Controls
import QtQuick.Controls.Material
import QtQuick.Layouts

// Gateways & Servers, for the one gateway there is: this machine.
Item {
    id: root

    function exposureLabel(e) {
        return e === "open" ? qsTr("Open to all") : e === "restricted" ? qsTr("Allowed for some")
             : e === "implied" ? qsTr("Implied rule") : e === "local" ? qsTr("Local only") : qsTr("Blocked")
    }
    function exposureColor(e) {
        return e === "open" ? c.reject : e === "restricted" ? c.limit : e === "implied" ? c.info
             : e === "local" ? c.dim : c.accept
    }
    function policyColor(p) { return p === "ACCEPT" ? c.accept : p === "REJECT" ? c.reject : c.drop }
    function policyLabel(p) { return p === "ACCEPT" ? qsTr("Accept") : p === "REJECT" ? qsTr("Reject") : qsTr("Drop") }

    ScrollView {
        id: scroll
        anchors.fill: parent
        contentWidth: availableWidth
        clip: true

        ColumnLayout {
            width: scroll.availableWidth
            spacing: 16

            Item { Layout.preferredHeight: 2 }

            Column {
                Layout.leftMargin: 18
                Text { text: qsTr("Gateways & Servers"); color: c.dim; font.pixelSize: 11 }
                Text { text: qsTr("Overview"); color: c.text; font.pixelSize: 18; font.bold: true }
            }

            GridLayout {
                Layout.fillWidth: true
                Layout.leftMargin: 18
                Layout.rightMargin: 18
                columns: 3
                columnSpacing: 16
                rowSpacing: 16

                // The gateway.
                Card {
                    Layout.fillWidth: true
                    Layout.fillHeight: true
                    Layout.preferredWidth: 1
                    title: qsTr("Gateway")
                    glyph: ""

                    RowLayout {
                        spacing: 14
                        Rectangle {
                            width: 52; height: 52
                            radius: Math.min(10, theme.radius)
                            color: Qt.rgba(Material.accentColor.r, Material.accentColor.g, Material.accentColor.b, 0.15)
                            Text { anchors.centerIn: parent; text: ""; font.family: c.icons; font.pixelSize: 26; color: theme.accent }
                        }
                        Column {
                            spacing: 3
                            Text { text: backend.gateway.hostname || ""; color: c.text; font.pixelSize: 20; font.bold: true }
                            Text { text: backend.gateway.os || ""; color: c.dim; font.pixelSize: 12 }
                            Text { text: qsTr("Linux %1").arg(backend.gateway.kernel || ""); color: c.dim; font.pixelSize: 12 }
                        }
                    }
                    Item { Layout.preferredHeight: 4 }
                    Repeater {
                        model: [
                            [qsTr("Firewall"), backend.defaults.enabled === "yes" ? qsTr("ufw, enabled") : qsTr("ufw, disabled"),
                             backend.defaults.enabled === "yes" ? c.accept : c.drop],
                            [qsTr("Service"), backend.gateway.service || "…", backend.gateway.service === "active" ? c.accept : c.reject],
                            [qsTr("Logging"), backend.defaults.loglevel || "", backend.defaults.loglevel === "off" ? c.reject : c.text],
                            [qsTr("IPv6"), backend.defaults.ipv6 === "yes" ? qsTr("filtered") : qsTr("not filtered"), c.text],
                            [qsTr("Policy"), qsTr("%n rules", "", backend.rules.length) + " · " + qsTr("%1 implied").arg(backend.implied.length), c.text]
                        ]
                        delegate: RowLayout {
                            required property var modelData
                            Text { text: modelData[0]; color: c.dim; font.pixelSize: 13; Layout.preferredWidth: 90 }
                            Text { text: modelData[1]; color: modelData[2]; font.pixelSize: 13 }
                        }
                    }
                }

                // Default policies, the cleanup rules.
                Card {
                    Layout.fillWidth: true
                    Layout.fillHeight: true
                    Layout.preferredWidth: 1
                    title: qsTr("Default policy")
                    glyph: ""
                    Repeater {
                        model: [["input", qsTr("Incoming")], ["output", qsTr("Outgoing")], ["forward", qsTr("Forwarded")]]
                        delegate: Rectangle {
                            required property var modelData
                            readonly property string p: backend.defaults[modelData[0]] || ""
                            Layout.fillWidth: true
                            implicitHeight: 46
                            radius: Math.min(6, theme.radius)
                            color: c.bg; border.color: c.line
                            RowLayout {
                                anchors { fill: parent; leftMargin: 14; rightMargin: 14 }
                                Text { text: modelData[1]; color: c.text; font.pixelSize: 14 }
                                Item { Layout.fillWidth: true }
                                Text {
                                    text: (p === "ACCEPT" ? "  " : "  ") + root.policyLabel(p)
                                    font.family: c.icons; font.pixelSize: 14; font.bold: true
                                    color: root.policyColor(p)
                                }
                            }
                            TapHandler { onTapped: win.view = 1 }
                            HoverHandler { cursorShape: Qt.PointingHandCursor }
                        }
                    }
                    Text {
                        Layout.fillWidth: true
                        wrapMode: Text.Wrap
                        color: c.dim; font.pixelSize: 12
                        text: qsTr("Traffic no rule matches meets these. Dropped packets are logged at most 3 a minute.")
                    }
                }

                // Last 24 hours.
                Card {
                    Layout.fillWidth: true
                    Layout.fillHeight: true
                    Layout.preferredWidth: 1
                    title: qsTr("Last 24 hours")
                    glyph: ""
                    GridLayout {
                        columns: 2
                        columnSpacing: 12
                        rowSpacing: 12
                        Layout.fillWidth: true
                        Repeater {
                            model: [
                                [qsTr("Dropped"), backend.stats.blocked || 0, c.drop, "action:drop"],
                                [qsTr("Accepted"), backend.stats.allowed || 0, c.accept, "action:accept"],
                                [qsTr("Sources"), backend.stats.sources || 0, c.info, ""],
                                [qsTr("Logged"), backend.stats.total || 0, c.text, ""]
                            ]
                            delegate: Rectangle {
                                required property var modelData
                                Layout.fillWidth: true
                                implicitHeight: 70
                                radius: Math.min(6, theme.radius)
                                color: c.bg; border.color: c.line
                                Column {
                                    anchors { left: parent.left; verticalCenter: parent.verticalCenter; leftMargin: 14 }
                                    spacing: 2
                                    Text {
                                        text: Number(modelData[1]).toLocaleString(Qt.locale(), 'f', 0)
                                        color: modelData[2]; font.pixelSize: 24; font.bold: true
                                    }
                                    Text { text: modelData[0]; color: c.dim; font.pixelSize: 12 }
                                }
                                TapHandler { onTapped: { backend.logs.hours = 24; win.openLogs(modelData[3]) } }
                                HoverHandler { cursorShape: Qt.PointingHandCursor }
                            }
                        }
                    }
                }

                // Top dropped sources and services.
                Repeater {
                    model: [
                        [qsTr("Top dropped sources"), "", "topSources", "src:"],
                        [qsTr("Top dropped services"), "", "topPorts", "port:"],
                        [qsTr("Dropped by interface"), "", "topIfaces", "iface:"]
                    ]
                    delegate: Card {
                        id: topCard
                        required property var modelData
                        readonly property string prefix: modelData[3]
                        readonly property var list: backend.stats[modelData[2]] || []
                        readonly property int peak: list.length ? list[0].count : 1
                        Layout.fillWidth: true
                        Layout.fillHeight: true
                        Layout.preferredWidth: 1
                        title: modelData[0]
                        glyph: modelData[1]
                        Text {
                            visible: list.length === 0
                            text: qsTr("Nothing dropped in the last 24 hours.")
                            color: c.dim; font.pixelSize: 13
                        }
                        Repeater {
                            model: list
                            delegate: Item {
                                required property var modelData
                                Layout.fillWidth: true
                                implicitHeight: 30
                                Rectangle {
                                    anchors { left: parent.left; verticalCenter: parent.verticalCenter }
                                    height: 24
                                    width: parent.width * modelData.count / peak
                                    radius: Math.min(4, theme.radius)
                                    color: Qt.rgba(c.drop.r, c.drop.g, c.drop.b, topHover.hovered ? 0.28 : 0.16)
                                }
                                Text {
                                    anchors { left: parent.left; verticalCenter: parent.verticalCenter; leftMargin: 8; right: count.left; rightMargin: 8 }
                                    text: modelData.label; elide: Text.ElideRight
                                    color: c.text; font.pixelSize: 13; font.family: c.mono
                                }
                                Text {
                                    id: count
                                    anchors { right: parent.right; verticalCenter: parent.verticalCenter; rightMargin: 8 }
                                    text: modelData.count.toLocaleString(Qt.locale(), 'f', 0)
                                    color: c.dim; font.pixelSize: 12
                                }
                                HoverHandler { id: topHover; cursorShape: Qt.PointingHandCursor }
                                TapHandler {
                                    onTapped: {
                                        backend.logs.hours = 24
                                        win.openLogs(topCard.prefix + modelData.label.split(" ")[0].split("/").pop())
                                    }
                                }
                            }
                        }
                    }
                }

                // Listening sockets and what the firewall lets reach them.
                Card {
                    Layout.fillWidth: true
                    Layout.columnSpan: 2
                    Layout.preferredWidth: 2
                    title: qsTr("Services listening on this machine")
                    glyph: ""
                    RowLayout {
                        Layout.fillWidth: true
                        Repeater {
                            model: [[qsTr("Port"), 110], [qsTr("Address"), 190], [qsTr("Process"), 140], [qsTr("Firewall"), -1]]
                            Text {
                                required property var modelData
                                text: modelData[0]; color: c.dim; font.pixelSize: 12; font.bold: true
                                Layout.preferredWidth: modelData[1]
                                Layout.fillWidth: modelData[1] < 0
                            }
                        }
                    }
                    Repeater {
                        model: backend.listening
                        delegate: RowLayout {
                            required property var modelData
                            Layout.fillWidth: true
                            Text {
                                text: modelData.proto + "/" + modelData.port + (modelData.service ? "  " + modelData.service : "")
                                color: c.text; font.pixelSize: 13; font.family: c.mono
                                Layout.preferredWidth: 110; elide: Text.ElideRight
                            }
                            Text { text: modelData.address; color: c.dim; font.pixelSize: 13; font.family: c.mono; Layout.preferredWidth: 190; elide: Text.ElideRight }
                            Text { text: modelData.process || "—"; color: c.text; font.pixelSize: 13; Layout.preferredWidth: 140; elide: Text.ElideRight }
                            Pill { text: root.exposureLabel(modelData.exposure); tint: root.exposureColor(modelData.exposure) }
                            Text {
                                visible: modelData.rule > 0
                                text: qsTr("rule %1").arg(modelData.rule)
                                color: c.dim; font.pixelSize: 12
                            }
                            Item { Layout.fillWidth: true }
                        }
                    }
                    Text {
                        Layout.fillWidth: true
                        wrapMode: Text.Wrap
                        color: c.dim; font.pixelSize: 12; topPadding: 4
                        text: qsTr("Judged for a new inbound connection from the network. Process names only show for sockets you own.")
                    }
                }

                // Interfaces.
                Card {
                    Layout.fillWidth: true
                    Layout.fillHeight: true
                    Layout.preferredWidth: 1
                    title: qsTr("Interfaces")
                    glyph: ""
                    Repeater {
                        model: backend.gateway.interfaces || []
                        delegate: ColumnLayout {
                            required property var modelData
                            Layout.fillWidth: true
                            spacing: 1
                            RowLayout {
                                Rectangle { width: 8; height: 8; radius: 4; color: modelData.up ? c.accept : c.line }
                                Text { text: modelData.name; color: c.text; font.pixelSize: 13; font.family: c.mono }
                                Text { text: modelData.loopback ? qsTr("loopback") : modelData.up ? "" : qsTr("down"); color: c.dim; font.pixelSize: 11 }
                            }
                            Text {
                                Layout.fillWidth: true
                                Layout.leftMargin: 14
                                visible: modelData.addresses !== ""
                                text: modelData.addresses
                                wrapMode: Text.WrapAnywhere
                                color: c.dim; font.pixelSize: 11; font.family: c.mono
                            }
                        }
                    }
                }
            }

            Item { Layout.preferredHeight: 6 }
        }
    }
}
