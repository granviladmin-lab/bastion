import QtQuick

Rectangle {
    id: root
    property string text
    property color tint: "#8d8d98"
    property bool dot: false

    implicitWidth: row.implicitWidth + 18
    implicitHeight: 22
    radius: Math.min(11, theme.radius === 0 ? 3 : 11)
    color: Qt.rgba(tint.r, tint.g, tint.b, 0.14)
    border.color: Qt.rgba(tint.r, tint.g, tint.b, 0.45)

    Row {
        id: row
        anchors.centerIn: parent
        spacing: 6
        Rectangle {
            visible: root.dot
            width: 7; height: 7; radius: 3.5
            anchors.verticalCenter: parent.verticalCenter
            color: root.tint
        }
        Text { text: root.text; color: root.tint; font.pixelSize: 11; font.bold: true }
    }
}
