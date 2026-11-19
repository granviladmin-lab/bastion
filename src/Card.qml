import QtQuick
import QtQuick.Layouts

// A titled panel on the Gateway view.
Rectangle {
    id: root
    property string title
    property string glyph
    default property alias content: body.data

    color: "#141418"
    border.color: "#2a2a32"
    radius: theme.radius
    implicitHeight: header.height + body.implicitHeight + 60

    Row {
        id: header
        anchors { left: parent.left; top: parent.top; margins: 16 }
        spacing: 9
        height: 20
        Text { text: root.glyph; font.family: "JetBrainsMono Nerd Font"; font.pixelSize: 14; color: theme.accent; anchors.verticalCenter: parent.verticalCenter }
        Text { text: root.title; font.pixelSize: 13; font.bold: true; color: "#e7e7ea"; anchors.verticalCenter: parent.verticalCenter }
    }
    ColumnLayout {
        id: body
        anchors { left: parent.left; right: parent.right; top: header.bottom; margins: 16; topMargin: 12 }
        spacing: 8
    }
}
