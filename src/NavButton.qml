import QtQuick

Item {
    id: root
    property string glyph
    property string label
    property bool selected: false
    signal clicked()

    width: parent ? parent.width : 96
    height: 76

    Rectangle {
        anchors { fill: parent; leftMargin: 6; rightMargin: 6 }
        radius: Math.min(6, theme.radius)
        color: root.selected ? "#24242c" : hover.hovered ? "#1c1c22" : "transparent"
    }
    Rectangle {
        anchors { left: parent.left; verticalCenter: parent.verticalCenter }
        width: 3; height: 40
        color: theme.accent
        visible: root.selected
    }
    Column {
        anchors.centerIn: parent
        spacing: 5
        Text {
            anchors.horizontalCenter: parent.horizontalCenter
            text: root.glyph
            font.family: "JetBrainsMono Nerd Font"
            font.pixelSize: 22
            color: root.selected ? theme.accent : "#a0a0aa"
        }
        Text {
            anchors.horizontalCenter: parent.horizontalCenter
            text: root.label
            horizontalAlignment: Text.AlignHCenter
            font.pixelSize: 11
            color: root.selected ? "#e7e7ea" : "#8d8d98"
        }
    }
    HoverHandler { id: hover; cursorShape: Qt.PointingHandCursor }
    TapHandler { onTapped: root.clicked() }
}
