import QtQuick
import QtQuick.Controls
import QtQuick.Layouts
import Quickshell
import qs.Commons
import qs.Widgets

Item {
    id: root

    // Required properties from parent
    property var pluginMain: null
    property var request: null
    property bool busy: false
    property bool agentAvailable: true
    property string statusText: ""
    property string errorText: ""
    property bool showBitwardenIcon: true

    // Internal state
    property bool revealPassword: false
    property bool animateIn: false

    // Signal to request closing the container
    signal closeRequested()

    // --- Style helpers ---
    readonly property string barSpaciousness: Settings?.data?.bar?.spaciousness ?? "default"
    
    readonly property int unit: {
        switch (barSpaciousness) {
            case "mini": return 4;
            case "compact": return 6;
            case "comfortable": return 12;
            case "spacious": return 16;
            default: return 8;
        }
    }

    readonly property int padOuter: unit * 2
    readonly property int padInner: Math.round(unit * 1.5)
    readonly property int gapItems: unit * 2
    readonly property int baseSize: Math.round(getStyle("baseWidgetSize", 32))
    readonly property int controlHeight: Math.round(baseSize * 1.4)
    readonly property int iconTile: baseSize
    readonly property int overlayButton: Math.round(baseSize * 0.75)
    readonly property int radiusOuter: getStyle("radiusXL", 24)
    readonly property int radiusInner: Math.max(getStyle("radiusS", 4), radiusOuter - padOuter)

    function getColor(path, fallback) {
        if (typeof Color === "undefined" || Color === null) return fallback;
        const parts = path.split('.');
        let cur = Color;
        for (const p of parts) { if (cur[p] === undefined) return fallback; cur = cur[p]; }
        return cur;
    }

    function getStyle(prop, fallback) {
        if (typeof Style === "undefined" || Style === null) return fallback;
        return Style[prop] !== undefined ? Style[prop] : fallback;
    }

    readonly property bool hasRequest: request !== null && request !== undefined && typeof request === "object" && request.id

    function focusPasswordInput() {
        if (hasRequest && passwordInput.visible) {
            root.forceActiveFocus();
            passwordInput.inputItem.forceActiveFocus();
        }
    }

    Connections {
        target: pluginMain
        function onRequestCompleted(success) {
            if (!success) {
                shakeAnim.restart();
                passwordInput.text = "";
                focusPasswordInput();
            }
        }
    }

    // --- UI ---
    implicitWidth: Math.round(400 * getStyle("uiScaleRatio", 1.0))
    implicitHeight: mainColumn.implicitHeight + (padOuter * 2)

    ColumnLayout {
        id: mainColumn
        anchors.fill: parent
        anchors.margins: padOuter
        spacing: gapItems

        opacity: root.animateIn ? 1.0 : 0.0
        transform: Scale {
            origin.x: mainColumn.width / 2
            origin.y: mainColumn.height / 2
            xScale: root.animateIn ? 1.0 : 0.95
            yScale: root.animateIn ? 1.0 : 0.95
        }
        Behavior on opacity {
            NumberAnimation { duration: getStyle("animationNormal", 200); easing.type: Easing.OutCubic }
        }

        // Header with icon and close button
        Rectangle {
            Layout.fillWidth: true
            implicitHeight: headerRow.implicitHeight + (padInner * 2)
            color: getColor("mSurfaceVariant", "#eee")
            radius: radiusInner
            border.color: getColor("mOutline", "#ccc")
            border.width: 1

            RowLayout {
                id: headerRow
                anchors.fill: parent
                anchors.margins: padInner
                spacing: padInner

                // Bitwarden icon
                Rectangle {
                    visible: root.showBitwardenIcon
                    Layout.preferredWidth: iconTile
                    Layout.preferredHeight: iconTile
                    Layout.alignment: Qt.AlignVCenter
                    radius: Math.max(4, radiusInner - 4)
                    color: "#175DDC"

                    Image {
                        anchors.centerIn: parent
                        source: "assets/bitwarden.svg"
                        sourceSize.width: iconTile - 8
                        sourceSize.height: iconTile - 8
                    }
                }

                // Fallback icon if no Bitwarden icon
                Rectangle {
                    visible: !root.showBitwardenIcon
                    Layout.preferredWidth: iconTile
                    Layout.preferredHeight: iconTile
                    Layout.alignment: Qt.AlignVCenter
                    radius: Math.max(4, radiusInner - 4)
                    color: Qt.alpha(getColor("mPrimary", "blue"), 0.1)
                    NIcon {
                        anchors.centerIn: parent
                        icon: "lock"
                        pointSize: 16
                        color: getColor("mPrimary", "blue")
                    }
                }

                NText {
                    Layout.fillWidth: true
                    Layout.alignment: Qt.AlignVCenter
                    text: hasRequest ? (request.title || "Bitwarden Keyring") : "Bitwarden Keyring"
                    font.weight: getStyle("fontWeightBold", 700)
                    pointSize: getStyle("fontSizeM", 14)
                    color: getColor("mOnSurface", "black")
                    elide: Text.ElideRight
                }

                NIconButton {
                    Layout.preferredWidth: iconTile
                    Layout.preferredHeight: Layout.preferredWidth
                    Layout.alignment: Qt.AlignVCenter
                    icon: "x"
                    baseSize: Layout.preferredWidth
                    colorBg: "transparent"
                    onClicked: {
                        if (!busy) {
                            root.closeRequested()
                            passwordInput.text = ""
                        }
                    }
                }
            }
        }

        // Prompt message
        NText {
            visible: hasRequest && request.prompt
            Layout.fillWidth: true
            horizontalAlignment: Text.AlignHCenter
            text: hasRequest ? (request.prompt || "Bitwarden Master Password") : ""
            color: getColor("mOnSurfaceVariant", "#666")
            pointSize: getStyle("fontSizeS", 12)
            wrapMode: Text.WordWrap
        }

        // Password Input
        Rectangle {
            id: inputWrapper
            Layout.fillWidth: true
            implicitHeight: passwordInput.implicitHeight + (padInner * 2)
            visible: hasRequest
            radius: radiusInner
            color: getColor("mSurfaceVariant", "#eee")
            border.color: errorText.length > 0 ? getColor("mError", "red") : (passwordInput.activeFocus ? getColor("mPrimary", "blue") : getColor("mOutline", "#ccc"))
            border.width: passwordInput.activeFocus ? 2 : 1

            NTextInput {
                id: passwordInput
                anchors.fill: parent
                anchors.leftMargin: padInner
                anchors.rightMargin: overlayIcons.width + padInner + unit
                anchors.topMargin: padInner
                anchors.bottomMargin: padInner

                inputItem.font.pointSize: getStyle("fontSizeM", 14)
                inputItem.verticalAlignment: TextInput.AlignVCenter
                placeholderText: "Master Password"
                text: ""
                inputItem.echoMode: root.revealPassword ? TextInput.Normal : TextInput.Password
                enabled: !busy

                Component.onCompleted: {
                    if (passwordInput.background) passwordInput.background.visible = false
                }

                inputItem.Keys.onPressed: function(event) {
                    if (event.key === Qt.Key_Return || event.key === Qt.Key_Enter) {
                        if (hasRequest && !busy && passwordInput.text.length > 0) {
                            pluginMain?.submitPassword(passwordInput.text)
                        }
                    } else if (event.key === Qt.Key_Escape) {
                        if (!busy) {
                            root.closeRequested()
                            passwordInput.text = ""
                        }
                    }
                }
            }

            Row {
                id: overlayIcons
                anchors.right: parent.right
                anchors.rightMargin: padInner
                anchors.verticalCenter: parent.verticalCenter
                spacing: unit

                NIconButton {
                    icon: root.revealPassword ? "eye-off" : "eye"
                    baseSize: overlayButton
                    colorBg: "transparent"
                    onClicked: root.revealPassword = !root.revealPassword
                }
            }
        }

        // Unlock Button
        NButton {
            id: authButton
            visible: hasRequest
            Layout.fillWidth: true
            Layout.preferredHeight: controlHeight
            text: busy ? "Unlocking..." : "Unlock"
            enabled: !busy && passwordInput.text.length > 0

            Component.onCompleted: {
                if (authButton.background) authButton.background.radius = radiusInner
            }

            onClicked: {
                if (hasRequest && pluginMain && passwordInput.text.length > 0) {
                    pluginMain.submitPassword(passwordInput.text)
                }
            }

            NIcon {
                anchors.right: parent.right
                anchors.rightMargin: padInner
                anchors.verticalCenter: parent.verticalCenter
                visible: busy
                icon: "loader"
                pointSize: 12
                RotationAnimation on rotation {
                    from: 0
                    to: 360
                    duration: 1000
                    loops: Animation.Infinite
                    running: busy
                }
            }
        }

        // Error message
        NText {
            Layout.fillWidth: true
            visible: errorText.length > 0
            horizontalAlignment: Text.AlignHCenter
            text: errorText
            color: getColor("mError", "red")
            pointSize: getStyle("fontSizeS", 12)
            wrapMode: Text.WordWrap
        }

        // Agent status
        NText {
            Layout.fillWidth: true
            visible: !agentAvailable && statusText.length > 0
            horizontalAlignment: Text.AlignHCenter
            text: statusText
            color: getColor("mOnSurfaceVariant", "#666")
            pointSize: getStyle("fontSizeS", 12)
            wrapMode: Text.WordWrap
        }
    }

    // Shake animation for errors
    SequentialAnimation {
        id: shakeAnim
        NumberAnimation { target: mainColumn; property: "anchors.horizontalCenterOffset"; from: 0; to: -8; duration: 50 }
        NumberAnimation { target: mainColumn; property: "anchors.horizontalCenterOffset"; to: 8; duration: 50 }
        NumberAnimation { target: mainColumn; property: "anchors.horizontalCenterOffset"; to: 0; duration: 50 }
    }

    Timer {
        id: focusTimer
        interval: 100
        onTriggered: focusPasswordInput()
    }

    Timer {
        id: animateInTimer
        interval: 16
        onTriggered: root.animateIn = true
    }

    onHasRequestChanged: {
        if (hasRequest) {
            passwordInput.text = ""
            revealPassword = false
            focusTimer.restart()
        }
    }

    onVisibleChanged: {
        if (visible && hasRequest) {
            focusTimer.restart()
        }
    }

    Component.onCompleted: {
        animateInTimer.start()
        if (hasRequest) {
            focusTimer.restart()
        }
    }
}
