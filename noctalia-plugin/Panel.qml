import QtQuick
import QtQuick.Layouts
import qs.Commons
import qs.Services.UI

Item {
    id: root

    property var pluginApi: null
    property var screen: null

    readonly property var pluginMain: pluginApi?.mainInstance ?? null
    readonly property string panelMode: pluginMain?.getSetting("panelMode", "centered") ?? "centered"
    readonly property bool attachToBar: panelMode === "attached"
    readonly property string barPosition: Settings.data.bar.position

    // Panel positioning properties (passed through by PluginPanelSlot)
    readonly property bool allowAttach: attachToBar
    readonly property bool panelAnchorHorizontalCenter: attachToBar ? (barPosition === "top" || barPosition === "bottom") : true
    readonly property bool panelAnchorVerticalCenter: attachToBar ? (barPosition === "left" || barPosition === "right") : true
    readonly property bool panelAnchorTop: attachToBar && barPosition === "top"
    readonly property bool panelAnchorBottom: attachToBar && barPosition === "bottom"
    readonly property bool panelAnchorLeft: attachToBar && barPosition === "left"
    readonly property bool panelAnchorRight: attachToBar && barPosition === "right"

    readonly property int contentPreferredWidth: Math.round(400 * Style.uiScaleRatio)
    readonly property int contentPreferredHeight: {
        const baseHeight = authContent.implicitHeight;
        const minHeight = Math.round(280 * Style.uiScaleRatio);
        const maxHeight = Math.round(520 * Style.uiScaleRatio);
        return Math.max(minHeight, Math.min(baseHeight, maxHeight));
    }

    AuthDialog {
        id: authContent
        anchors.fill: parent
        pluginMain: root.pluginMain
        request: pluginMain?.currentRequest ?? null
        busy: pluginMain?.responseInFlight ?? false
        agentAvailable: pluginMain?.agentAvailable ?? true
        statusText: pluginMain?.agentStatus ?? ""
        errorText: pluginMain?.lastError ?? ""
        showBitwardenIcon: pluginMain?.showBitwardenIcon ?? true
        onCloseRequested: pluginMain?.requestClose()
    }
}
