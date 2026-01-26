import QtQuick
import QtQuick.Controls
import QtQuick.Layouts
import qs.Commons
import qs.Widgets

ColumnLayout {
    id: root

    property var pluginApi: null

    spacing: Style.marginL
    implicitWidth: Math.round(520 * Style.uiScaleRatio)
    Layout.minimumWidth: implicitWidth
    Layout.maximumWidth: implicitWidth
    Layout.preferredWidth: implicitWidth

    // Settings getter with fallback to manifest defaults
    function getSetting(key, fallback) {
        if (!pluginApi) {
            return fallback
        }
        if (!pluginApi.pluginSettings) {
            const defaultVal = pluginApi?.manifest?.metadata?.defaultSettings?.[key]
            return defaultVal !== undefined ? defaultVal : fallback
        }
        try {
            const userVal = pluginApi?.pluginSettings?.[key]
            if (userVal !== undefined && userVal !== null) return userVal
            const defaultVal = pluginApi?.manifest?.metadata?.defaultSettings?.[key]
            if (defaultVal !== undefined && defaultVal !== null) return defaultVal
            return fallback
        } catch (e) {
            return fallback
        }
    }

    property string valueTimeout: getSetting("timeout", 120).toString()
    property bool valueShowBitwardenIcon: getSetting("showBitwardenIcon", true)
    property bool valueAutoCloseOnSuccess: getSetting("autoCloseOnSuccess", true)
    property bool valueAutoCloseOnCancel: getSetting("autoCloseOnCancel", true)
    property string valuePanelMode: getSetting("panelMode", "attached")

    readonly property var pluginMain: pluginApi?.mainInstance

    function saveSettings() {
        if (!pluginApi || !pluginApi.pluginSettings) {
            return
        }

        try {
            pluginApi.pluginSettings.timeout = parseInt(valueTimeout, 10) || 120
            pluginApi.pluginSettings.showBitwardenIcon = valueShowBitwardenIcon
            pluginApi.pluginSettings.autoCloseOnSuccess = valueAutoCloseOnSuccess
            pluginApi.pluginSettings.autoCloseOnCancel = valueAutoCloseOnCancel
            pluginApi.pluginSettings.panelMode = valuePanelMode

            pluginApi.saveSettings()
            pluginMain?.refresh()
        } catch (e) {
            console.log("Bitwarden Keyring: Failed to save settings:", e)
        }
    }

    NText {
        text: "Password prompts for Bitwarden Keyring vault unlock."
        wrapMode: Text.WordWrap
        color: Color.mOnSurface
    }

    NTextInput {
        label: "Timeout (seconds)"
        description: "How long to wait for user input before timing out."
        placeholderText: "120"
        text: root.valueTimeout
        inputItem.inputMethodHints: Qt.ImhDigitsOnly
        onTextChanged: root.valueTimeout = text
    }

    NDivider { Layout.fillWidth: true }

    NToggle {
        label: "Show Bitwarden icon"
        description: "Display the Bitwarden logo in the authentication dialog."
        checked: root.valueShowBitwardenIcon
        onToggled: checked => root.valueShowBitwardenIcon = checked
    }

    NToggle {
        label: "Close on success"
        description: "Automatically close the panel after successful authentication."
        checked: root.valueAutoCloseOnSuccess
        onToggled: checked => root.valueAutoCloseOnSuccess = checked
    }

    NToggle {
        label: "Close on cancel"
        description: "Automatically close the panel when the request is cancelled."
        checked: root.valueAutoCloseOnCancel
        onToggled: checked => root.valueAutoCloseOnCancel = checked
    }

    NDivider { Layout.fillWidth: true }

    NComboBox {
        Layout.fillWidth: true
        label: "Panel mode"
        description: "Choose how the authentication dialog appears."
        model: [
            { key: "attached", name: "Panel attached to bar" },
            { key: "centered", name: "Centered panel" },
            { key: "window", name: "Separate window" }
        ]
        currentKey: root.valuePanelMode
        onSelected: key => root.valuePanelMode = key
    }
}
