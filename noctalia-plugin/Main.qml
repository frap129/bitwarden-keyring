import QtQuick
import Quickshell
import Quickshell.Io

Item {
    id: root

    property var pluginApi: null

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

    readonly property bool autoCloseOnSuccess: getSetting("autoCloseOnSuccess", true)
    readonly property bool autoCloseOnCancel: getSetting("autoCloseOnCancel", true)
    readonly property bool showBitwardenIcon: getSetting("showBitwardenIcon", true)

    readonly property string socketPath: {
        const runtimeDir = Quickshell.env("XDG_RUNTIME_DIR")
        return runtimeDir && runtimeDir.length > 0
            ? (runtimeDir + "/noctalia-keyring.sock")
            : ""
    }

    property bool serverActive: socketPath.length > 0
    property string lastError: ""

    property var currentRequest: null
    property var currentConnection: null

    signal requestReceived()
    signal requestCompleted(bool success)

    function refresh() {
        // No-op - server is always active when socket path is available
    }

    function handleKeyringRequest(request, connection) {
        currentRequest = {
            id: request.cookie,
            title: request.title,
            prompt: request.message,
            description: request.description || "",
            passwordNew: request.password_new || false,
            confirmOnly: request.confirm_only || false
        }
        currentConnection = connection

        lastError = ""
        requestReceived()

        // Open the panel
        pluginApi?.withCurrentScreen(function(screen) {
            pluginApi?.openPanel(screen)
        })
    }

    function handleRequestComplete(success) {
        requestCompleted(success)

        if ((success && autoCloseOnSuccess) || (!success && autoCloseOnCancel)) {
            closeAuthUI()
        }

        currentRequest = null
        currentConnection = null
        lastError = ""
    }

    function closeAuthUI() {
        pluginApi?.withCurrentScreen(function(screen) {
            pluginApi?.closePanel(screen)
        })
    }

    function submitPassword(password) {
        if (!currentRequest || !currentConnection) return

        const response = {
            type: "keyring_response",
            id: currentRequest.id,
            result: "ok",
            password: password
        }

        currentConnection.write(JSON.stringify(response) + "\n")
        currentConnection.flush()
        handleRequestComplete(true)
    }

    function cancelRequest() {
        if (!currentRequest || !currentConnection) return false

        const response = {
            type: "keyring_response",
            id: currentRequest.id,
            result: "cancelled"
        }

        currentConnection.write(JSON.stringify(response) + "\n")
        currentConnection.flush()
        handleRequestComplete(false)
        return true
    }

    function requestClose() {
        if (!currentRequest) {
            closeAuthUI()
            return
        }
        if (cancelRequest()) {
            closeAuthUI()
        }
    }

    // Socket server for receiving password requests
    SocketServer {
        id: keyringServer
        active: root.serverActive
        path: root.socketPath

        handler: Socket {
            parser: SplitParser {
                onRead: function(line) {
                    const trimmed = (line || "").trim()
                    if (!trimmed) return

                    try {
                        const request = JSON.parse(trimmed)
                        if (request.type === "keyring_request") {
                            root.handleKeyringRequest(request, this.parent)
                        }
                    } catch (e) {
                        console.log("Bitwarden Keyring: Failed to parse request:", e)
                    }
                }
            }
        }
    }

    Component.onCompleted: {
        refresh()
    }

    Connections {
        target: pluginApi
        function onPluginSettingsChanged() {
            refresh()
        }
    }
}
