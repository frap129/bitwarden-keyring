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
    property bool awaitingResult: false  // True after password submitted, waiting for Go to respond
    
    // Alias for Panel.qml binding
    readonly property bool responseInFlight: awaitingResult
    
    // Agent availability (always available when server is active)
    readonly property bool agentAvailable: serverActive
    readonly property string agentStatus: serverActive ? "" : "Keyring server not available"

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
        
        // Don't close the panel - wait for keyring_result from Go
        awaitingResult = true
        lastError = ""
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
        cancelRequest()  // Try to send cancel response
        // Close the connection so Go receives EOF if cancel wasn't sent
        if (currentConnection) {
            currentConnection.close()
        }
        currentRequest = null
        currentConnection = null
        awaitingResult = false
        closeAuthUI()
    }

    // Handle keyring_result message from Go indicating unlock success/failure
    function handleKeyringResult(result) {
        awaitingResult = false
        
        if (result.success) {
            // Unlock succeeded - close panel
            handleRequestComplete(true)
        } else if (result.retry) {
            // Unlock failed but retry is allowed - show error, keep panel open
            lastError = result.error || "Incorrect password"
            requestCompleted(false)  // Signals AuthDialog to show error/shake
            // Don't close panel or clear request - allow retry
        } else {
            // Unlock failed and no retry allowed - show error briefly then close
            lastError = result.error || "Unlock failed"
            requestCompleted(false)
            // Close after a short delay so user can see the error
            closeTimer.start()
        }
    }
    
    Timer {
        id: closeTimer
        interval: 2000
        onTriggered: {
            handleRequestComplete(false)
        }
    }

    // Fix socket permissions after creation (Quickshell creates with 0775, we need 0700)
    Process {
        id: chmodProcess
        command: ["chmod", "0700", root.socketPath]
    }

    // Socket server for receiving password requests and results
    SocketServer {
        id: keyringServer
        active: root.serverActive
        path: root.socketPath
        onActiveChanged: {
            if (active && root.socketPath.length > 0) {
                chmodProcess.running = true
            }
        }

        handler: Socket {
            id: clientSocket
            parser: SplitParser {
                onRead: function(line) {
                    const trimmed = (line || "").trim()
                    if (!trimmed) return

                    try {
                        const message = JSON.parse(trimmed)
                        if (message.type === "keyring_request") {
                            root.handleKeyringRequest(message, clientSocket)
                        } else if (message.type === "keyring_result") {
                            root.handleKeyringResult(message)
                        }
                    } catch (e) {
                        console.log("Bitwarden Keyring: Failed to parse message:", e)
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
