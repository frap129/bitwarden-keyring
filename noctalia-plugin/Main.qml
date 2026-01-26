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

    readonly property int pollInterval: getSetting("pollInterval", 100)
    readonly property bool autoCloseOnSuccess: getSetting("autoCloseOnSuccess", true)
    readonly property bool autoCloseOnCancel: getSetting("autoCloseOnCancel", true)
    readonly property bool showBitwardenIcon: getSetting("showBitwardenIcon", true)

    readonly property string socketPath: {
        const runtimeDir = Quickshell.env("XDG_RUNTIME_DIR")
        return runtimeDir && runtimeDir.length > 0
            ? (runtimeDir + "/noctalia-polkit-agent.sock")
            : ""
    }

    property bool agentAvailable: false
    property string agentStatus: ""
    property string lastError: ""

    property var currentRequest: null
    property bool responseInFlight: false
    property var socketQueue: []
    property var pendingSocketRequest: null
    property bool socketBusy: false
    property bool socketResponseReceived: false

    signal requestReceived()
    signal requestCompleted(bool success)

    function refresh() {
        checkAgent()
    }

    function checkAgent() {
        if (!socketPath) {
            agentAvailable = false
            agentStatus = "Socket path not available"
            return
        }

        enqueueSocketCommand({ type: "ping" }, function(ok, response) {
            if (ok && response?.type === "pong") {
                agentAvailable = true
                agentStatus = ""
            } else {
                agentAvailable = false
                agentStatus = "Agent not reachable"
            }
        })
    }

    function pollRequests() {
        if (!agentAvailable || responseInFlight) return

        enqueueSocketCommand({ type: "next" }, function(ok, response) {
            if (!ok) return

            if (!response || response.type === "empty") {
                return
            }

            if (response.type === "request") {
                // Only handle keyring requests
                if (response.source === "keyring") {
                    handleKeyringRequest(response)
                }
            } else if (response.type === "update") {
                if (response.error && currentRequest && response.id === currentRequest.id) {
                    lastError = response.error
                }
            } else if (response.type === "complete") {
                if (currentRequest && response.id === currentRequest.id) {
                    handleRequestComplete(response.result === "success")
                }
            }
        })
    }

    function handleKeyringRequest(request) {
        currentRequest = {
            id: request.id,
            title: request.message,       // keyring_request.title -> event.message
            prompt: request.prompt,       // keyring_request.message -> event.prompt
            description: request.description || "",
            passwordNew: request.passwordNew || false,
            confirmOnly: request.confirmOnly || false
        }

        lastError = ""
        responseInFlight = false
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
        responseInFlight = false
        lastError = ""
    }

    function closeAuthUI() {
        pluginApi?.withCurrentScreen(function(screen) {
            pluginApi?.closePanel(screen)
        })
    }

    function submitPassword(password) {
        if (!currentRequest || responseInFlight) return

        responseInFlight = true
        lastError = ""

        enqueueSocketCommand({
            type: "respond",
            id: currentRequest.id,
            response: password
        }, function(ok, response) {
            responseInFlight = false
            if (!ok || response?.type !== "ok") {
                lastError = "Authentication failed"
            }
        })
    }

    function cancelRequest() {
        if (!currentRequest || responseInFlight) return false

        responseInFlight = true
        lastError = ""

        enqueueSocketCommand({
            type: "cancel",
            id: currentRequest.id
        }, function(ok, response) {
            responseInFlight = false
            if (!ok || response?.type !== "ok") {
                lastError = "Failed to cancel request"
            }
        })
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

    // Socket command queue management
    function enqueueSocketCommand(message, onResponse) {
        if (!socketPath) {
            onResponse?.(false, null)
            return
        }

        socketQueue = socketQueue.concat([{ payload: JSON.stringify(message), onResponse: onResponse }])
        startNextSocketCommand()
    }

    function startNextSocketCommand() {
        if (socketBusy || socketQueue.length === 0) return

        pendingSocketRequest = socketQueue[0]
        socketQueue = socketQueue.slice(1)
        socketBusy = true
        socketResponseReceived = false
        agentSocket.connected = true
        socketTimeout.restart()
    }

    function finishSocketCommand(ok, response) {
        socketTimeout.stop()
        socketResponseReceived = true
        agentSocket.connected = false
        socketBusy = false

        let parsed = null
        if (ok) {
            const line = (response || "").trim()
            if (!line) {
                ok = false
            } else {
                try {
                    parsed = JSON.parse(line)
                } catch (e) {
                    console.log("Bitwarden Keyring: Failed to parse response:", e)
                    ok = false
                }
            }
        }

        const cb = pendingSocketRequest?.onResponse
        pendingSocketRequest = null
        cb?.(ok, parsed)
        Qt.callLater(startNextSocketCommand)
    }

    // Timers
    Timer {
        id: pollTimer
        interval: Math.max(50, root.pollInterval)
        repeat: true
        running: agentAvailable
        onTriggered: pollRequests()
    }

    Timer {
        id: pingTimer
        interval: 3000
        repeat: true
        running: true
        onTriggered: checkAgent()
    }

    Timer {
        id: socketTimeout
        interval: 1000
        repeat: false
        onTriggered: {
            if (socketBusy && !socketResponseReceived) {
                finishSocketCommand(false, "")
            }
        }
    }

    // Socket for IPC
    Socket {
        id: agentSocket
        path: root.socketPath
        connected: false

        onConnectedChanged: {
            if (connected) {
                if (!pendingSocketRequest) {
                    connected = false
                    return
                }

                const data = pendingSocketRequest.payload + "\n"
                write(data)
                flush()
                return
            }

            if (socketBusy && !socketResponseReceived) {
                finishSocketCommand(false, "")
            }
        }

        parser: SplitParser {
            onRead: function(line) {
                const response = (line || "").trim()
                finishSocketCommand(true, response)
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
