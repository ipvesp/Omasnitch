import QtQuick
import Quickshell
import Quickshell.Io
import qs.Ui

BarWidget {
    id: root

    moduleName: "vesp.omasnitch"

    property int blockedAppCount: 0
    property bool showBlockedCount: true
    property bool showRecentConnections: true
    property int pendingCount: 0
    property int currentUid: -1
    property var previousPending: []
    property bool pendingInitialized: false
    property string setupState: "checking"
    property string setupError: ""
    readonly property string expectedVersion: "0.2.4"
    readonly property string pluginDir: Quickshell.env("HOME") + "/.config/omarchy/plugins/vesp.omasnitch"

    function retrySetup() {
        if (bootstrapProcess.running)
            return
        setupError = ""
        setupState = "installing"
        bootstrapProcess.running = true
    }

    readonly property bool opened:
        panelLoader.item
        ? panelLoader.item.opened === true
        : false

    readonly property bool popoutSwitchClosing:
        panelLoader.item
        ? panelLoader.item.popoutSwitchClosing === true
        : false

    function open() {
        if (panelLoader.item)
            panelLoader.item.open()
    }

    function close() {
        if (panelLoader.item)
            panelLoader.item.close()
    }

    function toggle() {
        if (panelLoader.item)
            panelLoader.item.toggle()
    }

    function closeForPopoutSwitch() {
        if (panelLoader.item)
            panelLoader.item.closeForPopoutSwitch()
    }

    function injectPanel() {
        if (!panelLoader.item)
            return

        panelLoader.item.bar = root.bar
        panelLoader.item.anchorItem = button
        panelLoader.item.hostWidget = root
    }

    function refreshRules() {
        if (!rulesProcess.running)
            rulesProcess.running = true
    }

    function updateShowBlockedCount(value) {
        root.showBlockedCount = value

        if (!blockedSettingProcess.running) {
            blockedSettingProcess.command = [
                "sh",
                "-c",
                "set -e; umask 077; install -d -m700 \"${XDG_CONFIG_HOME:-$HOME/.config}/omasnitch\"; "
                + "FILE=\"${XDG_CONFIG_HOME:-$HOME/.config}/omasnitch/ui.conf\"; "
                + "touch \"$FILE\"; "
                + "chmod 600 \"$FILE\"; "
                + "grep -v '^show_blocked_count=' \"$FILE\" > \"$FILE.tmp\" || true; "
                + "printf 'show_blocked_count="
                + (value ? "1" : "0")
                + "\\n' >> \"$FILE.tmp\"; "
                + "mv \"$FILE.tmp\" \"$FILE\""
            ]

            blockedSettingProcess.running = true
        }
    }

    function updateShowRecentConnections(value) {
        root.showRecentConnections = value

        if (!recentSettingProcess.running) {
            recentSettingProcess.command = [
                "sh",
                "-c",
                "set -e; umask 077; install -d -m700 \"${XDG_CONFIG_HOME:-$HOME/.config}/omasnitch\"; "
                + "FILE=\"${XDG_CONFIG_HOME:-$HOME/.config}/omasnitch/ui.conf\"; "
                + "touch \"$FILE\"; "
                + "chmod 600 \"$FILE\"; "
                + "grep -v '^show_recent_connections=' \"$FILE\" > \"$FILE.tmp\" || true; "
                + "printf 'show_recent_connections="
                + (value ? "1" : "0")
                + "\\n' >> \"$FILE.tmp\"; "
                + "mv \"$FILE.tmp\" \"$FILE\""
            ]

            recentSettingProcess.running = true
        }
    }

    implicitWidth:
        button.implicitWidth

    implicitHeight:
        button.implicitHeight

    onBarChanged:
        injectPanel()

    Loader {
        id: panelLoader

        active: true

        source:
            Qt.resolvedUrl(
                "Panel.qml"
            )

        visible: false

        onLoaded: {
            root.injectPanel()

            Qt.callLater(
                root.injectPanel
            )
        }
    }

    Process {
        id: rulesProcess

        command: [
            "omasnitchctl",
            "rules"
        ]

        stdout: StdioCollector {
            onStreamFinished: {
                try {
                    const object =
                        JSON.parse(
                            this.text
                        )

                    if (
                        object.type
                        !== "rules"
                    ) {
                        return
                    }

                    let count = 0

                    for (
                        let i = 0;
                        i < object.data.length;
                        i++
                    ) {
                        if (
                            object.data[i].action
                            === "block"
                        ) {
                            count++
                        }
                    }

                    root.blockedAppCount =
                        count
                } catch (error) {
                    console.log(
                        "OmaSnitch rules parse error:",
                        error
                    )
                }
            }
        }
    }

    Process {
        id: serviceCheckProcess
        command: ["/usr/bin/bash", "-c",
            "test \"$(omasnitchctl --version 2>/dev/null)\" = \"omasnitchctl "
            + root.expectedVersion + "\" && omasnitchctl status >/dev/null 2>&1"]
        onExited: function(exitCode) {
            if (exitCode === 0) root.setupState = "ready"
            else root.retrySetup()
        }
    }

    Process {
        id: bootstrapProcess
        command: ["/usr/bin/bash", root.pluginDir + "/scripts/bootstrap.sh"]
        stderr: StdioCollector {
            onStreamFinished: root.setupError = this.text.trim()
        }
        onExited: function(exitCode) {
            root.setupState = exitCode === 0 ? "ready" : "failed"
            if (exitCode === 0) {
                root.refreshRules()
            } else {
                Quickshell.execDetached(["notify-send", "-a", "OmaSnitch",
                    "OmaSnitch setup needs attention",
                    "Open the panel to retry. Details: ~/.cache/omasnitch/install.log"])
            }
        }
    }

    Process {
        id: uidProcess
        command: ["id", "-u"]
        stdout: StdioCollector {
            onStreamFinished: root.currentUid = parseInt(this.text.trim())
        }
    }

    Process {
        id: pendingProcess
        command: ["omasnitchctl", "pending"]
        stdout: StdioCollector {
            onStreamFinished: {
                try {
                    const object = JSON.parse(this.text)
                    if (object.type !== "pending") return
                    const items = object.data.filter(function(item) { return item.uid === root.currentUid })
                    const keys = items.map(function(item) { return item.application })
                    root.pendingCount = keys.length
                    if (root.pendingInitialized) {
                        for (let i = 0; i < items.length; i++) {
                            if (root.previousPending.indexOf(items[i].application) < 0)
                                Quickshell.execDetached(["notify-send", "-a", "OmaSnitch",
                                    "Internet access requested", items[i].application + " → " + items[i].destination
                                    + "\nOpen OmaSnitch to allow once, allow always, or block."])
                        }
                    }
                    root.previousPending = keys
                    root.pendingInitialized = true
                } catch (error) { console.log("OmaSnitch pending parse error:", error) }
            }
        }
    }

    Process {
        id: settingsReadProcess

        command: [
            "sh",
            "-c",
            "set -e; install -d -m700 \"${XDG_CONFIG_HOME:-$HOME/.config}/omasnitch\"; "
            + "FILE=\"${XDG_CONFIG_HOME:-$HOME/.config}/omasnitch/ui.conf\"; "
            + "if [ -f \"$FILE\" ]; then chmod 600 \"$FILE\"; fi; "
            + "BLOCKED=1; "
            + "RECENT=1; "
            + "if [ -f \"$FILE\" ]; then "
            + "B=$(grep '^show_blocked_count=' \"$FILE\" | tail -n1 | cut -d= -f2); "
            + "R=$(grep '^show_recent_connections=' \"$FILE\" | tail -n1 | cut -d= -f2); "
            + "[ -n \"$B\" ] && BLOCKED=\"$B\"; "
            + "[ -n \"$R\" ] && RECENT=\"$R\"; "
            + "fi; "
            + "printf '%s,%s\\n' \"$BLOCKED\" \"$RECENT\""
        ]

        stdout: StdioCollector {
            onStreamFinished: {
                const parts =
                    this.text
                        .trim()
                        .split(",")

                if (parts.length >= 1)
                    root.showBlockedCount =
                        parts[0] !== "0"

                if (parts.length >= 2)
                    root.showRecentConnections =
                        parts[1] !== "0"
            }
        }
    }

    Process {
        id: blockedSettingProcess

        command: [
            "true"
        ]
    }

    Process {
        id: recentSettingProcess

        command: [
            "true"
        ]
    }

    Timer {
        interval: 1500
        repeat: true
        running: true

        onTriggered: {
            root.refreshRules()
            if (!pendingProcess.running && root.currentUid >= 0) pendingProcess.running = true
        }
    }

    Component.onCompleted: {
        root.refreshRules()

        uidProcess.running = true

        serviceCheckProcess.running = true

        if (!settingsReadProcess.running)
            settingsReadProcess.running = true
    }

    WidgetButton {
        id: button

        anchors.fill: root

        bar: root.bar

        text:
            root.setupState === "installing" ? "󰒃 …" : root.setupState === "failed" ? "󰒃 !"
            : root.pendingCount > 0 ? "󰒃 " + root.pendingCount + " !" : root.showBlockedCount
            ? "󰒃 " + root.blockedAppCount
            : "󰒃"

        tooltipText:
            root.setupState === "installing" ? "OmaSnitch · installing service"
            : root.setupState === "failed" ? "OmaSnitch · setup failed; open to retry"
            : root.blockedAppCount === 1
            ? "OmaSnitch · 1 blocked application"
            : "OmaSnitch · "
              + root.blockedAppCount
              + " blocked applications"

        onPressed:
            function(buttonCode) {
                if (
                    buttonCode
                    === Qt.LeftButton
                ) {
                    root.toggle()
                }
            }
    }
}
