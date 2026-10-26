import QtQuick
import Quickshell
import Quickshell.Io
import qs.Commons
import qs.Commons as Commons
import qs.Ui

Panel {
    id: root

    moduleName: "vesp.omasnitch"
    manageIpc: false

    property var anchorItem: null
    property var hostWidget: null

    property var events: []
    property var traffic: []
    property var temporaryRules: []
    property var pending: []
    property var promptStatus: ({ enabled: false, uid: null })
    property var profileInfo: ({ active: "Home", names: ["Home", "Work", "Public Wi-Fi"] })
    property string previewText: ""
    property string actionError: ""
    property var rules: []
    property var applications: root.buildApplications(
        root.events, root.rules, DesktopEntries.applications.values, root.currentUid, root.hideLocal
    )
    property string selectedAppId: ""
    property string sortMode: "name"
    property var pinnedIds: []
    property var knownServices: []
    property var annotations: ({})
    property bool hideLocal: false
    property bool unknownAlerts: true
    property bool pinnedCollapsed: false
    property bool appsCollapsed: false
    property bool servicesCollapsed: false
    property var collapsedTags: ({})
    property bool preferencesReadyToLoad: false
    property bool preferencesLoaded: false
    property string copiedValue: ""
    readonly property string preferencesPath:
        Quickshell.env("HOME") + "/.config/omasnitch/panel.json"

    onApplicationsChanged: syncAppList()
    onCurrentUidChanged: Qt.callLater(root.refreshAll)
    onSearchQueryChanged: syncAppList()
    onSortModeChanged: {
        Qt.callLater(root.syncAppList)
        savePreferences()
    }
    onPinnedIdsChanged: {
        Qt.callLater(root.syncAppList)
        savePreferences()
    }
    onHideLocalChanged: { Qt.callLater(root.syncAppList); savePreferences() }
    onUnknownAlertsChanged: { Qt.callLater(root.syncAppList); savePreferences() }
    onKnownServicesChanged: { Qt.callLater(root.syncAppList); savePreferences() }
    onAnnotationsChanged: { Qt.callLater(root.syncAppList); savePreferences() }
    onPinnedCollapsedChanged: { Qt.callLater(root.syncAppList); savePreferences() }
    onAppsCollapsedChanged: { Qt.callLater(root.syncAppList); savePreferences() }
    onServicesCollapsedChanged: { Qt.callLater(root.syncAppList); savePreferences() }
    onCollapsedTagsChanged: { Qt.callLater(root.syncAppList); savePreferences() }

    ListModel {
        id: appListModel
    }

    Component.onCompleted: {
        syncAppList()
        ensurePreferencesDir.running = true
    }

    Process {
        id: ensurePreferencesDir
        command: ["mkdir", "-p", Quickshell.env("HOME") + "/.config/omasnitch"]
        onExited: {
            root.preferencesReadyToLoad = true
            preferencesFile.reload()
        }
    }

    FileView {
        id: preferencesFile
        path: root.preferencesReadyToLoad ? root.preferencesPath : ""
        watchChanges: false
        atomicWrites: true
        printErrors: false
        onLoaded: root.loadPreferences(text())
        onLoadFailed: root.loadPreferences("")
    }

    Timer {
        id: copyFeedbackTimer
        interval: 1500
        onTriggered: root.copiedValue = ""
    }

    property int currentUid: -1
    property bool busy: false
    property bool settingsOpen: false

    property string searchQuery: ""

    readonly property color panelBackground: Commons.Color.popups.background
    readonly property color textColor: Commons.Color.popups.text
    readonly property color inverseText: Qt.rgba(
        panelBackground.r, panelBackground.g, panelBackground.b, 1
    )
    readonly property color accentColor: Commons.Color.accent
    readonly property color dangerColor: Commons.Color.urgent

    function ink(alpha) {
        return Qt.rgba(textColor.r, textColor.g, textColor.b, alpha)
    }

    function loadPreferences(raw) {
        if (!preferencesReadyToLoad || preferencesLoaded)
            return
        try {
            const value = JSON.parse(raw || "{}")
            if (["name", "recent", "connections", "blocked"].indexOf(value.sort) >= 0)
                sortMode = value.sort
            if (Array.isArray(value.pinned))
                pinnedIds = value.pinned.filter(function(id) { return typeof id === "string" })
            if (Array.isArray(value.knownServices))
                knownServices = value.knownServices.filter(function(id) { return typeof id === "string" })
            if (value.annotations && typeof value.annotations === "object")
                annotations = value.annotations
            hideLocal = value.hideLocal === true
            unknownAlerts = value.unknownAlerts !== false
            pinnedCollapsed = value.pinnedCollapsed === true
            appsCollapsed = value.appsCollapsed === true
            servicesCollapsed = value.servicesCollapsed === true
            if (value.collapsedTags && typeof value.collapsedTags === "object")
                collapsedTags = value.collapsedTags
        } catch (error) {
            console.log("OmaSnitch preferences error:", error)
        }
        preferencesLoaded = true
        syncAppList()
    }

    function savePreferences() {
        if (!preferencesLoaded)
            return
        preferencesFile.setText(JSON.stringify({
            version: 2,
            sort: sortMode,
            pinned: pinnedIds,
            knownServices: knownServices,
            annotations: annotations,
            hideLocal: hideLocal,
            unknownAlerts: unknownAlerts,
            pinnedCollapsed: pinnedCollapsed,
            appsCollapsed: appsCollapsed,
            servicesCollapsed: servicesCollapsed,
            collapsedTags: collapsedTags
        }, null, 2) + "\n")
    }

    function isPinned(id) {
        return pinnedIds.indexOf(id) >= 0
    }

    function isUnknown(app) {
        return unknownAlerts && !!app && app.kind === "service" && knownServices.indexOf(app.ruleKey) < 0
    }

    function acknowledge(app) {
        if (!isUnknown(app)) return
        knownServices = knownServices.concat([app.ruleKey])
    }

    function updateAnnotation(app, field, value) {
        if (!app || !app.ruleKey) return
        const next = Object.assign({}, annotations)
        next[app.ruleKey] = Object.assign({}, next[app.ruleKey] || {})
        next[app.ruleKey][field] = String(value).slice(0, 160)
        annotations = next
    }

    function annotation(app, field) {
        return app && annotations[app.ruleKey] ? String(annotations[app.ruleKey][field] || "") : ""
    }

    function trafficFor(app) {
        if (!app) return ({ uploaded: 0, downloaded: 0 })
        for (let i = 0; i < traffic.length; i++)
            if (traffic[i].application === app.ruleKey
                && (currentUid < 0 || traffic[i].uid === currentUid)) return traffic[i]
        return ({ uploaded: 0, downloaded: 0 })
    }

    function temporaryFor(app) {
        if (!app) return 0
        for (let i = 0; i < temporaryRules.length; i++)
            if (temporaryRules[i].application === app.ruleKey)
                return temporaryRules[i].remaining_seconds === null
                    ? -1 : temporaryRules[i].remaining_seconds
        return 0
    }

    function formatBytes(value) {
        const bytes = Math.max(0, Number(value) || 0)
        if (bytes < 1024) return Math.round(bytes) + " B"
        if (bytes < 1048576) return (bytes / 1024).toFixed(1) + " KB"
        if (bytes < 1073741824) return (bytes / 1048576).toFixed(1) + " MB"
        return (bytes / 1073741824).toFixed(2) + " GB"
    }

    function togglePinned(id) {
        const next = pinnedIds.slice()
        const index = next.indexOf(id)
        if (index >= 0)
            next.splice(index, 1)
        else
            next.push(id)
        pinnedIds = next
    }

    function toggleSection(section) {
        if (section === "pinned")
            pinnedCollapsed = !pinnedCollapsed
        else if (section === "applications")
            appsCollapsed = !appsCollapsed
        else if (section === "services")
            servicesCollapsed = !servicesCollapsed
        else if (section.indexOf("tag:") === 0) {
            const next = Object.assign({}, collapsedTags)
            next[section] = !next[section]
            collapsedTags = next
        }
    }

    function copyText(value) {
        const text = String(value || "")
        if (!text)
            return
        Quickshell.execDetached(["wl-copy", text])
        copiedValue = text
        copyFeedbackTimer.restart()
    }

    function formatSeen(timestamp) {
        return timestamp > 0
            ? Qt.formatDateTime(new Date(timestamp * 1000), "dd MMM yyyy · HH:mm")
            : "Never seen"
    }

    function isLocalAddress(address) {
        const value = String(address || "").toLowerCase()
        if (value.indexOf(":") >= 0) {
            if (value === "::1" || value.indexOf("fe8") === 0
                    || value.indexOf("fe9") === 0 || value.indexOf("fea") === 0
                    || value.indexOf("feb") === 0 || value.indexOf("fc") === 0
                    || value.indexOf("fd") === 0)
                return true
            const mapped = value.match(/(?:^|:)ffff:(\d+\.\d+\.\d+\.\d+)$/)
            return mapped ? root.isLocalAddress(mapped[1]) : false
        }
        const parts = value.split(".").map(Number)
        if (parts.length !== 4 || parts.some(function(n) { return !isFinite(n) || n < 0 || n > 255 }))
            return false
        return parts[0] === 10 || parts[0] === 127
            || (parts[0] === 172 && parts[1] >= 16 && parts[1] <= 31)
            || (parts[0] === 192 && parts[1] === 168)
            || (parts[0] === 169 && parts[1] === 254)
    }

    function open() {
        root.controller.show()
        refreshAll()
    }

    function close() {
        root.settingsOpen = false
        root.selectedAppId = ""
        root.controller.hide()
    }

    function toggle() {
        if (root.opened)
            close()
        else
            open()
    }

    function switchPanel(direction) {
        if (
            root.bar
            && typeof root.bar.switchPanelFrom === "function"
        ) {
            return root.bar.switchPanelFrom(
                root.hostWidget || root,
                direction
            )
        }

        return false
    }

    function blockedCountVisible() {
        return root.hostWidget
            ? root.hostWidget.showBlockedCount
            : true
    }

    function toggleBlockedCount() {
        if (
            root.hostWidget
            && typeof root.hostWidget.updateShowBlockedCount === "function"
        ) {
            root.hostWidget.updateShowBlockedCount(
                !root.hostWidget.showBlockedCount
            )
        }
    }

    function iconKey(value) {
        return String(value || "")
            .toLowerCase()
            .replace(/\.desktop$/, "")
            .replace(/[^a-z0-9]/g, "")
    }

    function iconSource(name) {
        const value = String(name || "")
        if (!value)
            return ""
        if (value.indexOf("file://") === 0 || value.indexOf("image://") === 0)
            return value
        if (value.charAt(0) === "/")
            return "file://" + value
        return Quickshell.iconPath(value, true)
    }

    function appIconSource(application, executable, revision) {
        const app = String(application || "").toLowerCase()
        const aliases = {
            "brave": "brave-desktop",
            "vscode": "vscode",
            "google-chrome": "google-chrome",
            "telegram-desktop": "telegram",
            "discord": "omarchy-discord",
            "codex": "chatgpt"
        }
        const names = [aliases[app], app]
        const executableName = String(executable || "").split("/").pop()
        if (executableName && executableName !== app)
            names.push(executableName)

        const entries = DesktopEntries.applications.values || []
        let best = null
        let bestScore = 0
        for (let i = 0; i < entries.length; i++) {
            const entry = entries[i]
            if (!entry || !entry.icon)
                continue
            const id = iconKey(entry.id)
            const title = iconKey(entry.name)
            const icon = iconKey(entry.icon)
            const command = entry.command || []
            const commandName = iconKey(
                command.length > 0 ? String(command[0]).split("/").pop() : ""
            )
            for (let j = 0; j < names.length; j++) {
                const key = iconKey(names[j])
                if (!key)
                    continue
                let score = 0
                if (commandName === key || id === key || icon === key)
                    score = 4
                else if (title === key)
                    score = 3
                else if (id && (id.endsWith(key) || key.endsWith(id)))
                    score = 2
                if (score > bestScore) {
                    best = entry
                    bestScore = score
                }
            }
        }
        if (best) {
            const source = iconSource(best.icon)
            if (source)
                return source
        }
        for (let i = 0; i < names.length; i++) {
            const source = iconSource(names[i])
            if (source)
                return source
        }
        return iconSource("application-x-executable")
    }

    function applicationKey(entry) {
        const command = entry.command || []
        if (command.length === 0)
            return ""
        let binary = String(command[0]).split("/").pop().toLowerCase()
        if (binary === "env") {
            for (let i = 1; i < command.length; i++) {
                const part = String(command[i])
                if (part.indexOf("=") < 0 && part.charAt(0) !== "-") {
                    binary = part.split("/").pop().toLowerCase()
                    break
                }
            }
        }
        if (["sh", "bash", "flatpak", "uwsm-app", "omarchy-launch-webapp", "gtk-launch"].indexOf(binary) >= 0)
            return ""
        const aliases = {
            "brave-browser": "brave",
            "brave-bin": "brave",
            "google-chrome-stable": "google-chrome",
            "code": "vscode",
            "code-oss": "vscode",
            "firefox-bin": "firefox",
            "discordcanary": "discord"
        }
        return aliases[binary] || binary
    }

    function buildApplications(allEvents, allRules, desktopEntries, uid, hideLocalFlag) {
        const summaries = {}
        for (let i = 0; i < allEvents.length; i++) {
            const event = allEvents[i]
            if (uid >= 0 && event.uid !== uid)
                continue
            if (hideLocalFlag && isLocalAddress(event.destination))
                continue
            const key = event.application
            if (!summaries[key])
                summaries[key] = {
                    connections: 0,
                    blocked: 0,
                    executable: event.executable || "",
                    lastTimestamp: 0,
                    localCount: 0,
                    internetCount: 0,
                    tcpCount: 0,
                    udpCount: 0
                }
            summaries[key].connections++
            if (event.verdict === "block")
                summaries[key].blocked++
            if (event.executable)
                summaries[key].executable = event.executable
            if (event.timestamp > summaries[key].lastTimestamp)
                summaries[key].lastTimestamp = event.timestamp
            if (isLocalAddress(event.destination))
                summaries[key].localCount++
            else
                summaries[key].internetCount++
            if (event.protocol === "TCP")
                summaries[key].tcpCount++
            else if (event.protocol === "UDP")
                summaries[key].udpCount++
        }

        const apps = []
        const matchedKeys = {}
        const entries = desktopEntries || []
        for (let i = 0; i < entries.length; i++) {
            const entry = entries[i]
            if (!entry || entry.noDisplay)
                continue
            const id = String(entry.id || "")
            const name = String(entry.name || id)
            if (!id || !name)
                continue
            const key = applicationKey(entry)
            if (key)
                matchedKeys[key] = true
            const summary = summaries[key] || {
                connections: 0, blocked: 0, executable: "", lastTimestamp: 0,
                localCount: 0, internetCount: 0, tcpCount: 0, udpCount: 0
            }
            let action = "allow"
            if (key) {
                for (let j = 0; j < allRules.length; j++) {
                    if (allRules[j].application === key) {
                        action = allRules[j].action
                        break
                    }
                }
            }
            apps.push({
                desktopId: id,
                application: name,
                ruleKey: key,
                icon: String(entry.icon || ""),
                kind: "application",
                executable: summary.executable || String((entry.command || [])[0] || ""),
                connections: summary.connections,
                blocked: summary.blocked,
                lastTimestamp: summary.lastTimestamp,
                localCount: summary.localCount,
                internetCount: summary.internetCount,
                tcpCount: summary.tcpCount,
                udpCount: summary.udpCount,
                action: action
            })
        }
        apps.sort(function(a, b) {
            return a.application.localeCompare(b.application)
        })

        const processes = []
        for (const key in summaries) {
            if (!key || matchedKeys[key])
                continue
            const summary = summaries[key]
            let action = "allow"
            for (let i = 0; i < allRules.length; i++) {
                if (allRules[i].application === key) {
                    action = allRules[i].action
                    break
                }
            }
            processes.push({
                desktopId: "process:" + key,
                application: key,
                ruleKey: key,
                icon: appIconSource(key, summary.executable, 0),
                kind: "service",
                executable: summary.executable,
                connections: summary.connections,
                blocked: summary.blocked,
                lastTimestamp: summary.lastTimestamp,
                localCount: summary.localCount,
                internetCount: summary.internetCount,
                tcpCount: summary.tcpCount,
                udpCount: summary.udpCount,
                action: action
            })
        }
        processes.sort(function(a, b) {
            return a.application.localeCompare(b.application)
        })
        for (let i = 0; i < processes.length; i++)
            apps.push(processes[i])
        return apps
    }

    function selectedApplication() {
        for (let i = 0; i < applications.length; i++) {
            if (applications[i].desktopId === selectedAppId)
                return applications[i]
        }
        return null
    }

    function selectedRecentEvents() {
        const app = selectedApplication()
        if (!app || !app.ruleKey)
            return []
        return events.filter(function(event) {
            return event.application === app.ruleKey
                && (currentUid < 0 || event.uid === currentUid)
                && (!hideLocal || !isLocalAddress(event.destination))
        }).slice(-20).reverse()
    }

    function refreshAll() {
        if (
            currentUid < 0
            && !uidProcess.running
        ) {
            uidProcess.running = true
        }

        if (!rulesProcess.running)
            rulesProcess.running = true

        if (!eventsProcess.running)
            eventsProcess.running = true
        if (!trafficProcess.running)
            trafficProcess.running = true
        if (!temporaryProcess.running)
            temporaryProcess.running = true
        if (!profilesProcess.running)
            profilesProcess.running = true
        if (currentUid >= 0 && !pendingProcess.running)
            pendingProcess.running = true
        if (!promptStatusProcess.running)
            promptStatusProcess.running = true
    }

    function setRule(application, action) {
        if (actionProcess.running)
            return

        root.busy = true
        root.actionError = ""

        actionProcess.command = [
            "omasnitchctl",
            action,
            application
        ]

        actionProcess.running = true
    }

    function runAction(args) {
        if (actionProcess.running) return
        root.busy = true
        root.actionError = ""
        actionProcess.command = ["omasnitchctl"].concat(args)
        actionProcess.running = true
    }

    function previewAddress(address) {
        const value = String(address || "").trim()
        if (!value || previewProcess.running) return
        previewText = "Checking recorded connections…"
        previewProcess.command = ["omasnitchctl", "preview-ip", value]
        previewProcess.running = true
    }

    function openPending(application) {
        for (let i = 0; i < applications.length; i++) {
            if (applications[i].ruleKey === application) {
                selectedAppId = applications[i].desktopId
                return
            }
        }
    }

    function visibleApplications() {
        const query = searchQuery.trim().toLowerCase()
        let visible = applications.filter(function(app) {
            return !query || (app.application + " " + app.desktopId)
                .toLowerCase().indexOf(query) >= 0
        })
        if (sortMode === "recent") {
            visible = visible.filter(function(app) { return app.lastTimestamp > 0 })
            visible.sort(function(a, b) {
                return b.lastTimestamp - a.lastTimestamp
                    || a.application.localeCompare(b.application)
            })
            return visible.slice(0, 10)
        }
        if (sortMode === "connections")
            return visible.filter(function(app) { return app.connections > 0 })
        if (sortMode === "blocked")
            return visible.filter(function(app) {
                return app.blocked > 0 || app.action === "block"
            })
        return visible
    }

    function filteredApplications() {
        const visible = visibleApplications()
        function compare(a, b) {
            let difference = 0
            if (root.sortMode === "recent")
                difference = b.lastTimestamp - a.lastTimestamp
            else if (root.sortMode === "connections")
                difference = b.connections - a.connections
            else if (root.sortMode === "blocked")
                difference = b.blocked - a.blocked
            return difference || a.application.localeCompare(b.application)
        }
        const pinned = []
        const apps = []
        const services = []
        for (let i = 0; i < visible.length; i++) {
            const app = visible[i]
            if (isPinned(app.desktopId))
                pinned.push(app)
            else if (app.kind === "service")
                services.push(app)
            else
                apps.push(app)
        }
        pinned.sort(compare)
        apps.sort(compare)
        services.sort(compare)

        const rows = []
        function appendSection(items, key, label, collapsed) {
            if (items.length === 0)
                return
            rows.push({
                desktopId: "heading:" + key,
                application: label + " · " + items.length,
                ruleKey: "",
                icon: "",
                kind: "heading",
                executable: "",
                connections: 0,
                blocked: 0,
                lastTimestamp: 0,
                localCount: 0,
                internetCount: 0,
                tcpCount: 0,
                udpCount: 0,
                action: "allow",
                rowType: "heading",
                sectionKey: key,
                pinned: false,
                collapsed: collapsed,
                unknown: false,
                tag: ""
            })
            if (collapsed)
                return
            for (let i = 0; i < items.length; i++) {
                const row = {}
                for (const role in items[i])
                    row[role] = items[i][role]
                row.rowType = "item"
                row.sectionKey = key
                row.pinned = key === "pinned"
                row.collapsed = false
                row.unknown = root.isUnknown(row)
                row.tag = root.annotation(row, "tag")
                rows.push(row)
            }
        }
        appendSection(pinned, "pinned", "Pinned", pinnedCollapsed)
        appendSection(apps, "applications", "Applications", appsCollapsed)
        const tagged = {}
        const untagged = []
        for (let i = 0; i < services.length; i++) {
            const tag = root.annotation(services[i], "tag").trim()
            if (!tag) untagged.push(services[i])
            else (tagged[tag] || (tagged[tag] = [])).push(services[i])
        }
        Object.keys(tagged).sort().forEach(function(tag) {
            const key = "tag:" + tag
            appendSection(tagged[tag], key, tag, !!root.collapsedTags[key])
        })
        appendSection(untagged, "services", "Services & processes", servicesCollapsed)
        return rows
    }

    function matchingApplicationsCount() {
        return visibleApplications().length
    }

    function activeTabSummary() {
        const count = matchingApplicationsCount()
        const descriptions = {
            name: "all by name",
            recent: "latest 10 active",
            connections: "connected, most first",
            blocked: "blocked or with blocked traffic"
        }
        return count + " items · " + descriptions[sortMode]
    }

    function emptyListMessage() {
        if (searchQuery.trim())
            return "No matching items"
        if (sortMode === "recent")
            return "No recent activity"
        if (sortMode === "connections")
            return "No connections recorded"
        if (sortMode === "blocked")
            return "Nothing blocked"
        return "No applications found"
    }

    function syncAppList() {
        if (!appListModel)
            return
        const rows = filteredApplications()
        for (let i = 0; i < rows.length; i++) {
            const row = rows[i]
            let found = -1
            for (let j = i; j < appListModel.count; j++) {
                if (appListModel.get(j).desktopId === row.desktopId) {
                    found = j
                    break
                }
            }
            if (found < 0)
                appListModel.insert(i, row)
            else if (found !== i)
                appListModel.move(found, i, 1)

            const current = appListModel.get(i)
            for (const role in row) {
                if (current[role] !== row[role])
                    appListModel.setProperty(i, role, row[role])
            }
        }
        while (appListModel.count > rows.length)
            appListModel.remove(appListModel.count - 1)
    }

    Process {
        id: uidProcess

        command: [
            "id",
            "-u"
        ]

        stdout: StdioCollector {
            onStreamFinished: {
                const value =
                    parseInt(this.text.trim())

                if (!isNaN(value)) {
                    root.currentUid = value
                }
            }
        }
    }

    Process {
        id: eventsProcess

        command: [
            "omasnitchctl",
            "events"
        ]

        stdout: StdioCollector {
            onStreamFinished: {
                try {
                    const object =
                        JSON.parse(this.text)

                    if (object.type === "events")
                        root.events = object.data
                } catch (error) {
                    console.log(
                        "OmaSnitch events error:",
                        error
                    )
                }
            }
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
                        JSON.parse(this.text)

                    if (object.type === "rules")
                        root.rules = object.data
                } catch (error) {
                    console.log(
                        "OmaSnitch rules error:",
                        error
                    )
                }
            }
        }
    }

    Process {
        id: trafficProcess
        command: ["omasnitchctl", "traffic"]
        stdout: StdioCollector {
            onStreamFinished: {
                try {
                    const object = JSON.parse(this.text)
                    if (object.type === "traffic") root.traffic = object.data
                } catch (error) { console.log("OmaSnitch traffic error:", error) }
            }
        }
    }

    Process {
        id: temporaryProcess
        command: ["omasnitchctl", "temporary"]
        stdout: StdioCollector {
            onStreamFinished: {
                try {
                    const object = JSON.parse(this.text)
                    if (object.type === "temporary") root.temporaryRules = object.data
                } catch (error) { console.log("OmaSnitch temporary rules error:", error) }
            }
        }
    }

    Process {
        id: profilesProcess
        command: ["omasnitchctl", "profiles"]
        stdout: StdioCollector {
            onStreamFinished: {
                try {
                    const object = JSON.parse(this.text)
                    if (object.type === "profiles") root.profileInfo = object.data
                } catch (error) { console.log("OmaSnitch profiles error:", error) }
            }
        }
    }

    Process {
        id: previewProcess
        command: []
        stdout: StdioCollector {
            onStreamFinished: {
                try {
                    const object = JSON.parse(this.text)
                    if (object.type === "ip_preview") {
                        const data = object.data
                        root.previewText = data.applications.length
                            ? data.applications.join(", ") + " · " + data.recorded_attempts + " recorded attempts"
                            : "No matching attempts in the recent history"
                    } else if (object.type === "error") root.previewText = String(object.data)
                } catch (error) { root.previewText = "Preview unavailable" }
            }
        }
    }

    Process {
        id: pendingProcess
        command: ["omasnitchctl", "pending"]
        stdout: StdioCollector {
            onStreamFinished: {
                try {
                    const object = JSON.parse(this.text)
                    if (object.type === "pending")
                        root.pending = object.data.filter(function(item) { return item.uid === root.currentUid })
                } catch (error) { console.log("OmaSnitch pending error:", error) }
            }
        }
    }

    Process {
        id: promptStatusProcess
        command: ["omasnitchctl", "prompt-status"]
        stdout: StdioCollector {
            onStreamFinished: {
                try {
                    const object = JSON.parse(this.text)
                    if (object.type === "prompt_status") root.promptStatus = object.data
                } catch (error) { console.log("OmaSnitch prompt status error:", error) }
            }
        }
    }

    Process {
        id: actionProcess

        command: []

        stdout: StdioCollector {
            onStreamFinished: {
                try {
                    const response = JSON.parse(this.text)
                    if (response.type === "error") root.actionError = String(response.data)
                } catch (error) { root.actionError = "Action failed" }
            }
        }

        onRunningChanged: {
            if (!running) {
                root.busy = false
                Qt.callLater(root.refreshAll)
            }
        }
    }

    Timer {
        interval: 1500
        repeat: true

        running:
            root.opened
            && !root.settingsOpen

        onTriggered:
            root.refreshAll()
    }

    KeyboardPanel {
        id: panel
        anchorItem: root.anchorItem
        owner: root.hostWidget || root
        bar: root.bar
        open: root.opened
        focusTarget: keyCatcher
        contentWidth: panel.fittedContentWidth(Style.space(450))
        contentHeight: panel.fittedContentHeight(Style.space(680))

        PanelKeyCatcher {
            id: keyCatcher
            anchors.fill: parent
            onCloseRequested: root.close()
            onTabRequested: function(direction) { root.switchPanel(direction) }

            Rectangle {
                anchors.fill: parent
                radius: 14
                clip: true
                color: root.panelBackground
                border.width: 1
                border.color: root.ink(0.12)

                Column {
                    anchors.fill: parent
                    anchors.margins: 16
                    spacing: 12

                    Item {
                        width: parent.width
                        height: 42

                        Rectangle {
                            id: backButton
                            visible: root.settingsOpen || root.selectedAppId !== ""
                            width: 32
                            height: 32
                            radius: 9
                            anchors.verticalCenter: parent.verticalCenter
                            color: backMouse.containsMouse ? root.ink(0.10) : root.ink(0.05)
                            Text {
                                anchors.centerIn: parent
                                text: "‹"
                                color: root.textColor
                                font.pixelSize: 22
                            }
                            MouseArea {
                                id: backMouse
                                anchors.fill: parent
                                hoverEnabled: true
                                cursorShape: Qt.PointingHandCursor
                                onClicked: {
                                    root.settingsOpen = false
                                    root.selectedAppId = ""
                                }
                            }
                        }

                        Text {
                            anchors.left: backButton.visible ? backButton.right : parent.left
                            anchors.leftMargin: backButton.visible ? 10 : 0
                            anchors.right: settingsButton.left
                            anchors.rightMargin: 8
                            anchors.verticalCenter: parent.verticalCenter
                            text: root.settingsOpen ? "Settings"
                                : (root.selectedAppId !== "" && root.selectedApplication()
                                    ? root.selectedApplication().application : "OmaSnitch")
                            color: root.textColor
                            elide: Text.ElideRight
                            font.pixelSize: 18
                            font.bold: true
                        }

                        Rectangle {
                            id: settingsButton
                            visible: root.selectedAppId === "" && !root.settingsOpen
                            width: 32
                            height: 32
                            radius: 9
                            anchors.right: parent.right
                            anchors.verticalCenter: parent.verticalCenter
                            color: settingsMouse.containsMouse ? root.ink(0.10) : root.ink(0.05)
                            Text {
                                anchors.centerIn: parent
                                text: "󰒓"
                                color: root.textColor
                                font.pixelSize: 16
                            }
                            MouseArea {
                                id: settingsMouse
                                anchors.fill: parent
                                hoverEnabled: true
                                cursorShape: Qt.PointingHandCursor
                                onClicked: root.settingsOpen = true
                            }
                        }
                    }

                    Item {
                        id: panelBody
                        width: parent.width
                        height: parent.height - 54

                        Column {
                            id: catalog
                            visible: root.selectedAppId === "" && !root.settingsOpen
                            anchors.fill: parent
                            spacing: 10

                            Rectangle {
                                width: parent.width
                                height: 42
                                radius: 10
                                color: root.ink(0.05)
                                border.width: 1
                                border.color: root.ink(0.07)

                                Text {
                                    anchors.left: parent.left
                                    anchors.leftMargin: 12
                                    anchors.verticalCenter: parent.verticalCenter
                                    text: "󰍉"
                                    color: root.ink(0.48)
                                    font.pixelSize: 15
                                }
                                TextInput {
                                    id: searchInput
                                    anchors.left: parent.left
                                    anchors.leftMargin: 37
                                    anchors.right: parent.right
                                    anchors.rightMargin: 12
                                    anchors.verticalCenter: parent.verticalCenter
                                    text: root.searchQuery
                                    color: root.textColor
                                    font.pixelSize: 12
                                    clip: true
                                    selectByMouse: true
                                    selectionColor: root.textColor
                                    selectedTextColor: root.inverseText
                                    onTextChanged: root.searchQuery = text
                                }
                                Text {
                                    visible: searchInput.text.length === 0
                                    anchors.left: searchInput.left
                                    anchors.verticalCenter: parent.verticalCenter
                                    text: "Search installed applications"
                                    color: root.ink(0.42)
                                    font.pixelSize: 12
                                }
                            }

                            Rectangle {
                                id: pendingBanner
                                visible: root.pending.length > 0
                                width: parent.width
                                height: visible ? 60 : 0
                                radius: 10
                                color: Qt.rgba(0.98, 0.72, 0.20, 0.15)
                                border.width: 1
                                border.color: Qt.rgba(0.98, 0.72, 0.20, 0.35)
                                Row {
                                    anchors.fill: parent
                                    anchors.margins: 10
                                    spacing: 8
                                    Column {
                                        width: parent.width - 85
                                        anchors.verticalCenter: parent.verticalCenter
                                        spacing: 3
                                        Text { text: root.pending.length + " awaiting decision"; color: root.textColor; font.pixelSize: 11; font.bold: true }
                                        Text { width: parent.width; text: root.pending.length ? root.pending[0].application + " → " + root.pending[0].destination : ""; color: root.ink(0.65); font.pixelSize: 10; elide: Text.ElideRight }
                                    }
                                    Rectangle {
                                        width: 77; height: 28; radius: 7
                                        anchors.verticalCenter: parent.verticalCenter
                                        color: root.textColor
                                        Text { anchors.centerIn: parent; text: "Review"; color: root.inverseText; font.pixelSize: 10; font.bold: true }
                                        MouseArea { anchors.fill: parent; cursorShape: Qt.PointingHandCursor; onClicked: if (root.pending.length) root.openPending(root.pending[0].application) }
                                    }
                                }
                            }

                            Row {
                                width: parent.width
                                height: 30
                                spacing: 6
                                Repeater {
                                    model: [
                                        { key: "name", label: "Name" },
                                        { key: "recent", label: "Recent" },
                                        { key: "connections", label: "Connections" },
                                        { key: "blocked", label: "Blocked" }
                                    ]
                                    delegate: Rectangle {
                                        required property var modelData
                                        width: (parent.width - 18) / 4
                                        height: parent.height
                                        radius: 8
                                        color: root.sortMode === modelData.key
                                            ? root.textColor : root.ink(0.05)
                                        Text {
                                            anchors.centerIn: parent
                                            text: modelData.label
                                            color: root.sortMode === modelData.key
                                                ? root.inverseText : root.textColor
                                            font.pixelSize: 10
                                            font.bold: true
                                        }
                                        MouseArea {
                                            anchors.fill: parent
                                            cursorShape: Qt.PointingHandCursor
                                            onClicked: root.sortMode = modelData.key
                                        }
                                    }
                                }
                            }

                            Text {
                                width: parent.width
                                height: 18
                                text: root.activeTabSummary()
                                color: root.ink(0.55)
                                font.pixelSize: 11
                            }

                            Rectangle {
                                width: parent.width
                                height: catalog.height - 120 - pendingBanner.height - (pendingBanner.visible ? 10 : 0)
                                radius: 11
                                color: root.ink(0.025)
                                clip: true

                                ListView {
                                    id: appList
                                    anchors.fill: parent
                                    clip: true
                                    model: appListModel
                                    spacing: 2

                                    delegate: Rectangle {
                                        id: appRow
                                        required property string application
                                        required property string desktopId
                                        required property string icon
                                        required property string rowType
                                        required property string sectionKey
                                        required property bool pinned
                                        required property bool collapsed
                                        required property bool unknown
                                        required property string tag
                                        width: appList.width
                                        height: rowType === "heading" ? 34 : 56
                                        radius: 9
                                        color: rowType === "item" && appMouse.containsMouse
                                            ? root.ink(0.09) : "transparent"

                                        Row {
                                            visible: appRow.rowType === "heading"
                                            anchors.fill: parent
                                            anchors.leftMargin: 10
                                            anchors.rightMargin: 10
                                            Text {
                                                width: parent.width - 20
                                                anchors.verticalCenter: parent.verticalCenter
                                                text: appRow.application
                                                color: root.ink(0.6)
                                                font.pixelSize: 11
                                                font.bold: true
                                            }
                                            Text {
                                                width: 20
                                                anchors.verticalCenter: parent.verticalCenter
                                                text: appRow.collapsed ? "▸" : "▾"
                                                color: root.ink(0.5)
                                                horizontalAlignment: Text.AlignRight
                                                font.pixelSize: 13
                                            }
                                        }
                                        MouseArea {
                                            visible: appRow.rowType === "heading"
                                            anchors.fill: parent
                                            cursorShape: Qt.PointingHandCursor
                                            onClicked: root.toggleSection(appRow.sectionKey)
                                        }

                                        Row {
                                            visible: appRow.rowType === "item"
                                            anchors.fill: parent
                                            anchors.leftMargin: 10
                                            anchors.rightMargin: 10
                                            spacing: 12

                                            Item {
                                                width: 36
                                                height: 36
                                                anchors.verticalCenter: parent.verticalCenter
                                                Rectangle {
                                                    anchors.fill: parent
                                                    radius: 9
                                                    color: root.ink(0.07)
                                                    visible: appImage.status !== Image.Ready
                                                    Text {
                                                        anchors.centerIn: parent
                                                        text: appRow.application.charAt(0).toUpperCase()
                                                textFormat: Text.PlainText
                                                        color: root.textColor
                                                        font.pixelSize: 14
                                                        font.bold: true
                                                    }
                                                }
                                                Image {
                                                    id: appImage
                                                    anchors.fill: parent
                                                    anchors.margins: 2
                                                    source: root.iconSource(appRow.icon)
                                                        || root.iconSource("application-x-executable")
                                                    sourceSize.width: 32
                                                    sourceSize.height: 32
                                                    fillMode: Image.PreserveAspectFit
                                                    smooth: true
                                                }
                                            }

                                            Text {
                                                width: parent.width - 36 - 12 - 36 - (appRow.unknown ? 44 : 0)
                                                anchors.verticalCenter: parent.verticalCenter
                                                text: appRow.application
                                                textFormat: Text.PlainText
                                                color: root.textColor
                                                elide: Text.ElideRight
                                                font.pixelSize: 13
                                                font.bold: true
                                            }
                                            Rectangle {
                                                visible: appRow.unknown
                                                width: 40
                                                height: 19
                                                radius: 6
                                                anchors.verticalCenter: parent.verticalCenter
                                                color: Qt.rgba(0.98, 0.72, 0.20, 0.18)
                                                Text {
                                                    anchors.centerIn: parent
                                                    text: "NEW"
                                                    color: "#d79a18"
                                                    font.pixelSize: 9
                                                    font.bold: true
                                                }
                                            }
                                        }
                                        MouseArea {
                                            id: appMouse
                                            visible: appRow.rowType === "item"
                                            anchors.fill: parent
                                            hoverEnabled: true
                                            cursorShape: Qt.PointingHandCursor
                                            onClicked: {
                                                root.selectedAppId = appRow.desktopId
                                                root.acknowledge(root.selectedApplication())
                                            }
                                        }
                                        Rectangle {
                                            visible: appRow.rowType === "item"
                                            width: 28
                                            height: 28
                                            radius: 8
                                            anchors.right: parent.right
                                            anchors.rightMargin: 8
                                            anchors.verticalCenter: parent.verticalCenter
                                            color: pinMouse.containsMouse ? root.ink(0.12) : "transparent"
                                            Text {
                                                anchors.centerIn: parent
                                                text: appRow.pinned ? "★" : "☆"
                                                color: appRow.pinned ? root.accentColor : root.ink(0.45)
                                                font.pixelSize: 18
                                            }
                                            MouseArea {
                                                id: pinMouse
                                                anchors.fill: parent
                                                hoverEnabled: true
                                                cursorShape: Qt.PointingHandCursor
                                                onClicked: root.togglePinned(appRow.desktopId)
                                            }
                                        }
                                    }
                                }

                                Text {
                                    visible: appList.count === 0
                                    anchors.centerIn: parent
                                    text: root.emptyListMessage()
                                    color: root.ink(0.5)
                                    font.pixelSize: 12
                                }
                            }
                        }

                        Flickable {
                            id: detail
                            visible: root.selectedAppId !== "" && !root.settingsOpen
                            anchors.fill: parent
                            clip: true
                            contentHeight: detailContent.height
                            readonly property var app: root.selectedApplication()

                            Column {
                            id: detailContent
                            width: detail.width
                            spacing: 10

                            Row {
                                width: parent.width
                                height: 60
                                spacing: 12
                                Item {
                                    width: 48
                                    height: 48
                                    anchors.verticalCenter: parent.verticalCenter
                                    Rectangle {
                                        anchors.fill: parent
                                        radius: 11
                                        color: root.ink(0.07)
                                        visible: detailIcon.status !== Image.Ready
                                    }
                                    Image {
                                        id: detailIcon
                                        anchors.fill: parent
                                        anchors.margins: 3
                                        source: detail.app ? (root.iconSource(detail.app.icon)
                                            || root.iconSource("application-x-executable")) : ""
                                        sourceSize.width: 42
                                        sourceSize.height: 42
                                        fillMode: Image.PreserveAspectFit
                                        smooth: true
                                    }
                                }
                                Column {
                                    width: parent.width - 60
                                    anchors.verticalCenter: parent.verticalCenter
                                    spacing: 3
                                    Text {
                                        width: parent.width
                                        text: detail.app ? detail.app.application : ""
                                        textFormat: Text.PlainText
                                        color: root.textColor
                                        elide: Text.ElideRight
                                        font.pixelSize: 15
                                        font.bold: true
                                    }
                                    Text {
                                        width: parent.width
                                        text: detail.app ? detail.app.desktopId : ""
                                        textFormat: Text.PlainText
                                        color: root.ink(0.5)
                                        elide: Text.ElideMiddle
                                        font.pixelSize: 10
                                    }
                                    Text {
                                        width: parent.width
                                        text: "Last seen: " + root.formatSeen(
                                            detail.app ? detail.app.lastTimestamp : 0)
                                        color: root.ink(0.58)
                                        elide: Text.ElideRight
                                        font.pixelSize: 10
                                    }
                                }
                            }

                            Rectangle {
                                id: executableRow
                                visible: !!detail.app && !!detail.app.executable
                                width: parent.width
                                height: 36
                                radius: 9
                                color: root.ink(0.045)
                                Text {
                                    anchors.left: parent.left
                                    anchors.leftMargin: 10
                                    anchors.right: executableCopy.left
                                    anchors.rightMargin: 8
                                    anchors.verticalCenter: parent.verticalCenter
                                    text: detail.app ? detail.app.executable : ""
                                    textFormat: Text.PlainText
                                    color: root.ink(0.68)
                                    elide: Text.ElideMiddle
                                    font.pixelSize: 10
                                }
                                Rectangle {
                                    id: executableCopy
                                    width: 44
                                    height: 26
                                    radius: 7
                                    anchors.right: parent.right
                                    anchors.rightMargin: 5
                                    anchors.verticalCenter: parent.verticalCenter
                                    color: executableCopyMouse.containsMouse
                                        ? root.ink(0.14) : root.ink(0.07)
                                    Text {
                                        anchors.centerIn: parent
                                        text: detail.app && root.copiedValue === detail.app.executable
                                            ? "✓" : "Copy"
                                        color: root.textColor
                                        font.pixelSize: 10
                                    }
                                    MouseArea {
                                        id: executableCopyMouse
                                        anchors.fill: parent
                                        hoverEnabled: true
                                        cursorShape: Qt.PointingHandCursor
                                        onClicked: if (detail.app) root.copyText(detail.app.executable)
                                    }
                                }
                            }

                            Row {
                                width: parent.width
                                height: 72
                                spacing: 10
                                Repeater {
                                    model: [
                                        { title: "Connections", count: detail.app ? detail.app.connections : 0 },
                                        { title: "Blocked", count: detail.app ? detail.app.blocked : 0 }
                                    ]
                                    delegate: Rectangle {
                                        required property var modelData
                                        width: (parent.width - 10) / 2
                                        height: parent.height
                                        radius: 10
                                        color: root.ink(0.045)
                                        Column {
                                            anchors.left: parent.left
                                            anchors.leftMargin: 12
                                            anchors.verticalCenter: parent.verticalCenter
                                            spacing: 4
                                            Text {
                                                text: modelData.count
                                                color: root.textColor
                                                font.pixelSize: 20
                                                font.bold: true
                                            }
                                            Text {
                                                text: modelData.title
                                                color: root.ink(0.55)
                                                font.pixelSize: 11
                                            }
                                        }
                                    }
                                }
                            }

                            Rectangle {
                                width: parent.width
                                height: 72
                                radius: 10
                                color: root.ink(0.045)
                                Column {
                                    anchors.fill: parent
                                    anchors.margins: 10
                                    spacing: 5
                                    Text {
                                        text: "Connection breakdown"
                                        color: root.textColor
                                        font.pixelSize: 11
                                        font.bold: true
                                    }
                                    Text {
                                        text: "Local " + (root.hideLocal ? "hidden" : (detail.app ? detail.app.localCount : 0))
                                            + "   ·   Internet " + (detail.app ? detail.app.internetCount : 0)
                                        color: root.ink(0.68)
                                        font.pixelSize: 10
                                    }
                                    Text {
                                        text: "TCP " + (detail.app ? detail.app.tcpCount : 0)
                                            + "   ·   UDP " + (detail.app ? detail.app.udpCount : 0)
                                            + ((detail.app && detail.app.connections
                                                - detail.app.tcpCount - detail.app.udpCount > 0)
                                                ? "   ·   Other " + (detail.app.connections
                                                    - detail.app.tcpCount - detail.app.udpCount)
                                                : "")
                                        color: root.ink(0.68)
                                        font.pixelSize: 10
                                    }
                                }
                            }

                            Rectangle {
                                id: policyCard
                                width: parent.width
                                height: detail.app && detail.app.ruleKey
                                    ? (root.temporaryFor(detail.app) !== 0 ? 103 : 82) : 64
                                radius: 10
                                color: root.ink(0.045)

                                Column {
                                    anchors.fill: parent
                                    anchors.margins: 10
                                    spacing: 8
                                    Text {
                                        text: "Network access"
                                        color: root.textColor
                                        font.pixelSize: 12
                                        font.bold: true
                                    }
                                    Row {
                                        visible: detail.app && detail.app.ruleKey !== ""
                                        width: parent.width
                                        height: 32
                                        spacing: 8
                                        Repeater {
                                            model: [
                                                { label: "Allowed", action: "allow" },
                                                { label: "Blocked", action: "block" }
                                            ]
                                            delegate: Rectangle {
                                                required property var modelData
                                                width: (parent.width - 8) / 2
                                                height: parent.height
                                                radius: 8
                                                color: detail.app && detail.app.action === modelData.action
                                                    ? root.textColor : root.ink(0.07)
                                                Text {
                                                    anchors.centerIn: parent
                                                    text: modelData.label
                                                    color: detail.app && detail.app.action === modelData.action
                                                        ? root.inverseText : root.textColor
                                                    font.pixelSize: 11
                                                    font.bold: true
                                                }
                                                MouseArea {
                                                    anchors.fill: parent
                                                    enabled: !root.busy && detail.app
                                                        && detail.app.action !== modelData.action
                                                    cursorShape: Qt.PointingHandCursor
                                                    onClicked: root.setRule(detail.app.ruleKey, modelData.action)
                                                }
                                            }
                                        }
                                    }
                                    Text {
                                        visible: !detail.app || !detail.app.ruleKey
                                        width: parent.width
                                        text: "This launcher has no separate network process."
                                        color: root.ink(0.55)
                                        font.pixelSize: 10
                                        elide: Text.ElideRight
                                    }
                                    Row {
                                        visible: root.temporaryFor(detail.app) !== 0
                                        width: parent.width
                                        height: 16
                                        Text {
                                            width: parent.width - 55
                                            text: root.temporaryFor(detail.app) < 0
                                                ? "Temporary access · until daemon restart"
                                                : "Temporary access · " + Math.ceil(root.temporaryFor(detail.app) / 60) + " min left"
                                            color: root.accentColor
                                            font.pixelSize: 10
                                        }
                                        Text {
                                            text: "Revoke"
                                            color: root.dangerColor
                                            font.pixelSize: 10
                                            font.bold: true
                                            MouseArea {
                                                anchors.fill: parent
                                                cursorShape: Qt.PointingHandCursor
                                                onClicked: if (detail.app) root.runAction(["revoke", detail.app.ruleKey])
                                            }
                                        }
                                    }
                                }
                            }

                            Rectangle {
                                width: parent.width
                                height: 62
                                radius: 10
                                color: root.ink(0.045)
                                Column {
                                    anchors.fill: parent
                                    anchors.margins: 10
                                    spacing: 5
                                    Text { text: "Data use · this daemon session"; color: root.textColor; font.pixelSize: 11; font.bold: true }
                                    Text {
                                        text: "↑ " + root.formatBytes(root.trafficFor(detail.app).uploaded)
                                            + " uploaded      ↓ " + root.formatBytes(root.trafficFor(detail.app).downloaded) + " downloaded"
                                        color: root.ink(0.7)
                                        font.pixelSize: 11
                                    }
                                }
                            }

                            Rectangle {
                                width: parent.width
                                height: 92
                                radius: 10
                                color: root.ink(0.045)
                                Column {
                                    anchors.fill: parent
                                    anchors.margins: 9
                                    spacing: 4
                                    Text { text: "Personal details"; color: root.textColor; font.pixelSize: 11; font.bold: true }
                                    TextInput {
                                        id: tagInput
                                        width: parent.width
                                        height: 23
                                        text: root.annotation(detail.app, "tag")
                                        color: root.textColor
                                        font.pixelSize: 11
                                        selectByMouse: true
                                        clip: true
                                        onEditingFinished: root.updateAnnotation(detail.app, "tag", text)
                                        Text {
                                            visible: !tagInput.text && !tagInput.activeFocus
                                            text: "Tag · development, game, system…"
                                            color: root.ink(0.42)
                                            font.pixelSize: 11
                                        }
                                    }
                                    TextInput {
                                        id: noteInput
                                        width: parent.width
                                        height: 23
                                        text: root.annotation(detail.app, "note")
                                        color: root.textColor
                                        font.pixelSize: 11
                                        selectByMouse: true
                                        clip: true
                                        onEditingFinished: root.updateAnnotation(detail.app, "note", text)
                                        Text {
                                            visible: !noteInput.text && !noteInput.activeFocus
                                            text: "Add a note…"
                                            color: root.ink(0.42)
                                            font.pixelSize: 11
                                        }
                                    }
                                }
                            }

                            Row {
                                visible: !!detail.app && !!detail.app.ruleKey
                                width: parent.width
                                height: 34
                                spacing: 6
                                Repeater {
                                    model: [
                                        { label: "Allow once", args: ["allow-once"] },
                                        { label: "Allow 10 min", args: ["allow-for"] },
                                        { label: "Session", args: ["allow-session"] },
                                        { label: "Always allow", args: ["allow"] },
                                        { label: "Block", args: ["block"] }
                                    ]
                                    delegate: Rectangle {
                                        required property var modelData
                                        width: (parent.width - 24) / 5
                                        height: 34
                                        radius: 8
                                        color: tempMouse.containsMouse ? root.ink(0.13) : root.ink(0.065)
                                        Text { anchors.centerIn: parent; text: modelData.label; color: root.textColor; font.pixelSize: 10 }
                                        MouseArea {
                                            id: tempMouse
                                            anchors.fill: parent
                                            hoverEnabled: true
                                            cursorShape: Qt.PointingHandCursor
                                            enabled: !root.busy
                                            onClicked: if (detail.app) root.runAction(modelData.args.concat([detail.app.ruleKey],
                                                modelData.args[0] === "allow-for" ? ["600"] : []))
                                        }
                                    }
                                }
                            }

                            Rectangle {
                                width: parent.width
                                height: 73
                                radius: 10
                                color: root.ink(0.045)
                                Column {
                                    anchors.fill: parent
                                    anchors.margins: 8
                                    spacing: 4
                                    Row {
                                        width: parent.width
                                        height: 24
                                        spacing: 8
                                        TextInput {
                                            id: impactInput
                                            width: parent.width - 84
                                            height: 24
                                            color: root.textColor
                                            font.pixelSize: 11
                                            selectByMouse: true
                                            Text {
                                                visible: !impactInput.text && !impactInput.activeFocus
                                                text: "IP address to preview"
                                                color: root.ink(0.42)
                                                font.pixelSize: 11
                                            }
                                        }
                                        Rectangle {
                                            width: 76; height: 24; radius: 7
                                            color: impactMouse.containsMouse ? root.ink(0.16) : root.ink(0.09)
                                            Text { anchors.centerIn: parent; text: "Preview"; color: root.textColor; font.pixelSize: 10 }
                                            MouseArea { id: impactMouse; anchors.fill: parent; hoverEnabled: true; cursorShape: Qt.PointingHandCursor; onClicked: root.previewAddress(impactInput.text) }
                                        }
                                    }
                                    Text {
                                        width: parent.width
                                        text: root.previewText || "Shows apps that recently contacted this IP"
                                        color: root.ink(0.58)
                                        font.pixelSize: 10
                                        elide: Text.ElideRight
                                    }
                                }
                            }

                            Text {
                                width: parent.width
                                height: 18
                                text: "Recent connections"
                                color: root.textColor
                                font.pixelSize: 12
                                font.bold: true
                            }

                            Rectangle {
                                width: parent.width
                                height: 225
                                radius: 10
                                color: root.ink(0.025)
                                clip: true

                                ListView {
                                    id: connectionList
                                    anchors.fill: parent
                                    clip: true
                                    spacing: 2
                                    model: root.selectedRecentEvents()
                                    delegate: Rectangle {
                                        id: connectionRow
                                        required property var modelData
                                        width: connectionList.width
                                        height: 68
                                        radius: 8
                                        color: root.ink(0.035)
                                        Row {
                                            anchors.fill: parent
                                            anchors.margins: 10
                                            spacing: 8
                                            Column {
                                                width: parent.width - 124
                                                anchors.verticalCenter: parent.verticalCenter
                                                spacing: 4
                                                Text {
                                                    width: parent.width
                                                    text: connectionRow.modelData.hostname
                                                        || connectionRow.modelData.destination
                                                    textFormat: Text.PlainText
                                                    color: root.textColor
                                                    elide: Text.ElideMiddle
                                                    font.pixelSize: 11
                                                    font.bold: true
                                                }
                                                Text {
                                                    width: parent.width
                                                    text: (root.isLocalAddress(connectionRow.modelData.destination) ? "Local" : "Internet")
                                                        + " · " + connectionRow.modelData.destination + ":" + connectionRow.modelData.port
                                                        + " · " + connectionRow.modelData.protocol
                                                        + " · " + (connectionRow.modelData.verdict === "block" ? "Blocked" : "Allowed")
                                                    textFormat: Text.PlainText
                                                    color: root.ink(0.52)
                                                    elide: Text.ElideRight
                                                    font.pixelSize: 10
                                                }
                                            }
                                            Row {
                                                width: 116
                                                height: 26
                                                spacing: 4
                                                anchors.verticalCenter: parent.verticalCenter
                                                Repeater {
                                                    model: [
                                                        { label: "IP", value: connectionRow.modelData.destination },
                                                        { label: "PTR", value: connectionRow.modelData.hostname || "" },
                                                        { label: "Impact", value: connectionRow.modelData.destination }
                                                    ]
                                                    delegate: Rectangle {
                                                        required property var modelData
                                                        visible: modelData.value !== ""
                                                        width: modelData.label === "Impact" ? 40 : 34
                                                        height: 26
                                                        radius: 7
                                                        color: copyMouse.containsMouse
                                                            ? root.ink(0.14) : root.ink(0.07)
                                                        Text {
                                                            anchors.centerIn: parent
                                                            text: root.copiedValue === modelData.value
                                                                ? "✓" : modelData.label
                                                            color: root.textColor
                                                            font.pixelSize: 9
                                                        }
                                                        MouseArea {
                                                            id: copyMouse
                                                            anchors.fill: parent
                                                            hoverEnabled: true
                                                            cursorShape: Qt.PointingHandCursor
                                                            onClicked: {
                                                                if (modelData.label === "Impact") {
                                                                    impactInput.text = modelData.value
                                                                    root.previewAddress(modelData.value)
                                                                    detail.contentY = 0
                                                                } else root.copyText(modelData.value)
                                                            }
                                                        }
                                                    }
                                                }
                                            }
                                        }
                                    }
                                }
                                Text {
                                    visible: connectionList.count === 0
                                    anchors.centerIn: parent
                                    text: "No connections recorded"
                                    color: root.ink(0.5)
                                    font.pixelSize: 12
                                }
                            }
                            }
                        }

                        Column {
                            visible: root.settingsOpen
                            anchors.fill: parent
                            spacing: 12
                            Rectangle {
                                width: parent.width
                                height: 118
                                radius: 10
                                color: root.ink(0.045)
                                Column {
                                    anchors.fill: parent
                                    anchors.margins: 12
                                    spacing: 10
                                    Text { text: "Rule profile"; color: root.textColor; font.pixelSize: 13; font.bold: true }
                                    Text { text: "Active: " + root.profileInfo.active; color: root.ink(0.58); font.pixelSize: 10 }
                                    Row {
                                        width: parent.width
                                        height: 32
                                        spacing: 6
                                        Repeater {
                                            model: root.profileInfo.names
                                            delegate: Rectangle {
                                                required property string modelData
                                                width: (parent.width - 12) / Math.max(1, root.profileInfo.names.length)
                                                height: 32
                                                radius: 8
                                                color: root.profileInfo.active === modelData ? root.textColor : root.ink(0.08)
                                                Text { anchors.centerIn: parent; text: modelData; color: root.profileInfo.active === modelData ? root.inverseText : root.textColor; font.pixelSize: 10; font.bold: true }
                                                MouseArea { anchors.fill: parent; enabled: !root.busy; cursorShape: Qt.PointingHandCursor; onClicked: root.runAction(["profile", modelData]) }
                                            }
                                        }
                                    }
                                }
                            }
                            Repeater {
                                model: [
                                    { key: "hideLocal", title: "Hide local connections", detail: "Remove localhost and private network attempts from lists" },
                                    { key: "unknownAlerts", title: "New process alerts", detail: "Mark newly seen services with a yellow badge" },
                                    { key: "prompt", title: "Ask on first internet attempt", detail: "Pause new apps; they may need to retry after approval" }
                                ]
                                delegate: Rectangle {
                                    required property var modelData
                                    width: parent.width
                                    height: 68
                                    radius: 10
                                    color: root.ink(0.045)
                                    Row {
                                        anchors.fill: parent
                                        anchors.margins: 12
                                        spacing: 10
                                        Column {
                                            width: parent.width - 50
                                            anchors.verticalCenter: parent.verticalCenter
                                            spacing: 4
                                            Text { text: modelData.title; color: root.textColor; font.pixelSize: 12; font.bold: true }
                                            Text { width: parent.width; text: modelData.detail; color: root.ink(0.52); font.pixelSize: 10; elide: Text.ElideRight }
                                        }
                                        Rectangle {
                                            readonly property bool checked: modelData.key === "hideLocal" ? root.hideLocal
                                                : modelData.key === "unknownAlerts" ? root.unknownAlerts : root.promptStatus.enabled
                                            width: 36; height: 22; radius: 11
                                            anchors.verticalCenter: parent.verticalCenter
                                            color: checked ? root.textColor : root.ink(0.16)
                                            Rectangle { width: 16; height: 16; radius: 8; anchors.verticalCenter: parent.verticalCenter; x: parent.checked ? parent.width - width - 3 : 3; color: parent.checked ? root.inverseText : root.textColor }
                                            MouseArea { anchors.fill: parent; cursorShape: Qt.PointingHandCursor; onClicked: {
                                                if (modelData.key === "hideLocal") root.hideLocal = !root.hideLocal
                                                else if (modelData.key === "unknownAlerts") root.unknownAlerts = !root.unknownAlerts
                                                else if (root.currentUid > 0) root.runAction([root.promptStatus.enabled ? "prompt-off" : "prompt-on", String(root.currentUid)])
                                            } }
                                        }
                                    }
                                }
                            }
                            Rectangle {
                                width: parent.width
                                height: 68
                                radius: 10
                                color: root.ink(0.045)
                                Row {
                                    anchors.fill: parent
                                    anchors.margins: 12
                                    spacing: 10
                                    Column {
                                        width: parent.width - 50
                                        anchors.verticalCenter: parent.verticalCenter
                                        spacing: 4
                                        Text {
                                            text: "Blocked app count"
                                            color: root.textColor
                                            font.pixelSize: 12
                                            font.bold: true
                                        }
                                        Text {
                                            text: "Show the count next to the bar icon"
                                            color: root.ink(0.52)
                                            font.pixelSize: 10
                                        }
                                    }
                                    Rectangle {
                                        width: 36
                                        height: 22
                                        radius: 11
                                        anchors.verticalCenter: parent.verticalCenter
                                        color: root.blockedCountVisible() ? root.textColor : root.ink(0.16)
                                        Rectangle {
                                            width: 16
                                            height: 16
                                            radius: 8
                                            anchors.verticalCenter: parent.verticalCenter
                                            x: root.blockedCountVisible() ? parent.width - width - 3 : 3
                                            color: root.blockedCountVisible() ? root.inverseText : root.textColor
                                        }
                                        MouseArea {
                                            anchors.fill: parent
                                            cursorShape: Qt.PointingHandCursor
                                            onClicked: root.toggleBlockedCount()
                                        }
                                    }
                                }
                            }
                        }

                        Rectangle {
                            visible: root.actionError !== ""
                            width: parent.width
                            height: 36
                            radius: 8
                            anchors.bottom: parent.bottom
                            color: Qt.rgba(0.82, 0.28, 0.28, 0.88)
                            Text {
                                anchors.fill: parent
                                anchors.margins: 8
                                text: root.actionError
                                color: "white"
                                font.pixelSize: 11
                                elide: Text.ElideRight
                                verticalAlignment: Text.AlignVCenter
                            }
                        }
                    }
                }
            }
        }
    }
}
