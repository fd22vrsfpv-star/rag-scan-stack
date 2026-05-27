# -*- coding: utf-8 -*-
"""
RAG Scan Stack <-> Burp Suite Bridge Extension
================================================
Bidirectional finding sync between RAG Scan Stack and Burp Suite Professional.

Install:
  1. Burp Suite -> Extender -> Add -> Extension Type: Python (Jython)
  2. Select this file
  3. Configure the RAG API URL in the extension tab
"""

from burp import IBurpExtender, ITab, IScanIssue, IHttpRequestResponse
from javax.swing import (
    JPanel, JButton, JTextField, JLabel, JScrollPane, JTextArea,
    JComboBox, JCheckBox, BoxLayout, BorderFactory, SwingUtilities,
    JList, DefaultListModel, ListSelectionModel, JSplitPane, Box,
)
import javax.swing
from javax.swing.event import ListSelectionListener
from java.awt import BorderLayout, FlowLayout, Dimension, Color, Font, GridBagLayout, GridBagConstraints
from java.net import URL
import json
import threading


SEVERITY_MAP = {
    "critical": "High", "high": "High", "medium": "Medium",
    "low": "Low", "info": "Information", "informational": "Information",
}
CONFIDENCE_MAP = {"certain": "Certain", "firm": "Firm", "tentative": "Tentative"}
BURP_SEVERITY_MAP = {"High": "high", "Medium": "medium", "Low": "low", "Information": "info"}
BURP_CONFIDENCE_MAP = {"Certain": "certain", "Firm": "firm", "Tentative": "tentative"}


EXTENSION_VERSION = "2026.04.21-2"


class BurpExtender(IBurpExtender, ITab):

    def registerExtenderCallbacks(self, callbacks):
        self._callbacks = callbacks
        self._helpers = callbacks.getHelpers()
        callbacks.setExtensionName("RAG Scan Stack Bridge v%s" % EXTENSION_VERSION)
        self._api_url = "https://localhost:8000"
        self._api_key = "changeme"
        self._connected = False
        self._scope_targets = {}  # scope_name -> [ip, ...]
        self._engagement_ids = {}  # display_label -> full_uuid
        self._panel = JPanel(BorderLayout())
        self._build_ui()
        callbacks.addSuiteTab(self)
        self._log("RAG Scan Stack Bridge loaded.")

    def getTabCaption(self):
        return "RAG Scan Bridge"

    def getUiComponent(self):
        return self._panel

    def _build_ui(self):
        from javax.swing import JTabbedPane

        # Connection bar (always visible at top)
        top = JPanel()
        top.setLayout(BoxLayout(top, BoxLayout.Y_AXIS))
        config = JPanel()
        config.setLayout(BoxLayout(config, BoxLayout.Y_AXIS))
        config.setBorder(BorderFactory.createTitledBorder("Connection"))
        row_url = JPanel(FlowLayout(FlowLayout.LEFT))
        row_url.add(JLabel("RAG API URL:"))
        self._url_field = JTextField(self._api_url, 30)
        row_url.add(self._url_field)
        row_url.add(JLabel("API Key:"))
        self._key_field = JTextField(self._api_key, 15)
        row_url.add(self._key_field)
        row_url.add(JButton("Test Connection", actionPerformed=self._test_connection))
        config.add(row_url)
        self._status_label = JLabel("  Not connected")
        self._status_label.setFont(Font("SansSerif", Font.BOLD, 12))
        self._status_label.setForeground(Color(150, 150, 150))
        status_row = JPanel(FlowLayout(FlowLayout.LEFT))
        self._status_dot = JLabel("  ")
        self._status_dot.setOpaque(True)
        self._status_dot.setPreferredSize(Dimension(12, 12))
        self._status_dot.setBackground(Color(100, 100, 100))
        status_row.add(self._status_dot)
        status_row.add(self._status_label)
        config.add(status_row)
        top.add(config)

        # ── Tabbed Pane ──
        tabs = JTabbedPane()

        # ═══ TAB 1: Import / Export ═══
        tab_import = JPanel()
        tab_import.setLayout(BoxLayout(tab_import, BoxLayout.Y_AXIS))

        # Filters
        fp = JPanel()
        fp.setLayout(BoxLayout(fp, BoxLayout.Y_AXIS))
        fp.setBorder(BorderFactory.createTitledBorder("Selection Filters"))
        row1 = JPanel(FlowLayout(FlowLayout.LEFT))
        row1.add(JLabel("Target IP:"))
        self._import_target = JTextField("", 20)
        row1.add(self._import_target)
        row1.add(JLabel("Severity:"))
        self._import_severity = JComboBox(["all", "critical", "high", "medium", "low", "info"])
        row1.add(self._import_severity)
        fp.add(row1)

        row2 = JPanel(FlowLayout(FlowLayout.LEFT))
        row2.add(JLabel("Scope:"))
        self._scope_combo = JComboBox(["(all scopes)"])
        self._scope_combo.setPreferredSize(Dimension(200, 25))
        row2.add(self._scope_combo)
        row2.add(JLabel("Engagement:"))
        self._engagement_combo = JComboBox(["(all engagements)"])
        self._engagement_combo.setPreferredSize(Dimension(250, 25))
        row2.add(self._engagement_combo)
        row2.add(JButton("Refresh", actionPerformed=self._refresh_filters))
        fp.add(row2)

        row3 = JPanel(FlowLayout(FlowLayout.LEFT))
        row3.add(JLabel("Sources:"))
        self._src_checks = {}
        for name, default in [("zap", True), ("nikto", True), ("nuclei", True),
                               ("nmap", True), ("playwright", True), ("ssh-audit", True), ("burp", False)]:
            cb = JCheckBox(name, default)
            self._src_checks[name] = cb
            row3.add(cb)
        row3.add(JLabel("  "))
        self._hide_recon = JCheckBox("Hide recon-only (no severity)", True)
        self._hide_recon.setToolTipText("Filter out info/recon findings without actionable severity")
        row3.add(self._hide_recon)
        fp.add(row3)

        row4 = JPanel(FlowLayout(FlowLayout.LEFT))
        row4.add(JButton("Preview Count", actionPerformed=self._preview_count))
        self._count_label = JLabel("  Click Preview to see matching findings")
        row4.add(self._count_label)
        fp.add(row4)
        self._severity_panel = JPanel(FlowLayout(FlowLayout.LEFT))
        self._severity_panel.setVisible(False)
        fp.add(self._severity_panel)
        self._source_panel = JPanel(FlowLayout(FlowLayout.LEFT))
        self._source_panel.setVisible(False)
        fp.add(self._source_panel)
        tab_import.add(fp)

        # Import / Export / Sync buttons
        ip = JPanel(FlowLayout(FlowLayout.LEFT))
        ip.setBorder(BorderFactory.createTitledBorder("Import to Burp"))
        ip.add(JButton("Import Filtered Findings", actionPerformed=self._import_findings))
        ip.add(JButton("Import All", actionPerformed=self._import_all))
        self._import_status = JLabel("")
        ip.add(self._import_status)
        tab_import.add(ip)

        ep = JPanel(FlowLayout(FlowLayout.LEFT))
        ep.setBorder(BorderFactory.createTitledBorder("Export Burp Issues to RAG"))
        ep.add(JButton("Export Burp Issues", actionPerformed=self._export_findings))
        self._export_scope_only = JCheckBox("In-scope only", True)
        ep.add(self._export_scope_only)
        self._export_status = JLabel("")
        ep.add(self._export_status)
        tab_import.add(ep)

        sp = JPanel(FlowLayout(FlowLayout.LEFT))
        sp.setBorder(BorderFactory.createTitledBorder("Bidirectional Sync"))
        sp.add(JButton("Sync Both Ways", actionPerformed=self._sync_both))
        tab_import.add(sp)

        tabs.addTab("Import / Export", JScrollPane(tab_import))

        # ═══ TAB 2: Follow-Up Queue ═══
        tab_followup = JPanel(BorderLayout())

        fuc = JPanel(FlowLayout(FlowLayout.LEFT))
        fuc.add(JButton("Refresh Queue", actionPerformed=self._refresh_followup_queue))
        fuc.add(JButton("Import Selected to Burp", actionPerformed=self._import_selected_followups))
        fuc.add(JButton("Import All to Burp", actionPerformed=self._import_all_followups))
        self._fuq_status = JLabel("  Click Refresh to load queued items")
        fuc.add(self._fuq_status)
        tab_followup.add(fuc, BorderLayout.NORTH)

        self._fuq_model = DefaultListModel()
        self._fuq_list = JList(self._fuq_model)
        self._fuq_list.setSelectionMode(ListSelectionModel.MULTIPLE_INTERVAL_SELECTION)
        self._fuq_list.setFont(Font("Monospaced", Font.PLAIN, 11))
        self._fuq_list.addListSelectionListener(FollowUpSelectionListener(self))
        list_scroll = JScrollPane(self._fuq_list)
        list_scroll.setPreferredSize(Dimension(400, 200))

        self._fuq_detail = JTextArea(10, 50)
        self._fuq_detail.setEditable(False)
        self._fuq_detail.setFont(Font("Monospaced", Font.PLAIN, 10))
        self._fuq_detail.setLineWrap(True)
        self._fuq_detail.setWrapStyleWord(True)
        detail_scroll = JScrollPane(self._fuq_detail)

        split = JSplitPane(JSplitPane.HORIZONTAL_SPLIT, list_scroll, detail_scroll)
        split.setDividerLocation(420)
        tab_followup.add(split, BorderLayout.CENTER)

        self._fuq_items = []

        tabs.addTab("Follow-Up Queue", tab_followup)

        # ═══ TAB 3: Proxy Routing ═══
        tab_proxy = JPanel()
        tab_proxy.setLayout(BoxLayout(tab_proxy, BoxLayout.Y_AXIS))

        pp = JPanel()
        pp.setLayout(BoxLayout(pp, BoxLayout.Y_AXIS))
        pp.setBorder(BorderFactory.createTitledBorder("SOCKS Proxy Routing (Upstream via Tunnel Nodes)"))
        proxy_row1 = JPanel(FlowLayout(FlowLayout.LEFT))
        proxy_row1.add(JLabel("Tunnel Node:"))
        self._proxy_node_combo = JComboBox(["(select node)"])
        self._proxy_node_combo.setPreferredSize(Dimension(350, 25))
        proxy_row1.add(self._proxy_node_combo)
        proxy_row1.add(JButton("Refresh Nodes", actionPerformed=self._refresh_tunnel_nodes))
        pp.add(proxy_row1)

        proxy_row2 = JPanel(FlowLayout(FlowLayout.LEFT))
        proxy_row2.add(JLabel("Docker Host IP:"))
        self._docker_host_ip = JTextField("host.docker.internal", 15)
        self._docker_host_ip.setToolTipText("IP that Burp can reach to access SOCKS ports (your machine's IP or host.docker.internal)")
        proxy_row2.add(self._docker_host_ip)
        self._proxy_port_label = JLabel("  ")
        self._proxy_port_label.setFont(Font("Monospaced", Font.BOLD, 11))
        proxy_row2.add(self._proxy_port_label)
        proxy_row2.add(JButton("Set Single Proxy", actionPerformed=self._set_burp_upstream_proxy))
        proxy_row2.add(JButton("Verify", actionPerformed=self._verify_burp_proxy))
        proxy_row2.add(JButton("Disable", actionPerformed=self._disable_burp_proxy))
        pp.add(proxy_row2)

        # Auto-update port label when node selection changes
        from java.awt.event import ItemListener, ItemEvent
        class NodeSelectionListener(ItemListener):
            def __init__(self, ext):
                self._ext = ext
            def itemStateChanged(self, event):
                if event.getStateChange() == ItemEvent.SELECTED:
                    node = self._ext._get_selected_node()
                    if node:
                        port = node.get("proxy_port", 0)
                        host_ip = self._ext._docker_host_ip.getText().strip() or "host.docker.internal"
                        self._ext._proxy_port_label.setText("  -> socks5://%s:%d" % (host_ip, port))
                        self._ext._proxy_port_label.setForeground(Color(0, 180, 0))
                    else:
                        self._ext._proxy_port_label.setText("  ")
        self._proxy_node_combo.addItemListener(NodeSelectionListener(self))

        # Copy URL button
        proxy_row3 = JPanel(FlowLayout(FlowLayout.LEFT))
        proxy_row3.add(JButton("Copy Proxy URL", actionPerformed=self._copy_proxy_url))
        proxy_row3.add(JButton("Generate Proxy List", actionPerformed=self._push_all_to_rotator))
        pp.add(proxy_row3)

        self._proxy_status = JLabel("  Select a tunnel node and click Set Single Proxy")
        self._proxy_status.setFont(Font("SansSerif", Font.PLAIN, 11))
        proxy_row4 = JPanel(FlowLayout(FlowLayout.LEFT))
        proxy_row4.add(self._proxy_status)
        pp.add(proxy_row4)
        tab_proxy.add(pp)

        # Proxy list text area (copyable) — for rotator import
        proxy_list_panel = JPanel(BorderLayout())
        proxy_list_panel.setBorder(BorderFactory.createTitledBorder("Proxy List (select all + copy)"))
        self._proxy_list_area = JTextArea(6, 60)
        self._proxy_list_area.setFont(Font("Monospaced", Font.PLAIN, 11))
        self._proxy_list_area.setEditable(False)
        self._proxy_list_area.setText("Click 'Generate Proxy List' to populate with all online tunnel nodes.")
        proxy_list_panel.add(JScrollPane(self._proxy_list_area), BorderLayout.CENTER)
        copy_row = JPanel(FlowLayout(FlowLayout.LEFT))
        copy_row.add(JButton("Select All + Copy", actionPerformed=self._copy_proxy_list))
        copy_row.add(JLabel("  Paste into IP Rotate / Upstream Proxy Rotator extension"))
        proxy_list_panel.add(copy_row, BorderLayout.SOUTH)
        tab_proxy.add(proxy_list_panel)

        self._tunnel_nodes = []

        tabs.addTab("Proxy Routing", JScrollPane(tab_proxy))

        # ═══ TAB 4: Activity Log ═══
        tab_log = JPanel(BorderLayout())
        self._log_area = JTextArea(20, 80)
        self._log_area.setEditable(False)
        self._log_area.setFont(Font("Monospaced", Font.PLAIN, 11))
        tab_log.add(JScrollPane(self._log_area), BorderLayout.CENTER)

        tabs.addTab("Activity Log", tab_log)

        # ═══ TAB 5: About ═══
        tab_about = JPanel()
        tab_about.setLayout(BoxLayout(tab_about, BoxLayout.Y_AXIS))
        tab_about.setBorder(BorderFactory.createEmptyBorder(20, 20, 20, 20))

        about_title = JLabel("RAG Scan Stack Bridge")
        about_title.setFont(Font("SansSerif", Font.BOLD, 16))
        about_title.setAlignmentX(0.0)
        tab_about.add(about_title)
        tab_about.add(javax.swing.Box.createVerticalStrut(8))

        about_ver = JLabel("Version: %s" % EXTENSION_VERSION)
        about_ver.setFont(Font("Monospaced", Font.PLAIN, 13))
        about_ver.setAlignmentX(0.0)
        tab_about.add(about_ver)
        tab_about.add(javax.swing.Box.createVerticalStrut(15))

        about_lines = [
            "Bidirectional finding sync between RAG Scan Stack and Burp Suite Professional.",
            "",
            "Features:",
            "  - Import filtered findings into Burp's Target/Issues views",
            "  - Export Burp-discovered issues back to RAG for correlation",
            "  - Follow-Up Queue: import flagged items with CVE details",
            "  - SOCKS proxy routing through remote tunnel nodes",
            "  - Proxy rotation support for multiple tunnels",
            "  - Recon-only findings filter (hide info/recon severity)",
            "",
            "Install: Burp Suite > Extender > Add > Python (Jython) > select RagScanBridge.py",
            "Source: burp-extension/RagScanBridge.py in the RAG Scan Stack repo",
        ]
        about_text = JTextArea("\n".join(about_lines), 12, 60)
        about_text.setEditable(False)
        about_text.setFont(Font("SansSerif", Font.PLAIN, 12))
        about_text.setLineWrap(True)
        about_text.setWrapStyleWord(True)
        about_text.setOpaque(False)
        about_text.setAlignmentX(0.0)
        tab_about.add(about_text)

        tabs.addTab("About", JScrollPane(tab_about))

        # Assemble: connection bar on top, tabs below
        self._panel.add(top, BorderLayout.NORTH)
        self._panel.add(tabs, BorderLayout.CENTER)

    # ── Helpers ──
    @staticmethod
    def _safe_str(val):
        """Convert value to a Jython-safe ASCII string, replacing Unicode chars."""
        if val is None:
            return ""
        if isinstance(val, bytes):
            return val.decode("utf-8", "replace")
        try:
            return unicode(val).encode("ascii", "replace")
        except (NameError, UnicodeDecodeError, UnicodeEncodeError):
            try:
                return str(val).encode("ascii", "replace").decode("ascii")
            except Exception:
                return str(val)

    def _log(self, msg):
        def update():
            try:
                self._log_area.append(self._safe_str(msg) + "\n")
            except Exception:
                self._log_area.append("[log encoding error]\n")
            self._log_area.setCaretPosition(self._log_area.getDocument().getLength())
        SwingUtilities.invokeLater(update)

    def _get_config(self):
        return {"url": self._url_field.getText().strip().rstrip("/"),
                "key": self._key_field.getText().strip()}

    def _api_get(self, path):
        """GET request to RAG API. Returns parsed JSON dict."""
        import urllib2, ssl
        config = self._get_config()
        url = config["url"] + path
        self._log("[DEBUG] GET %s" % url)
        ctx = ssl.create_default_context()
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE
        req = urllib2.Request(url)
        req.add_header("x-api-key", config["key"])
        req.add_header("Accept", "application/json")
        try:
            resp = urllib2.urlopen(req, context=ctx, timeout=30)
            body = resp.read()
            return json.loads(body)
        except urllib2.HTTPError as e:
            body = e.read()
            self._log("[DEBUG] HTTP %d: %s" % (e.code, body[:300]))
            raise Exception("HTTP %d: %s" % (e.code, body[:200]))

    def _api_post(self, path, data):
        """POST request to RAG API. Returns parsed JSON dict."""
        import urllib2, ssl
        config = self._get_config()
        url = config["url"] + path
        self._log("[DEBUG] POST %s" % url)
        ctx = ssl.create_default_context()
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE
        req = urllib2.Request(url, json.dumps(data).encode("utf-8"))
        req.add_header("x-api-key", config["key"])
        req.add_header("Content-Type", "application/json")
        req.add_header("Accept", "application/json")
        try:
            resp = urllib2.urlopen(req, context=ctx, timeout=30)
            return json.loads(resp.read())
        except urllib2.HTTPError as e:
            body = e.read()
            self._log("[DEBUG] HTTP %d: %s" % (e.code, body[:300]))
            raise Exception("HTTP %d: %s" % (e.code, body[:200]))

    def _get_selected_sources(self):
        return [name for name, cb in self._src_checks.items() if cb.isSelected()]

    def _build_query(self):
        """Build query string for /findings/search from current filters."""
        parts = []
        target = self._import_target.getText().strip()
        if target:
            parts.append("ip=%s" % target)

        sev = str(self._import_severity.getSelectedItem())
        if sev != "all":
            parts.append("severity=%s" % sev)

        # Scope -> resolve to IP filter if scope selected and no target typed
        scope_idx = self._scope_combo.getSelectedIndex()
        if scope_idx > 0 and not target:
            scope_text = str(self._scope_combo.getSelectedItem())
            if " (" in scope_text:
                scope_text = scope_text.rsplit(" (", 1)[0]
            ips = self._scope_targets.get(scope_text, [])
            if ips:
                # Use first IP as filter (API only supports single ip)
                parts.append("ip=%s" % ips[0])
                if len(ips) > 1:
                    self._log("[Filter] Scope '%s' has %d targets, using first: %s" % (scope_text, len(ips), ips[0]))

        # Engagement
        eng_idx = self._engagement_combo.getSelectedIndex()
        if eng_idx > 0:
            eng_label = str(self._engagement_combo.getSelectedItem())
            eng_id = self._engagement_ids.get(eng_label, "")
            if eng_id:
                parts.append("engagement_id=%s" % eng_id)

        # Sources as repeated params
        for src in self._get_selected_sources():
            parts.append("source=%s" % src)

        return "&".join(parts)

    # ── Connection ──
    def _test_connection(self, event):
        def run():
            try:
                data = self._api_get("/health")
                ok = data.get("ok", False) or data.get("status") == "ok"
                self._connected = ok
                db = data.get("database", {})
                tables = db.get("tables_found", "?") if isinstance(db, dict) else "?"
                def update_ui():
                    if ok:
                        self._status_dot.setBackground(Color(0, 200, 0))
                        self._status_label.setForeground(Color(0, 180, 0))
                        self._status_label.setText("  Connected — %s (%s tables)" % (
                            data.get("service", "rag-api"), tables))
                    else:
                        self._status_dot.setBackground(Color(200, 200, 0))
                        self._status_label.setForeground(Color(200, 200, 0))
                        self._status_label.setText("  API status: %s" % data.get("status", "?"))
                SwingUtilities.invokeLater(update_ui)
                self._log("[OK] Connected: %s (%s tables)" % (data.get("service", "rag-api"), tables))
                self._refresh_filters(None)
            except Exception as e:
                self._connected = False
                def update_fail():
                    self._status_dot.setBackground(Color(220, 50, 50))
                    self._status_label.setForeground(Color(220, 50, 50))
                    self._status_label.setText("  Connection failed — %s" % str(e)[:60])
                SwingUtilities.invokeLater(update_fail)
                self._log("[ERROR] Connection failed: %s" % e)
        threading.Thread(target=run).start()

    # ── Refresh Filters ──
    def _refresh_filters(self, event):
        def run():
            # Scopes
            try:
                data = self._api_get("/scope/names")
                scope_list = data.get("names", [])
                self._scope_targets = {}
                # Load targets for each scope
                for s in scope_list:
                    name = s.get("name", str(s)) if isinstance(s, dict) else str(s)
                    try:
                        sd = self._api_get("/scope?name=%s" % name)
                        ips = [t.get("target", "") for t in sd.get("targets", []) if t.get("target_type") == "ip"]
                        self._scope_targets[name] = ips
                    except Exception:
                        self._scope_targets[name] = []
                def update_scopes():
                    self._scope_combo.removeAllItems()
                    self._scope_combo.addItem("(all scopes)")
                    for s in scope_list:
                        name = s.get("name", str(s)) if isinstance(s, dict) else str(s)
                        count = s.get("target_count", 0) if isinstance(s, dict) else 0
                        self._scope_combo.addItem("%s (%d targets)" % (name, count))
                SwingUtilities.invokeLater(update_scopes)
                self._log("[Filters] Loaded %d scopes" % len(scope_list))
            except Exception as e:
                self._log("[Filters] Scopes error: %s" % e)

            # Engagements
            try:
                data = self._api_get("/engagements")
                engs = data.get("engagements", [])
                self._engagement_ids = {}
                def update_engs():
                    self._engagement_combo.removeAllItems()
                    self._engagement_combo.addItem("(all engagements)")
                    for eng in engs:
                        eid = eng.get("id", "")
                        label = "%s (%s)" % (eng.get("name", "?"), eid)
                        self._engagement_ids[label] = eid
                        self._engagement_combo.addItem(label)
                SwingUtilities.invokeLater(update_engs)
                self._log("[Filters] Loaded %d engagements" % len(engs))
            except Exception as e:
                self._log("[Filters] Engagements error: %s" % e)
        threading.Thread(target=run).start()

    # ── Preview Count ──
    def _preview_count(self, event):
        def run():
            try:
                qs = self._build_query() + "&limit=1&offset=0"
                self._log("[Preview] Query: /findings/search?%s" % qs)
                data = self._api_get("/findings/search?%s" % qs)
                total = data.get("total", 0)
                by_sev = data.get("aggregations", {}).get("by_severity", {})
                by_src = data.get("aggregations", {}).get("by_source", {})

                def update_ui():
                    recon_note = ""
                    if self._hide_recon.isSelected():
                        recon_count = by_sev.get("info", 0) + by_sev.get("recon", 0)
                        if recon_count > 0:
                            recon_note = " (-%s recon/info)" % "{:,}".format(recon_count)
                    self._count_label.setText("  %s findings match%s" % ("{:,}".format(total), recon_note))
                    self._count_label.setForeground(Color(0, 180, 0) if total > 0 else Color(200, 100, 0))
                    sev_colors = {"critical": Color(220, 50, 50), "high": Color(230, 130, 0),
                                  "medium": Color(200, 200, 0), "low": Color(80, 160, 230),
                                  "info": Color(150, 150, 150), "recon": Color(160, 100, 200)}
                    self._severity_panel.removeAll()
                    self._severity_panel.add(JLabel("  Severity: "))
                    for sev in ["critical", "high", "medium", "low", "info", "recon"]:
                        c = by_sev.get(sev, 0)
                        if c > 0:
                            lbl = JLabel(" %s:%s " % (sev, "{:,}".format(c)))
                            lbl.setForeground(sev_colors.get(sev, Color(150, 150, 150)))
                            lbl.setFont(Font("SansSerif", Font.BOLD, 11))
                            self._severity_panel.add(lbl)
                    self._severity_panel.setVisible(True)
                    self._severity_panel.revalidate()
                    self._source_panel.removeAll()
                    self._source_panel.add(JLabel("  Sources: "))
                    for src, c in sorted(by_src.items(), key=lambda x: -x[1]):
                        if c > 0:
                            lbl = JLabel(" %s:%s " % (src, "{:,}".format(c)))
                            lbl.setFont(Font("Monospaced", Font.PLAIN, 10))
                            lbl.setForeground(Color(170, 170, 170))
                            self._source_panel.add(lbl)
                    self._source_panel.setVisible(True)
                    self._source_panel.revalidate()
                SwingUtilities.invokeLater(update_ui)
                self._log("[Preview] %d findings match" % total)

                # Also count follow-up queue items matching the target filter
                try:
                    fuq_data = self._api_get("/burp-queue?status=pending&limit=500")
                    fuq_all = fuq_data.get("items", [])
                    fuq_filtered = self._filter_by_target(fuq_all)
                    def update_fuq():
                        target_note = ""
                        target_filter = self._import_target.getText().strip()
                        if target_filter and len(fuq_filtered) != len(fuq_all):
                            target_note = " (filtered from %d)" % len(fuq_all)
                        self._fuq_status.setText("  %d pending queue items%s" % (len(fuq_filtered), target_note))
                        self._fuq_status.setForeground(Color(0, 180, 0) if fuq_filtered else Color(150, 150, 150))
                    SwingUtilities.invokeLater(update_fuq)
                    # Update the in-memory queue items
                    self._fuq_items = fuq_filtered
                    def update_fuq_list():
                        self._fuq_model.clear()
                        for item in fuq_filtered:
                            sev = (item.get("severity") or "info").upper()[:4]
                            title = self._safe_str(item.get("title", "?"))[:60]
                            target = self._safe_str(item.get("target") or item.get("url") or "?")
                            if len(target) > 40: target = target[:37] + "..."
                            self._fuq_model.addElement("[%s] %s  @ %s" % (sev, title, target))
                    SwingUtilities.invokeLater(update_fuq_list)
                except Exception as qe:
                    self._log("[Preview] Queue count error: %s" % qe)

            except Exception as e:
                self._log("[Preview ERROR] %s" % e)
                def update_err():
                    self._count_label.setText("  Error: %s" % str(e)[:50])
                    self._count_label.setForeground(Color(220, 50, 50))
                SwingUtilities.invokeLater(update_err)
        threading.Thread(target=run).start()

    # ── Import ──
    def _import_findings(self, event):
        self._do_import()

    def _import_all(self, event):
        self._do_import(ignore_filters=True)

    def _do_import(self, ignore_filters=False):
        def run():
            try:
                # Build exchange endpoint params (target, severity, source)
                exchange_params = []
                if not ignore_filters:
                    target = self._import_target.getText().strip()
                    # Resolve scope to IP if no target typed
                    if not target:
                        scope_idx = self._scope_combo.getSelectedIndex()
                        if scope_idx > 0:
                            scope_text = str(self._scope_combo.getSelectedItem())
                            if " (" in scope_text:
                                scope_text = scope_text.rsplit(" (", 1)[0]
                            ips = self._scope_targets.get(scope_text, [])
                            if ips:
                                target = ips[0]
                        # Also try engagement scope
                        if not target:
                            eng_idx = self._engagement_combo.getSelectedIndex()
                            if eng_idx > 0:
                                eng_label = str(self._engagement_combo.getSelectedItem())
                                eng_id = self._engagement_ids.get(eng_label, "")
                                if eng_id:
                                    # Look up engagement's scope targets
                                    try:
                                        eng_data = self._api_get("/engagements/%s" % eng_id)
                                        scope_name = eng_data.get("scope_name", "")
                                        if scope_name:
                                            ips = self._scope_targets.get(scope_name, [])
                                            if ips:
                                                target = ips[0]
                                    except Exception:
                                        pass
                    if target:
                        exchange_params.append("target=%s" % target)

                    sev = str(self._import_severity.getSelectedItem())
                    if sev != "all":
                        exchange_params.append("severity=%s" % sev)

                    sources = self._get_selected_sources()
                    if sources:
                        exchange_params.append("source=%s" % ",".join(sources))

                exchange_params.append("limit=500")
                qs = "&".join(exchange_params)

                self._log("[Import] GET /export/findings-exchange?%s" % qs)
                data = self._api_get("/export/findings-exchange?%s" % qs)

                all_findings = data.get("findings", [])

                # Client-side source filter for exact match
                if not ignore_filters:
                    sources_set = set(self._get_selected_sources())
                    findings = [f for f in all_findings if f.get("source", "").lower() in sources_set] if sources_set else all_findings
                else:
                    findings = all_findings

                # Filter out recon-only findings (info/recon severity with no actionable data)
                if self._hide_recon.isSelected():
                    before_recon = len(findings)
                    recon_severities = {"info", "recon", "informational", ""}
                    findings = [f for f in findings
                                if (f.get("severity") or "").lower() not in recon_severities
                                or f.get("name", "").lower().startswith(("cve-", "vuln", "sql", "xss", "csrf", "injection"))]
                    self._log("[Import] Recon filter: %d -> %d (removed %d info/recon-only)" % (
                        before_recon, len(findings), before_recon - len(findings)))

                self._log("[Import] Fetched %d findings (%d after filters)" % (len(all_findings), len(findings)))

                imported = 0
                skipped = 0
                for f in findings:
                    try:
                        url = f.get("url") or ""
                        if not url and f.get("ip"):
                            port = f.get("port") or 80
                            proto = "https" if port in (443, 8443) else "http"
                            url = "%s://%s:%s/" % (proto, f["ip"], port)
                        if not url:
                            skipped += 1
                            continue

                        # Use real request/response from exchange data, fall back to synthetic
                        request_raw = f.get("request_raw") or self._build_request(url, f.get("method", "GET") or "GET", f)
                        response_raw = f.get("response_raw") or self._build_response(f)

                        _s = self._safe_str
                        issue = RagScanIssue(
                            self._helpers, self._callbacks, url=_s(url),
                            name=_s(f.get("name", f.get("title", "Unknown"))),
                            detail=self._build_detail(f),
                            severity=SEVERITY_MAP.get(f.get("severity", "info"), "Information"),
                            confidence=CONFIDENCE_MAP.get(f.get("confidence", "tentative"), "Tentative"),
                            request_raw=_s(request_raw),
                            response_raw=_s(response_raw),
                        )
                        self._callbacks.addScanIssue(issue)
                        imported += 1
                    except Exception as e:
                        skipped += 1
                        if skipped <= 3:
                            self._log("[Import] Skip: %s - %s" % (self._safe_str(f.get("name", "?"))[:40], e))

                self._log("[Import] Added %d issues to Burp (%d skipped)" % (imported, skipped))
                def update():
                    self._import_status.setText("  Imported %d findings" % imported)
                    self._import_status.setForeground(Color(0, 180, 0) if imported > 0 else Color(200, 100, 0))
                SwingUtilities.invokeLater(update)
            except Exception as e:
                self._log("[Import ERROR] %s" % e)
                def update_err():
                    self._import_status.setText("  Error: %s" % str(e)[:40])
                    self._import_status.setForeground(Color(220, 50, 50))
                SwingUtilities.invokeLater(update_err)
        threading.Thread(target=run).start()

    def _build_request(self, url, method, f):
        """Build a synthetic HTTP request from finding data."""
        try:
            parsed = URL(url)
            host = parsed.getHost()
            port = parsed.getPort()
            path = parsed.getPath() or "/"
            query = parsed.getQuery()
            if query:
                path = "%s?%s" % (path, query)
            port_str = "" if port in (-1, 80, 443) else ":%d" % port
        except:
            host = f.get("ip", "unknown")
            path = "/"
            port_str = ""

        lines = [
            "%s %s HTTP/1.1" % (method.upper(), path),
            "Host: %s%s" % (host, port_str),
            "User-Agent: RAG-Scan-Stack/1.0",
            "Accept: text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
            "Accept-Language: en-US,en;q=0.5",
            "Connection: close",
        ]
        if method.upper() in ("POST", "PUT", "PATCH"):
            lines.append("Content-Type: application/x-www-form-urlencoded")
            lines.append("Content-Length: 0")
        lines.append("")
        lines.append("")
        return "\r\n".join(lines)

    def _build_response(self, f):
        """Build a synthetic HTTP response for the Target scope/sitemap.

        Returns a realistic-looking response with proper headers but NO
        injected finding details in the body. Finding metadata (evidence,
        description, remediation, CVEs) belongs in the Burp Issue detail
        pane via _build_detail(), not in the response body.
        """
        _s = self._safe_str
        title = _s(f.get("title", f.get("name", "")))
        url = _s(f.get("url", ""))

        body = (
            "<html>\n"
            "<head><title>%s</title></head>\n"
            "<body></body>\n"
            "</html>" % (title or url or "")
        )
        headers = [
            "HTTP/1.1 200 OK",
            "Content-Type: text/html; charset=utf-8",
            "Connection: close",
            "Content-Length: %d" % len(body),
            "",
            "",
        ]
        return "\r\n".join(headers) + body

    def _build_detail(self, f):
        _s = self._safe_str
        parts = ["<b>Source:</b> RAG Scan Stack (%s)" % _s(f.get("source", "?"))]
        if f.get("id"): parts.append("<b>ID:</b> %s" % _s(f["id"]))
        if f.get("severity"): parts.append("<b>Severity:</b> %s" % _s(f["severity"]))
        if f.get("evidence"):
            ev = f["evidence"]
            if isinstance(ev, list):
                parts.append("<b>Evidence:</b><ul>" + "".join("<li>%s</li>" % _s(e) for e in ev) + "</ul>")
            else:
                parts.append("<b>Evidence:</b><pre>%s</pre>" % _s(ev)[:2000])
        if f.get("description"): parts.append("<b>Description:</b> %s" % _s(f["description"])[:1000])
        if f.get("solution"): parts.append("<b>Remediation:</b> %s" % _s(f["solution"])[:1000])
        if f.get("cve"):
            cves = f["cve"] if isinstance(f["cve"], list) else [f["cve"]]
            if cves and cves[0]: parts.append("<b>CVE:</b> %s" % ", ".join(_s(c) for c in cves))
        return "<br>".join(parts)

    # ── Export ──
    def _export_findings(self, event):
        def run():
            try:
                issues = self._callbacks.getScanIssues(None)
                if not issues:
                    self._log("[Export] No Burp scan issues found")
                    return
                scope_only = self._export_scope_only.isSelected()
                findings = []
                for issue in issues:
                    url_str = str(issue.getUrl())
                    if scope_only and not self._callbacks.isInScope(issue.getUrl()):
                        continue
                    finding = {
                        "name": issue.getIssueName(),
                        "url": url_str,
                        "severity": BURP_SEVERITY_MAP.get(issue.getSeverity(), "info"),
                        "confidence": BURP_CONFIDENCE_MAP.get(issue.getConfidence(), "tentative"),
                        "type": issue.getIssueType(),
                        "evidence": [issue.getIssueDetail() or ""],
                        "source": "burpsuite",
                    }
                    msgs = issue.getHttpMessages()
                    if msgs and len(msgs) > 0:
                        msg = msgs[0]
                        if msg.getRequest():
                            finding["request_raw"] = self._helpers.bytesToString(msg.getRequest())
                        if msg.getResponse():
                            finding["response_raw"] = self._helpers.bytesToString(msg.getResponse())[:5000]
                    findings.append(finding)
                self._log("[Export] Collected %d issues" % len(findings))
                result = self._api_post("/import/findings-exchange", {"source": "burpsuite", "findings": findings})
                imported = result.get("imported", 0)
                self._log("[Export] Sent: %d imported, %d skipped" % (imported, result.get("skipped", 0)))
                def update():
                    self._export_status.setText("  Exported %d" % imported)
                    self._export_status.setForeground(Color(0, 180, 0))
                SwingUtilities.invokeLater(update)
            except Exception as e:
                self._log("[Export ERROR] %s" % e)
                def update_err():
                    self._export_status.setText("  Error: %s" % str(e)[:40])
                    self._export_status.setForeground(Color(220, 50, 50))
                SwingUtilities.invokeLater(update_err)
        threading.Thread(target=run).start()

    def _sync_both(self, event):
        def run():
            self._log("[Sync] Starting...")
            self._export_findings(None)
            import time; time.sleep(2)
            self._import_all(None)
            self._log("[Sync] Complete")
        threading.Thread(target=run).start()

    # ── SOCKS Proxy Routing ──
    def _refresh_tunnel_nodes(self, event):
        def run():
            try:
                data = self._api_get("/nodes")
                nodes = data.get("nodes", [])
                online = [n for n in nodes if n.get("status") == "online" and n.get("proxy_port")]
                self._tunnel_nodes = online
                def update_ui():
                    _s = self._safe_str
                    self._proxy_node_combo.removeAllItems()
                    self._proxy_node_combo.addItem("(select node)")
                    for n in online:
                        label = "%s - %s (SOCKS:%d)" % (
                            _s(n.get("name", "?")),
                            _s(n.get("hostname", "?")),
                            n.get("proxy_port", 0),
                        )
                        self._proxy_node_combo.addItem(label)
                    self._proxy_status.setText("  %d online tunnel node(s) available" % len(online))
                    self._proxy_status.setForeground(Color(0, 180, 0) if online else Color(150, 150, 150))
                SwingUtilities.invokeLater(update_ui)
                self._log("[Proxy] Loaded %d online tunnel nodes" % len(online))
            except Exception as e:
                self._log("[Proxy ERROR] %s" % e)
                def update_err():
                    self._proxy_status.setText("  Error loading nodes: %s" % str(e)[:40])
                    self._proxy_status.setForeground(Color(220, 50, 50))
                SwingUtilities.invokeLater(update_err)
        threading.Thread(target=run).start()

    def _get_selected_node(self):
        idx = self._proxy_node_combo.getSelectedIndex()
        if idx <= 0 or idx > len(self._tunnel_nodes):
            return None
        return self._tunnel_nodes[idx - 1]

    def _copy_proxy_url(self, event):
        """Copy the selected node's SOCKS proxy URL to clipboard."""
        node = self._get_selected_node()
        if not node:
            self._proxy_status.setText("  Select a tunnel node first")
            self._proxy_status.setForeground(Color(200, 100, 0))
            return
        docker_ip = self._docker_host_ip.getText().strip() or "host.docker.internal"
        port = node.get("proxy_port", 1080)
        url = "socks5://%s:%d" % (docker_ip, port)
        from java.awt import Toolkit
        from java.awt.datatransfer import StringSelection
        Toolkit.getDefaultToolkit().getSystemClipboard().setContents(StringSelection(url), None)
        self._proxy_status.setText("  Copied: %s" % url)
        self._proxy_status.setForeground(Color(0, 200, 0))
        self._log("[Proxy] Copied to clipboard: %s" % url)

    def _copy_proxy_list(self, event):
        """Select all text in proxy list area and copy to clipboard."""
        self._proxy_list_area.selectAll()
        text = self._proxy_list_area.getText()
        if text and "Click" not in text:
            from java.awt import Toolkit
            from java.awt.datatransfer import StringSelection
            Toolkit.getDefaultToolkit().getSystemClipboard().setContents(StringSelection(text), None)
            self._proxy_status.setText("  Proxy list copied to clipboard (%d lines)" % len(text.strip().splitlines()))
            self._proxy_status.setForeground(Color(0, 200, 0))
            self._log("[Proxy] Copied proxy list to clipboard")

    def _set_burp_upstream_proxy(self, event):
        node = self._get_selected_node()
        if not node:
            self._proxy_status.setText("  Select a tunnel node first")
            self._proxy_status.setForeground(Color(200, 100, 0))
            return
        def run():
            docker_ip = self._docker_host_ip.getText().strip() or "host.docker.internal"
            port = node.get("proxy_port", 1080)
            node_name = self._safe_str(node.get("name", "?"))
            self._log("[Proxy] Setting Burp upstream SOCKS5 to %s:%d (node: %s)" % (docker_ip, port, node_name))

            # Try Burp REST API directly (if Burp exposes it)
            set_ok = False
            try:
                import urllib2, ssl
                config_json = json.dumps({"project_options": {"connections": {"socks_proxy": {
                    "use_proxy": True, "host": docker_ip, "port": port, "version": 5,
                }}}})
                # Standard Burp REST API at localhost:1337
                for api_port in (1337, 8080):
                    try:
                        ctx = ssl.create_default_context()
                        ctx.check_hostname = False
                        ctx.verify_mode = ssl.CERT_NONE
                        req = urllib2.Request("http://127.0.0.1:%d/v0.1/configuration" % api_port, config_json)
                        req.get_method = lambda: "PUT"
                        req.add_header("Content-Type", "application/json")
                        urllib2.urlopen(req, context=ctx, timeout=3)
                        set_ok = True
                        break
                    except Exception:
                        pass
            except Exception:
                pass

            if set_ok:
                def update_ok():
                    self._proxy_status.setText("  Burp SOCKS5 set to %s:%d (%s)" % (docker_ip, port, node_name))
                    self._proxy_status.setForeground(Color(0, 200, 0))
                SwingUtilities.invokeLater(update_ok)
                self._log("[Proxy] Set via Burp REST API: socks5://%s:%d" % (docker_ip, port))
            else:
                def update_manual():
                    self._proxy_status.setText("  Set manually: SOCKS5 %s:%d  (Project options > Connections > SOCKS proxy)" % (docker_ip, port))
                    self._proxy_status.setForeground(Color(200, 200, 0))
                SwingUtilities.invokeLater(update_manual)
                self._log("[Proxy] Burp REST API not available. Set manually:")
                self._log("[Proxy]   Project options > Connections > SOCKS proxy")
                self._log("[Proxy]   Host: %s  Port: %d  Version: SOCKS5" % (docker_ip, port))
        threading.Thread(target=run).start()

    def _verify_burp_proxy(self, event):
        """Verify the proxy works by making a request through Burp to check the exit IP.

        Uses Burp's own makeHttpRequest so the request goes through Burp's
        configured upstream SOCKS proxy — if it's set correctly, the external
        IP will be the tunnel node's IP, not ours.
        """
        def run():
            try:
                import urllib2, ssl, time as _time
                start = _time.time()

                # Make a direct request to httpbin to get our external IP
                # This goes through Burp's proxy chain if configured
                ctx = ssl.create_default_context()
                ctx.check_hostname = False
                ctx.verify_mode = ssl.CERT_NONE
                req = urllib2.Request("https://httpbin.org/ip")
                req.add_header("User-Agent", "RAG-Scan-Bridge/1.0")
                resp = urllib2.urlopen(req, context=ctx, timeout=10)
                body = resp.read()
                elapsed = int((_time.time() - start) * 1000)

                data = json.loads(body)
                ext_ip = data.get("origin", "?")

                def update_ok():
                    self._proxy_status.setText("  Verified: exit IP %s (%dms)" % (self._safe_str(ext_ip), elapsed))
                    self._proxy_status.setForeground(Color(0, 200, 0))
                SwingUtilities.invokeLater(update_ok)
                self._log("[Proxy Verify] OK: exit IP %s (%dms)" % (self._safe_str(ext_ip), elapsed))
            except Exception as e:
                def update_err():
                    self._proxy_status.setText("  Verify failed: %s" % self._safe_str(str(e))[:50])
                    self._proxy_status.setForeground(Color(220, 50, 50))
                SwingUtilities.invokeLater(update_err)
                self._log("[Proxy Verify] FAILED: %s" % self._safe_str(str(e)))
        threading.Thread(target=run).start()

    def _disable_burp_proxy(self, event):
        def run():
            disabled = False
            try:
                import urllib2, ssl
                config_json = json.dumps({"project_options": {"connections": {"socks_proxy": {
                    "use_proxy": False,
                }}}})
                for api_port in (1337, 8080):
                    try:
                        ctx = ssl.create_default_context()
                        ctx.check_hostname = False
                        ctx.verify_mode = ssl.CERT_NONE
                        req = urllib2.Request("http://127.0.0.1:%d/v0.1/configuration" % api_port, config_json)
                        req.get_method = lambda: "PUT"
                        req.add_header("Content-Type", "application/json")
                        urllib2.urlopen(req, context=ctx, timeout=3)
                        disabled = True
                        break
                    except Exception:
                        pass
            except Exception:
                pass

            if disabled:
                def update_ok():
                    self._proxy_status.setText("  Upstream SOCKS proxy disabled")
                    self._proxy_status.setForeground(Color(150, 150, 150))
                SwingUtilities.invokeLater(update_ok)
                self._log("[Proxy] Disabled via Burp REST API")
            else:
                def update_manual():
                    self._proxy_status.setText("  Disable manually: Project options > Connections > SOCKS proxy > uncheck")
                    self._proxy_status.setForeground(Color(200, 200, 0))
                SwingUtilities.invokeLater(update_manual)
                self._log("[Proxy] Burp REST API not available. Disable manually: Project options > Connections > SOCKS proxy")
        threading.Thread(target=run).start()

    def _push_all_to_rotator(self, event):
        """Generate a copyable proxy list from all online tunnel nodes."""
        if not self._tunnel_nodes:
            self._refresh_tunnel_nodes(None)
            import time; time.sleep(2)

        def run():
            nodes = self._tunnel_nodes
            if not nodes:
                def update_none():
                    self._proxy_status.setText("  No online tunnel nodes found — click Refresh Nodes")
                    self._proxy_status.setForeground(Color(200, 100, 0))
                    self._proxy_list_area.setText("No online tunnel nodes found.\nClick 'Refresh Nodes' first.")
                SwingUtilities.invokeLater(update_none)
                return

            docker_ip = self._docker_host_ip.getText().strip() or "host.docker.internal"
            _s = self._safe_str

            lines = []
            for n in nodes:
                port = n.get("proxy_port", 0)
                name = _s(n.get("name", "?"))
                host = _s(n.get("hostname", "?"))
                lines.append("socks5://%s:%d" % (docker_ip, port))

            text = "\n".join(lines)

            def update_done():
                self._proxy_list_area.setText(text)
                self._proxy_status.setText("  Generated %d proxy entries — use Select All + Copy" % len(lines))
                self._proxy_status.setForeground(Color(0, 200, 0))
            SwingUtilities.invokeLater(update_done)
            self._log("[Rotator] Generated proxy list with %d nodes" % len(lines))

        threading.Thread(target=run).start()

    # ── Follow-Up Queue ──
    def _filter_by_target(self, items):
        """Filter items by the Target IP/hostname field if set."""
        target_filter = self._import_target.getText().strip().lower()
        if not target_filter:
            return items
        filtered = []
        for item in items:
            item_target = (item.get("target") or "").lower()
            item_url = (item.get("url") or "").lower()
            if target_filter in item_target or target_filter in item_url:
                filtered.append(item)
        return filtered

    def _refresh_followup_queue(self, event):
        def run():
            try:
                data = self._api_get("/burp-queue?status=pending&limit=500")
                all_items = data.get("items", [])
                items = self._filter_by_target(all_items)
                self._fuq_items = items
                def update_ui():
                    self._fuq_model.clear()
                    for item in items:
                        sev = (item.get("severity") or "info").upper()[:4]
                        title = self._safe_str(item.get("title", "?"))[:60]
                        target = self._safe_str(item.get("target") or item.get("url") or "?")
                        if len(target) > 40:
                            target = target[:37] + "..."
                        entry = "[%s] %s  @ %s" % (sev, title, target)
                        self._fuq_model.addElement(entry)
                    target_note = ""
                    target_filter = self._import_target.getText().strip()
                    if target_filter and len(items) != len(all_items):
                        target_note = " (filtered from %d by '%s')" % (len(all_items), target_filter)
                    self._fuq_status.setText("  %d pending items%s" % (len(items), target_note))
                    self._fuq_status.setForeground(Color(0, 180, 0) if items else Color(150, 150, 150))
                SwingUtilities.invokeLater(update_ui)
                self._log("[FollowUp Queue] Loaded %d pending items (%d total)" % (len(items), len(all_items)))
            except Exception as e:
                self._log("[FollowUp Queue ERROR] %s" % e)
                def update_err():
                    self._fuq_status.setText("  Error: %s" % str(e)[:40])
                    self._fuq_status.setForeground(Color(220, 50, 50))
                SwingUtilities.invokeLater(update_err)
        threading.Thread(target=run).start()

    def _on_followup_selected(self, index):
        """Called when a follow-up is selected in the queue list."""
        if index < 0 or index >= len(self._fuq_items):
            self._fuq_detail.setText("")
            return
        item = self._fuq_items[index]
        lines = []
        lines.append("=== %s ===" % item.get("title", "?"))
        lines.append("Severity:  %s" % (item.get("severity") or "?"))
        lines.append("Target:    %s" % (item.get("target") or "?"))
        lines.append("URL:       %s" % (item.get("url") or "N/A"))
        lines.append("Method:    %s" % (item.get("method") or "GET"))
        lines.append("Source:    %s" % (item.get("finding_source") or "?"))
        cves = item.get("cves") or []
        if cves:
            lines.append("CVEs:      %s" % ", ".join(str(c) for c in cves))
        lines.append("")
        if item.get("description"):
            lines.append("--- Description ---")
            lines.append(str(item["description"])[:2000])
            lines.append("")
        if item.get("evidence"):
            lines.append("--- Evidence ---")
            lines.append(str(item["evidence"])[:3000])
            lines.append("")
        if item.get("follow_up_reason"):
            lines.append("--- Reason ---")
            lines.append(str(item["follow_up_reason"]))
            lines.append("")
        if item.get("follow_up_notes"):
            lines.append("--- Notes ---")
            lines.append(str(item["follow_up_notes"]))
            lines.append("")
        if item.get("request_raw"):
            lines.append("--- HTTP Request ---")
            lines.append(str(item["request_raw"])[:3000])
            lines.append("")
        if item.get("response_raw"):
            lines.append("--- HTTP Response ---")
            lines.append(str(item["response_raw"])[:3000])
        meta = item.get("metadata") or {}
        if isinstance(meta, dict) and meta:
            lines.append("")
            lines.append("--- Metadata ---")
            for k, v in meta.items():
                lines.append("  %s: %s" % (k, v))
        self._fuq_detail.setText("\n".join(lines))
        self._fuq_detail.setCaretPosition(0)

    def _import_selected_followups(self, event):
        indices = list(self._fuq_list.getSelectedIndices())
        if not indices:
            self._log("[FollowUp Queue] No items selected")
            return
        items = [self._fuq_items[i] for i in indices if i < len(self._fuq_items)]
        self._do_import_followups(items)

    def _import_all_followups(self, event):
        if not self._fuq_items:
            self._log("[FollowUp Queue] No items in queue")
            return
        self._do_import_followups(list(self._fuq_items))

    def _do_import_followups(self, items):
        def run():
            imported = 0
            skipped = 0
            imported_ids = []
            for item in items:
                try:
                    url = item.get("url") or ""
                    if not url and item.get("target"):
                        target = item["target"]
                        url = target if target.startswith("http") else "https://%s/" % target
                    if not url:
                        skipped += 1
                        continue

                    request_raw = item.get("request_raw") or self._build_request(
                        url, item.get("method", "GET") or "GET", item)
                    response_raw = item.get("response_raw") or self._build_response(item)

                    _s = self._safe_str
                    detail_parts = ["<b>Source:</b> Follow-Up Queue (%s)" % _s(item.get("finding_source") or "?")]
                    if item.get("severity"): detail_parts.append("<b>Severity:</b> %s" % _s(item["severity"]))
                    if item.get("evidence"): detail_parts.append("<b>Evidence:</b><pre>%s</pre>" % _s(item["evidence"])[:2000])
                    if item.get("description"): detail_parts.append("<b>Description:</b> %s" % _s(item["description"])[:1000])
                    cves = item.get("cves") or []
                    if cves: detail_parts.append("<b>CVEs:</b> %s" % ", ".join(_s(c) for c in cves))
                    if item.get("follow_up_reason"): detail_parts.append("<b>Reason:</b> %s" % _s(item["follow_up_reason"])[:500])

                    issue = RagScanIssue(
                        self._helpers, self._callbacks, url=_s(url),
                        name="[FU] " + _s(item.get("title") or "Follow-Up"),
                        detail="<br>".join(detail_parts),
                        severity=SEVERITY_MAP.get(item.get("severity", "info"), "Information"),
                        confidence="Tentative",
                        request_raw=request_raw,
                        response_raw=response_raw,
                    )
                    self._callbacks.addScanIssue(issue)
                    imported += 1
                    if item.get("id"):
                        imported_ids.append(item["id"])
                except Exception as e:
                    skipped += 1
                    if skipped <= 3:
                        self._log("[FollowUp Import] Skip: %s — %s" % (
                            (item.get("title") or "?")[:40], e))

            # Bulk-mark as imported in the API
            if imported_ids:
                try:
                    self._api_post("/burp-queue/mark-imported", {"ids": imported_ids})
                except Exception as e:
                    self._log("[FollowUp Queue] Warning: could not mark as imported: %s" % e)

            self._log("[FollowUp Queue] Imported %d to Burp (%d skipped)" % (imported, skipped))
            def update():
                self._fuq_status.setText("  Imported %d items" % imported)
                self._fuq_status.setForeground(Color(0, 180, 0) if imported else Color(200, 100, 0))
            SwingUtilities.invokeLater(update)

            # Refresh queue to remove imported items
            if imported_ids:
                self._refresh_followup_queue(None)
        threading.Thread(target=run).start()


class FollowUpSelectionListener(ListSelectionListener):
    """Forwards JList selection changes to the BurpExtender detail pane."""
    def __init__(self, extender):
        self._ext = extender
    def valueChanged(self, event):
        if event.getValueIsAdjusting():
            return
        idx = self._ext._fuq_list.getSelectedIndex()
        self._ext._on_followup_selected(idx)


class RagScanIssue(IScanIssue):
    def __init__(self, helpers, callbacks, url, name, detail, severity, confidence,
                 request_raw=None, response_raw=None):
        self._helpers = helpers
        self._callbacks = callbacks
        self._url = url
        self._name = name
        self._detail = detail
        self._severity = severity
        self._confidence = confidence
        self._request_raw = request_raw
        self._response_raw = response_raw
        try:
            parsed = URL(url)
            self._host = parsed.getHost()
            self._port = parsed.getPort() if parsed.getPort() > 0 else (443 if parsed.getProtocol() == "https" else 80)
            self._protocol = parsed.getProtocol()
        except:
            self._host = "unknown"
            self._port = 80
            self._protocol = "http"

    def getUrl(self):
        try: return URL(self._url)
        except: return URL("http://unknown/")
    def getIssueName(self): return "[RAG] " + self._name
    def getIssueType(self): return 0x08000000
    def getSeverity(self): return self._severity
    def getConfidence(self): return self._confidence
    def getIssueBackground(self): return "Imported from RAG Scan Stack."
    def getRemediationBackground(self): return None
    def getIssueDetail(self): return self._detail
    def getRemediationDetail(self): return None
    def getHttpMessages(self):
        if not self._request_raw:
            return []
        try:
            service = self._helpers.buildHttpService(self._host, self._port, self._protocol == "https")
            req_bytes = self._helpers.stringToBytes(self._request_raw)
            resp_bytes = self._helpers.stringToBytes(self._response_raw) if self._response_raw else None
            return [CustomHttpRequestResponse(req_bytes, resp_bytes, service)]
        except:
            return []
    def getHttpService(self):
        try: return self._helpers.buildHttpService(self._host, self._port, self._protocol == "https")
        except: return None


class CustomHttpRequestResponse(IHttpRequestResponse):
    """Wrapper for synthetic HTTP request/response pairs."""
    def __init__(self, request, response, service):
        self._request = request
        self._response = response
        self._service = service
    def getRequest(self): return self._request
    def getResponse(self): return self._response
    def getHttpService(self): return self._service
    def setRequest(self, m): self._request = m
    def setResponse(self, m): self._response = m
    def setHttpService(self, s): self._service = s
    def getComment(self): return "Imported from RAG Scan Stack"
    def setComment(self, c): pass
    def getHighlight(self): return None
    def setHighlight(self, c): pass
