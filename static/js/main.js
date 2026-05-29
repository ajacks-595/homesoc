"use strict";
/* HomeSOC — single-namespace JS for all pages.
 * Each page calls SOC.initX() from its template; pages that aren't on the
 * page simply never invoke their init().
 */

const SOC = (() => {
  // ===== core utilities =====================================================

  async function api(path, opts = {}) {
    const r = await fetch(path, {
      headers: { "Content-Type": "application/json", ...(opts.headers || {}) },
      ...opts,
    });
    let body;
    try { body = await r.json(); } catch { body = { success: false, error: "non-json response" }; }
    if (!r.ok && body && body.error === undefined) body.error = `HTTP ${r.status}`;
    return body;
  }

  // All DB timestamps are stored UTC (without a 'Z' suffix). Parse them as
  // UTC and render in the user's local time so BST/GMT shows correctly.
  function parseUtc(s) {
    if (!s) return null;
    let iso = s.replace(" ", "T");
    if (!iso.endsWith("Z") && !/[+-]\d{2}:?\d{2}$/.test(iso)) iso += "Z";
    return new Date(iso);
  }

  const fmt = {
    ts(s) {
      const d = parseUtc(s);
      if (!d || isNaN(d)) return "";
      // YYYY-MM-DD HH:MM:SS in local time
      const pad = n => String(n).padStart(2, "0");
      return `${d.getFullYear()}-${pad(d.getMonth() + 1)}-${pad(d.getDate())} `
           + `${pad(d.getHours())}:${pad(d.getMinutes())}:${pad(d.getSeconds())}`;
    },
    short(s, n = 80) { if (!s) return ""; return s.length > n ? s.slice(0, n) + "…" : s; },
    int(n) { return (n ?? 0).toLocaleString(); },
    pct(n) { return (n ?? 0).toFixed(1) + "%"; },
    age(iso) {
      const t = parseUtc(iso);
      if (!t || isNaN(t)) return "";
      const s = Math.max(0, Math.floor((Date.now() - t.getTime()) / 1000));
      if (s < 60) return s + "s ago";
      if (s < 3600) return Math.floor(s / 60) + "m ago";
      if (s < 86400) return Math.floor(s / 3600) + "h ago";
      return Math.floor(s / 86400) + "d ago";
    },
  };

  function el(tag, attrs = {}, children = []) {
    const e = document.createElement(tag);
    for (const [k, v] of Object.entries(attrs)) {
      if (k === "className") e.className = v;
      else if (k === "html") e.innerHTML = v;
      else if (k.startsWith("on") && typeof v === "function") e.addEventListener(k.slice(2), v);
      else if (k === "dataset") Object.assign(e.dataset, v);
      else if (v !== null && v !== undefined) e.setAttribute(k, v);
    }
    for (const c of [].concat(children)) {
      if (c == null) continue;
      e.appendChild(typeof c === "string" ? document.createTextNode(c) : c);
    }
    return e;
  }

  function toast(msg, kind = "info") {
    const root = document.getElementById("toast-root");
    if (!root) return;
    const t = el("div", { className: `banner ${kind}`, style: "min-width:280px; margin-top:6px" }, msg);
    root.appendChild(t);
    setTimeout(() => t.remove(), 4500);
  }

  function openModal(html, opts = {}) {
    const root = document.getElementById("modal-root");
    if (!root) return null;
    root.innerHTML = "";
    const back = el("div", { className: "modal-backdrop", onclick: e => {
      if (e.target.classList.contains("modal-backdrop")) closeModal();
    }});
    const m = el("div", { className: "modal" });
    m.innerHTML = html;
    back.appendChild(m);
    root.appendChild(back);
    if (opts.onMount) opts.onMount(m);
    return m;
  }

  function closeModal() {
    const root = document.getElementById("modal-root");
    if (root) root.innerHTML = "";
  }

  function openSidePanel(html) {
    const p = document.getElementById("side-panel-content");
    p.innerHTML = html;
    document.getElementById("side-panel").classList.add("open");
  }

  function closeSidePanel() {
    document.getElementById("side-panel").classList.remove("open");
  }

  // ===== theme handling =====================================================

  function applyTheme(name) {
    document.body.className = "theme-" + name;
    localStorage.setItem("soc-theme", name);
    document.querySelectorAll(".theme-swatch").forEach(s => {
      s.classList.toggle("active", s.dataset.theme === name);
    });
    // Persist on server (best-effort)
    fetch("/api/settings/theme", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ theme: name }),
    }).catch(() => {});
  }

  function initThemePicker() {
    const current = localStorage.getItem("soc-theme") || "midnight";
    document.body.className = "theme-" + current;
    document.querySelectorAll(".theme-swatch").forEach(s => {
      if (s.dataset.theme === current) s.classList.add("active");
      s.addEventListener("click", () => applyTheme(s.dataset.theme));
    });
  }

  // ===== view toggle =======================================================

  function initViewToggle(hasSocView) {
    const tgl = document.getElementById("view-toggle");
    if (!tgl) return;
    const stored = localStorage.getItem("soc-view") || "minimal";
    function setView(v) {
      localStorage.setItem("soc-view", v);
      tgl.querySelectorAll("button").forEach(b => b.classList.toggle("active", b.dataset.view === v));
      if (hasSocView) {
        document.getElementById("view-minimal")?.classList.toggle("hidden", v !== "minimal");
        document.getElementById("view-soc")?.classList.toggle("hidden", v !== "soc");
        if (v === "soc") socViewActivate();
      }
    }
    tgl.querySelectorAll("button").forEach(b => b.addEventListener("click", () => setView(b.dataset.view)));
    setView(stored);
  }

  // ===== severity helpers ==================================================

  function sevClass(level) {
    // Wazuh severity convention: 10+ is high-critical (e.g. auth-failure
    // bruteforce, CVE alerts), 12+ is alarm-grade. Treat both as critical
    // in the UI — they should grab attention.
    if (level >= 10) return "sev-crit";
    if (level >= 7)  return "sev-high";
    if (level >= 4)  return "sev-med";
    return "";
  }

  function ipLink(ip) {
    if (!ip) return "";
    return `<a href="/osint?ioc=${encodeURIComponent(ip)}" class="mono">${escapeHtml(ip)}</a>`;
  }

  const _IPV4_TEST = /\b(?:\d{1,3}\.){3}\d{1,3}\b/;
  const _IPV4_GLOBAL = /\b(?:\d{1,3}\.){3}\d{1,3}\b/g;

  // Link IPv4 addresses found in TEXT NODES of an element to OSINT lookups.
  // Operates on the live DOM rather than round-tripping innerHTML, so it never
  // re-parses or duplicates (possibly untrusted) markup. Skips text already
  // inside an <a> so we don't double-link.
  function linkifyIpsInEl(root) {
    if (!root) return;
    const walker = document.createTreeWalker(root, NodeFilter.SHOW_TEXT, {
      acceptNode(node) {
        if (!node.nodeValue || !_IPV4_TEST.test(node.nodeValue)) return NodeFilter.FILTER_REJECT;
        for (let p = node.parentNode; p && p !== root.parentNode; p = p.parentNode) {
          if (p.nodeName === "A") return NodeFilter.FILTER_REJECT;
        }
        return NodeFilter.FILTER_ACCEPT;
      },
    });
    const targets = [];
    let node;
    while ((node = walker.nextNode())) targets.push(node);
    for (const t of targets) {
      const text = t.nodeValue;
      const frag = document.createDocumentFragment();
      let last = 0, m;
      _IPV4_GLOBAL.lastIndex = 0;
      while ((m = _IPV4_GLOBAL.exec(text))) {
        if (m.index > last) frag.appendChild(document.createTextNode(text.slice(last, m.index)));
        frag.appendChild(el("a", { href: "/osint?ioc=" + encodeURIComponent(m[0]), className: "mono" }, m[0]));
        last = m.index + m[0].length;
      }
      if (last < text.length) frag.appendChild(document.createTextNode(text.slice(last)));
      t.parentNode.replaceChild(frag, t);
    }
  }

  // ===== DASHBOARD ==========================================================

  let dashCharts = {};
  let dashFeedTimer = null;

  async function initDashboard() {
    initThemePicker();
    initViewToggle(true);
    await Promise.all([
      loadMetrics(), loadSummary(), loadRecActions(), loadHiSevFeed(),
    ]);
    // Start polling feed every 30s
    if (dashFeedTimer) clearInterval(dashFeedTimer);
    dashFeedTimer = setInterval(() => {
      loadHiSevFeed();
      const v = localStorage.getItem("soc-view");
      if (v === "soc") loadSocFeed();
    }, 30000);
  }

  async function loadMetrics() {
    const r = await api("/api/dashboard/metrics");
    if (!r.success) return;
    const d = r.data;
    document.getElementById("m-alerts-today").textContent = fmt.int(d.alerts_today);
    document.getElementById("m-block-rate").textContent = (d.block_rate ?? 0).toFixed(1);
    document.getElementById("m-block-rate-sub").textContent =
      `${fmt.int(d.dns_blocked)} / ${fmt.int(d.dns_total)} blocked`;
    document.getElementById("m-agents").textContent = fmt.int(d.active_agents);
    const p1 = document.getElementById("m-p1");
    p1.textContent = fmt.int(d.open_p1);

    // Build banner(s) — critical alerts first (higher urgency), then P1 actions
    const banners = [];
    if (d.critical_count > 0) {
      const sample = (d.critical_24h || []).slice(0, 3).map(a =>
        `<div class="mono tiny" style="margin-top:4px">
           <span class="badge danger">L${a.rule_level}</span>
           ${escapeHtml(fmt.ts(a.timestamp))} ·
           <strong>${escapeHtml(a.agent_name || "—")}</strong> ·
           rule ${a.rule_id} —
           ${escapeHtml(fmt.short(a.rule_description, 110))}
         </div>`).join("");
      banners.push(
        `<div class="banner danger">
           <div style="flex:1">
             <div><strong>⚠ ${d.critical_count} critical alert${d.critical_count > 1 ? "s" : ""}
               (level ≥ 10) in the last 24h</strong> —
               <a href="/alerts?min_level=10">view all</a>
             </div>
             ${sample}
           </div>
         </div>`);
    }
    if (d.open_p1 > 0) {
      banners.push(
        `<div class="banner danger">⚠ ${d.open_p1} open P1 action${d.open_p1 > 1 ? "s" : ""} — <a href="/actions">review now</a></div>`);
    }
    const host = document.getElementById("dash-banner-host");
    if (host) host.innerHTML = banners.join("");
    const banner2 = document.getElementById("soc-p1-banner");
    if (banner2) banner2.innerHTML = banners.join("");
  }

  async function loadSummary() {
    const r = await api("/api/dashboard/summary");
    if (!r.success) return;
    document.getElementById("exec-summary").innerHTML = r.data.html || "<p class='muted'>No briefing.</p>";
    if (r.data.date)
      document.getElementById("summary-date").textContent = `(${r.data.date})`;
  }

  async function loadRecActions() {
    const r = await api("/api/actions?status=open");
    if (!r.success) return;
    const r2 = await api("/api/actions?status=in_progress");
    const all = (r.data || []).concat(r2.success ? (r2.data || []) : []);
    const p1 = all.filter(a => a.priority === "P1");
    const p2 = all.filter(a => a.priority === "P2");
    const p3 = all.filter(a => a.priority === "P3");

    const host = document.getElementById("rec-actions");
    if (!host) return;
    host.innerHTML = "";
    if (!all.length) {
      host.innerHTML = "<p class='muted small'>No open actions. ✓</p>";
      return;
    }
    const renderItem = (a) =>
      `<div style="margin:6px 0; padding:6px 0; border-bottom:1px solid var(--border)">
         <span class="badge ${a.priority.toLowerCase()}">${a.priority}</span>
         <span style="margin-left:6px">${fmt.short(stripBold(a.description), 200)}</span>
         <div class="tiny muted">${a.briefing_date} · ${a.status}</div>
       </div>`;
    let html = "";
    p1.forEach(a => html += renderItem(a));   // all P1s
    p2.slice(0, 2).forEach(a => html += renderItem(a));
    p3.slice(0, 2).forEach(a => html += renderItem(a));
    const hidden = (p2.length - 2 > 0 ? p2.length - 2 : 0) + (p3.length - 2 > 0 ? p3.length - 2 : 0);
    if (hidden > 0) {
      html += `<a href="/actions" class="small">Show ${hidden} more →</a>`;
    }
    host.innerHTML = html;
  }

  function stripBold(s) {
    return (s || "").replace(/\*\*/g, "").replace(/`/g, "");
  }

  async function loadHiSevFeed() {
    const r = await api("/api/alerts/latest?min_level=7&limit=10");
    if (!r.success) return;
    const feed = document.getElementById("hi-sev-feed");
    if (!feed) return;
    feed.innerHTML = "";
    if (!r.data.length) {
      feed.innerHTML = "<div class='muted small'>No high-severity alerts.</div>";
      return;
    }
    r.data.forEach(a => feed.appendChild(alertRowEl(a)));
  }

  function alertRowEl(a) {
    const div = el("div", { className: `alert-row ${sevClass(a.rule_level)}` });
    const agent = escapeHtml(a.agent_name || "—");
    const desc = escapeHtml(fmt.short(a.rule_description, 200));
    // Click anywhere on the row → open that alert in Alert Explorer (expanded).
    // Click the agent name → filter explorer to that agent.
    div.innerHTML =
      `<span class="ts">${fmt.ts(a.timestamp)}</span>
       <a class="agent" href="/alerts?agent=${encodeURIComponent(a.agent_name || "")}" onclick="event.stopPropagation()">${agent}</a>
       <span class="level">${a.rule_level}</span>
       <span class="desc">${desc}
         <span class="muted tiny"> · rule ${escapeHtml(a.rule_id)}</span></span>`;
    div.style.cursor = "pointer";
    div.addEventListener("click", () => {
      window.location.href = `/alerts?focus=${a.id}`;
    });
    return div;
  }

  // ===== SOC view ==========================================================

  let socActivated = false;
  async function socViewActivate() {
    if (socActivated) { loadSocFeed(); return; }
    socActivated = true;
    await Promise.all([loadSocFeed(), loadAgents(), loadSocDns(), loadCharts()]);
  }

  async function loadSocFeed() {
    const r = await api("/api/alerts/latest?min_level=3&limit=30");
    if (!r.success) return;
    const feed = document.getElementById("soc-feed");
    if (!feed) return;
    feed.innerHTML = "";
    r.data.forEach(a => feed.appendChild(alertRowEl(a)));
    const stale = document.getElementById("soc-feed-stale");
    if (stale) stale.textContent = "updated " + new Date().toLocaleTimeString();
  }

  async function loadAgents() {
    const r = await api("/api/hosts");
    if (!r.success) return;
    const host = document.getElementById("soc-agents");
    if (!host) return;
    const withAgent = r.data.filter(h => h.agent_id);
    host.innerHTML = withAgent.length ? "" : "<div class='muted small'>No agents recorded.</div>";
    withAgent.forEach(h => {
      const row = el("div", { className: "flex-row", style: "padding:4px 0; border-bottom:1px solid var(--border)" });
      row.innerHTML = `
        <span class="dot ${h.agent_status || "no_agent"}"></span>
        <span class="mono">${escapeHtml(h.ip)}</span>
        <span style="flex:1">${escapeHtml(h.hostname || "—")}</span>
        <span class="tiny muted">${h.last_seen ? fmt.age(h.last_seen) : ""}</span>`;
      host.appendChild(row);
    });
  }

  async function loadSocDns() {
    const r = await api("/api/dns/today");
    if (!r.success) return;
    const d = r.data;
    document.getElementById("soc-dns-q").textContent = fmt.int(d.total_queries);
    document.getElementById("soc-dns-b").textContent = fmt.int(d.blocked_queries);
    document.getElementById("soc-dns-r").textContent = d.total_queries
      ? ((d.blocked_queries * 100 / d.total_queries).toFixed(1) + "%") : "—";
    const top = document.getElementById("soc-dns-top");
    top.innerHTML = "";
    (d.top_blocked || []).slice(0, 5).forEach(t => {
      const tr = el("tr");
      tr.innerHTML = `<td class="mono small">${escapeHtml(t.domain)}</td><td class="right mono">${fmt.int(t.count)}</td>`;
      top.appendChild(tr);
    });
  }

  async function loadCharts() {
    const stats = await api("/api/dashboard/stats");
    if (!stats.success) return;
    const s = stats.data;
    const accent = getCssVar("--accent");
    const accent2 = getCssVar("--accent-secondary");
    const warn = getCssVar("--warning");
    const danger = getCssVar("--danger");

    drawChart("chart-vol", {
      type: "bar",
      data: {
        labels: s.alerts_by_day.map(d => d.day),
        datasets: [{ label: "Alerts", data: s.alerts_by_day.map(d => d.n),
                     backgroundColor: accent }],
      },
    });

    drawChart("chart-sev", {
      type: "doughnut",
      data: {
        labels: s.alerts_by_severity.map(d => "Lvl " + d.rule_level),
        datasets: [{
          data: s.alerts_by_severity.map(d => d.n),
          backgroundColor: s.alerts_by_severity.map(d =>
            d.rule_level >= 12 ? danger : d.rule_level >= 7 ? warn : d.rule_level >= 4 ? accent : accent2),
        }],
      },
    });

    drawChart("chart-rules", {
      type: "bar",
      options: { indexAxis: "y" },
      data: {
        labels: s.alerts_top_rules.map(r => fmt.short(r.rule_description || r.rule_id, 50)),
        datasets: [{ label: "Hits", data: s.alerts_top_rules.map(r => r.n),
                     backgroundColor: accent }],
      },
    });

    drawChart("chart-dns-vol", {
      type: "line",
      data: {
        labels: s.dns_trend.map(d => d.date),
        datasets: [{
          label: "Queries", data: s.dns_trend.map(d => d.total_queries),
          borderColor: accent, fill: false, tension: 0.3,
        }],
      },
    });

    drawChart("chart-dns-rate", {
      type: "line",
      data: {
        labels: s.dns_trend.map(d => d.date),
        datasets: [{
          label: "Block rate %",
          data: s.dns_trend.map(d => d.total_queries
            ? +(d.blocked_queries * 100 / d.total_queries).toFixed(1) : 0),
          borderColor: warn, fill: false, tension: 0.3,
        }],
      },
    });
  }

  function getCssVar(name) {
    return getComputedStyle(document.body).getPropertyValue(name).trim();
  }

  function drawChart(id, cfg) {
    const c = document.getElementById(id);
    if (!c) return;
    if (dashCharts[id]) { dashCharts[id].destroy(); }
    dashCharts[id] = new Chart(c.getContext("2d"), {
      ...cfg,
      options: {
        responsive: true, maintainAspectRatio: false,
        plugins: { legend: { display: cfg.type !== "doughnut" ? false : true } },
        ...(cfg.options || {}),
      },
    });
  }

  function quickOsint(ev) {
    ev.preventDefault();
    const v = document.getElementById("quick-osint-ioc").value.trim();
    if (v) window.location.href = "/osint?ioc=" + encodeURIComponent(v);
  }

  // Attribute-safe HTML escaping. Encodes quotes too, so values interpolated
  // into HTML *attribute* contexts (value="...", title="...") can't break out.
  function escapeHtml(s) {
    return (s == null ? "" : String(s))
      .replace(/&/g, "&amp;").replace(/</g, "&lt;").replace(/>/g, "&gt;")
      .replace(/"/g, "&quot;").replace(/'/g, "&#39;");
  }

  // Allow only http(s)/mailto absolute URLs and same-origin relative paths into
  // href/src. Rejects javascript:, data:, vbscript:, and protocol-relative
  // (//evil) URLs — returns "" so the attribute is inert. Use together with
  // escapeHtml for the attribute-quote layer.
  function safeUrl(u) {
    if (u == null) return "";
    const s = String(u).trim();
    if (/^https?:\/\//i.test(s)) return s;
    if (/^mailto:/i.test(s)) return s;
    if (/^[/#?]/.test(s) && !s.startsWith("//")) return s;   // same-origin relative
    return "";
  }

  // ===== BRIEFINGS ==========================================================

  let briefingsCache = { daily: [], weekly: [] };

  async function initBriefings() {
    initThemePicker();
    document.getElementById("b-search").addEventListener("input", e => {
      filterCalendar(e.target.value.trim());
    });
    await loadBriefings();
  }

  async function loadBriefings() {
    const [d, w] = await Promise.all([
      api("/api/briefings?type=daily"),
      api("/api/briefings?type=weekly"),
    ]);
    if (d.success) briefingsCache.daily = d.data;
    if (w.success) briefingsCache.weekly = w.data;
    renderCalendar();
    renderWeeklyList();
  }

  async function syncBriefings() {
    toast("Syncing briefings…", "info");
    const r = await api("/api/briefings/sync", { method: "POST" });
    if (r.success) {
      toast(`Synced ${r.data.briefings} briefings, ${r.data.actions} new actions.`, "info");
      await loadBriefings();
    } else {
      toast("Sync failed: " + r.error, "danger");
    }
  }

  function filterCalendar(q) {
    if (!q) { renderCalendar(); return; }
    api("/api/briefings?type=daily&q=" + encodeURIComponent(q)).then(r => {
      if (!r.success) return;
      briefingsCache.daily = r.data;
      renderCalendar();
    });
  }

  let calMonth = null;

  function renderCalendar() {
    const host = document.getElementById("b-calendar-host");
    if (!host) return;
    const by = {};
    briefingsCache.daily.forEach(b => { by[b.date] = b; });

    const latest = briefingsCache.daily[0]?.date || new Date().toISOString().slice(0, 10);
    if (!calMonth) calMonth = latest.slice(0, 7);

    const [yr, mo] = calMonth.split("-").map(Number);
    const first = new Date(Date.UTC(yr, mo - 1, 1));
    const dayCount = new Date(Date.UTC(yr, mo, 0)).getDate();
    const offset = (first.getUTCDay() + 6) % 7; // Mon-first

    let html = `
      <div class="calendar-header">
        <button class="ghost small" onclick="SOC.calNav(-1)">◀</button>
        <strong>${calMonth}</strong>
        <button class="ghost small" onclick="SOC.calNav(1)">▶</button>
      </div>
      <div class="calendar">`;
    ["M","T","W","T","F","S","S"].forEach(d => html += `<div class="dow">${d}</div>`);
    for (let i = 0; i < offset; i++) html += `<div class="day empty"></div>`;
    for (let d = 1; d <= dayCount; d++) {
      const iso = `${yr}-${String(mo).padStart(2, "0")}-${String(d).padStart(2, "0")}`;
      const b = by[iso];
      const cls = b ? `day ${b.assessment}` : "day muted";
      html += `<div class="${cls}" data-date="${iso}" ${b ? `data-id="${b.id}"` : ""}>
                 <span class="num">${d}</span>
                 <span class="assessment"></span>
               </div>`;
    }
    html += `</div>`;
    host.innerHTML = html;
    host.querySelectorAll(".day[data-id]").forEach(n => {
      n.addEventListener("click", () => loadBriefing(parseInt(n.dataset.id, 10), n));
    });
  }

  function calNav(d) {
    if (!calMonth) return;
    const [yr, mo] = calMonth.split("-").map(Number);
    const nd = new Date(Date.UTC(yr, mo - 1 + d, 1));
    calMonth = `${nd.getUTCFullYear()}-${String(nd.getUTCMonth() + 1).padStart(2, "0")}`;
    renderCalendar();
  }

  function renderWeeklyList() {
    const host = document.getElementById("b-weekly-list");
    if (!host) return;
    host.innerHTML = "";
    if (!briefingsCache.weekly.length) {
      host.innerHTML = "<div class='muted small'>No weekly reports.</div>";
      return;
    }
    briefingsCache.weekly.forEach(b => {
      const a = el("a", { href: "#", className: "flex-row", style: "padding:6px 0; border-bottom:1px solid var(--border)" });
      a.innerHTML = `<span class="dot ${b.assessment === 'action_required' ? 'disconnected' : b.assessment === 'notable' ? 'never' : 'active'}"></span>
                     <span style="flex:1">Week ending ${b.date}</span>
                     <span class="muted small">${fmt.int(b.word_count)} words</span>`;
      a.addEventListener("click", e => { e.preventDefault(); loadBriefing(b.id); });
      host.appendChild(a);
    });
  }

  async function loadBriefing(id, dayNode) {
    const r = await api("/api/briefings/" + id);
    if (!r.success) { toast(r.error, "danger"); return; }
    const d = r.data;
    document.getElementById("b-reader-title").textContent =
      `${d.type === "weekly" ? "Weekly" : "Daily"} — ${d.date}`;
    document.getElementById("b-reader-meta").textContent =
      `${fmt.int(d.word_count)} words · ${d.actions.length} actions · ${d.assessment}`;
    document.getElementById("b-reader-body").innerHTML = d.html;
    document.querySelectorAll(".calendar .day").forEach(n => n.classList.remove("selected"));
    if (dayNode) dayNode.classList.add("selected");
    // Link IPs in the rendered briefing body
    const body = document.getElementById("b-reader-body");
    linkifyIpsInEl(body);
  }

  // ===== ALERTS =============================================================

  let alertsState = { page: 1, perPage: 50, filters: {}, focusId: null, mitre: null };

  async function initAlerts() {
    initThemePicker();
    const f = document.getElementById("f-level");
    if (f) {
      f.addEventListener("input", () => {
        document.getElementById("f-level-out").textContent = f.value;
      });
    }
    // Status filter dropdown triggers a re-query
    const stat = document.getElementById("f-status");
    if (stat) stat.addEventListener("change", () => { alertsState.page = 1; loadAlerts(); });

    // Pre-fill filters from URL params (so /alerts?min_level=10 works)
    const qp = new URLSearchParams(window.location.search);
    const map = {
      min_level: "f-level", rule_id: "f-rule", agent: "f-agent",
      group: "f-group", q: "f-q", date_from: "f-date-from", date_to: "f-date-to",
    };
    for (const [param, id] of Object.entries(map)) {
      const v = qp.get(param);
      if (v != null) {
        const el = document.getElementById(id);
        if (el) el.value = v;
      }
    }
    if (qp.get("min_level")) {
      document.getElementById("f-level-out").textContent = qp.get("min_level");
    }
    // ?focus=<id> opens that alert at the top of the list, expanded
    const _focus = qp.get("focus") ? parseInt(qp.get("focus"), 10) : NaN;
    alertsState.focusId = Number.isInteger(_focus) ? _focus : null;
    alertsState.mitre = qp.get("mitre") || null;

    await loadAlerts();

    if (alertsState.focusId) await loadAndShowFocusedAlert(alertsState.focusId);
  }

  async function loadAndShowFocusedAlert(id) {
    const r = await api("/api/alerts/" + id);
    if (!r.success) { toast("Could not load focused alert: " + r.error, "warn"); return; }
    const a = r.data;
    const tbody = document.querySelector("#alerts-table tbody");
    // Build a row, mark it, prepend
    const tr = el("tr", { className: sevClass(a.rule_level) + " focused-row",
                          dataset: { id: a.id } });
    tr.innerHTML = `
      <td><input type="checkbox" class="sel" value="${a.id}"></td>
      <td class="mono small">${fmt.ts(a.timestamp)}</td>
      <td><a href="/alerts?agent=${encodeURIComponent(a.agent_name || "")}">${escapeHtml(a.agent_name || "—")}</a></td>
      <td><a href="/alerts?rule_id=${encodeURIComponent(a.rule_id)}" class="mono">${escapeHtml(a.rule_id)}</a></td>
      <td class="mono">${a.rule_level}</td>
      <td>${escapeHtml(fmt.short(a.rule_description, 110))}</td>
      <td class="mono tiny">${escapeHtml(a.location || "")}</td>`;
    tr.addEventListener("click", e => {
      if (e.target.tagName === "A" || e.target.tagName === "INPUT") return;
      toggleAlertRow(tr, a);
    });
    tbody.insertBefore(tr, tbody.firstChild);
    // expand immediately
    toggleAlertRow(tr, a);
    tr.scrollIntoView({ block: "start", behavior: "smooth" });
  }

  function alertsPreset(name) {
    const lvl = document.getElementById("f-level");
    const out = document.getElementById("f-level-out");
    if (name === "critical") lvl.value = 10;
    else if (name === "high") lvl.value = 7;
    else lvl.value = 0;
    out.textContent = lvl.value;
    alertsState.page = 1;
    loadAlerts();
  }

  function alertFiltersFromUi() {
    const out = {
      date_from: document.getElementById("f-date-from").value,
      date_to:   document.getElementById("f-date-to").value,
      agent:     document.getElementById("f-agent").value.trim(),
      rule_id:   document.getElementById("f-rule").value.trim(),
      group:     document.getElementById("f-group").value.trim(),
      min_level: document.getElementById("f-level").value || "0",
      q:         document.getElementById("f-q").value.trim(),
    };
    // Status dropdown: include the param even when empty (means "all"),
    // since the server's default-on-missing is "open only".
    const stat = document.getElementById("f-status");
    if (stat) out.statuses = stat.value;
    return out;
  }

  function applyAlertFilters() { alertsState.page = 1; loadAlerts(); }
  function clearAlertFilters() {
    ["f-date-from","f-date-to","f-agent","f-rule","f-group","f-q"].forEach(id => document.getElementById(id).value = "");
    document.getElementById("f-level").value = 0;
    document.getElementById("f-level-out").textContent = "0";
    alertsState.page = 1; loadAlerts();
  }

  async function loadAlerts() {
    alertsState.filters = alertFiltersFromUi();
    // Empty values dropped, except `statuses=""` which is a meaningful
    // "all statuses" sentinel (server treats missing as "open only").
    const filtered = Object.entries(alertsState.filters)
      .filter(([k, v]) => k === "statuses" || (v && v !== "0"));
    const params = new URLSearchParams({
      page: alertsState.page,
      per_page: alertsState.perPage,
      ...Object.fromEntries(filtered),
    });
    if (alertsState.mitre) params.set("mitre", alertsState.mitre);
    const r = await api("/api/alerts?" + params.toString());
    if (!r.success) { toast(r.error, "danger"); return; }
    document.getElementById("alert-count-badge").textContent = fmt.int(r.data.total);
    document.getElementById("alerts-page-info").textContent =
      `page ${r.data.page} · ${fmt.int(r.data.rows.length)} of ${fmt.int(r.data.total)}`
      + (alertsState.mitre ? ` · ATT&CK: ${alertsState.mitre}` : "");
    const tbody = document.querySelector("#alerts-table tbody");
    tbody.innerHTML = "";
    const statusBadge = {
      tp_remediated:  '<span class="badge ok" title="True Positive — Remediated">TP</span>',
      false_positive: '<span class="badge warn" title="False Positive">FP</span>',
      acknowledged:   '<span class="badge muted" title="Acknowledged">ack</span>',
      in_progress:    '<span class="badge accent" title="In Progress">…</span>',
    };
    r.data.rows.forEach(a => {
      const trClass = sevClass(a.rule_level) + (a.status !== "open" ? " acked" : "");
      const tr = el("tr", { className: trClass, dataset: { id: a.id } });
      const badge = (statusBadge[a.status] || "") + (a.status !== "open" ? " " : "");
      tr.innerHTML =
        `<td><input type="checkbox" class="sel" value="${a.id}"></td>
         <td class="mono small">${fmt.ts(a.timestamp)}</td>
         <td><a href="/alerts?agent=${encodeURIComponent(a.agent_name || "")}" class="agent-jump">${escapeHtml(a.agent_name || "—")}</a></td>
         <td><a href="#" class="rule-jump mono" data-rid="${escapeHtml(a.rule_id)}">${escapeHtml(a.rule_id)}</a></td>
         <td class="mono">${a.rule_level}</td>
         <td>${badge}${escapeHtml(fmt.short(a.rule_description, 110))}</td>
         <td class="mono tiny">${escapeHtml(a.location || "")}</td>`;
      tr.addEventListener("click", e => {
        if (e.target.tagName === "A" || e.target.tagName === "INPUT") return;
        toggleAlertRow(tr, a);
      });
      tbody.appendChild(tr);
    });
    tbody.querySelectorAll(".rule-jump").forEach(a => {
      a.addEventListener("click", e => {
        e.preventDefault();
        document.getElementById("f-rule").value = a.dataset.rid;
        applyAlertFilters();
      });
    });
  }

  // Non-AI IOC cross-correlation panel for an expanded alert row.
  async function loadRelated(id, host) {
    if (!host) return;
    const r = await api(`/api/alerts/${id}/related`);
    if (!r.success) { host.innerHTML = `<span class="muted small">—</span>`; return; }
    const d = r.data || {};
    if (!d.iocs || !d.iocs.length) {
      host.innerHTML = `<span class="muted small">No indicators extracted from this alert.</span>`;
      return;
    }
    let html = `<div class="tiny muted" style="margin-bottom:4px">Indicators: ${
      d.iocs.map(i => `<a href="/osint?ioc=${encodeURIComponent(i)}" class="mono">${escapeHtml(i)}</a>`).join(", ")}</div>`;
    if (d.alerts && d.alerts.length) {
      html += `<table class="data"><tbody>` + d.alerts.map(a =>
        `<tr><td class="mono tiny">${fmt.ts(a.timestamp)}</td>
             <td class="mono tiny">${escapeHtml(a.ioc)}</td>
             <td>${escapeHtml(a.agent_name || "—")}</td>
             <td><a href="/alerts?focus=${encodeURIComponent(a.id)}">rule ${escapeHtml(a.rule_id)}</a> <span class="muted">L${escapeHtml(a.rule_level)}</span></td>
             <td>${escapeHtml(fmt.short(a.rule_description, 70))}</td></tr>`).join("") + `</tbody></table>`;
    } else {
      html += `<div class="muted small">No other alerts referenced these indicators in the last 24h.</div>`;
    }
    if (d.dns && d.dns.length) {
      html += `<div class="tiny" style="margin-top:6px">DNS today: ` + d.dns.map(x =>
        `<span class="badge ${x.status === "blocked" ? "danger" : "muted"}">${escapeHtml(x.domain)} ${escapeHtml(x.status)} ×${escapeHtml(x.count)}</span>`).join(" ") + `</div>`;
    }
    host.innerHTML = html;
  }

  function toggleAlertRow(tr, a) {
    const next = tr.nextElementSibling;
    if (next && next.classList.contains("alert-expanded")) {
      next.remove(); tr.classList.remove("expanded");
      // Drop the focus= param when collapsing
      const url = new URL(window.location.href);
      url.searchParams.delete("focus");
      history.replaceState({}, "", url);
      return;
    }
    tr.classList.add("expanded");
    // Make the URL shareable: /alerts?focus=<id>
    const url = new URL(window.location.href);
    url.searchParams.set("focus", a.id);
    history.replaceState({}, "", url);
    const x = el("tr", { className: "alert-expanded" });
    const td = el("td", { colspan: 7 });

    // Left panel: full_log if present, otherwise a rendered view of the
    // alert's `data` field (vulnerability detector, syscheck, etc. all
    // populate `data` instead of full_log).
    let leftPanel;
    if (a.full_log) {
      leftPanel = `<h3>Full Log</h3>
                   <pre class="pre">${escapeHtml(a.full_log)}</pre>`;
    } else if (a.raw_json && a.raw_json.data && Object.keys(a.raw_json.data).length) {
      leftPanel = `<h3>Details</h3>${renderAlertData(a.raw_json.data)}`;
    } else {
      leftPanel = `<h3>Details</h3>
                   <div class="muted small">
                     No log line for this alert (decoder/location:
                     <span class="mono">${escapeHtml(a.location || "—")}</span>).
                     See raw JSON →
                   </div>`;
    }

    const statusMeta = {
      open:           { label: "open",            cls: "muted",   bg: "var(--bg-secondary)" },
      in_progress:    { label: "in progress",     cls: "accent",  bg: "rgba(88,166,255,0.08)" },
      tp_remediated:  { label: "true positive — remediated", cls: "ok", bg: "rgba(63,185,80,0.08)" },
      false_positive: { label: "false positive",  cls: "warn",    bg: "rgba(210,153,34,0.08)" },
      acknowledged:   { label: "acknowledged",    cls: "muted",   bg: "rgba(127,127,127,0.08)" },
    };
    const meta = statusMeta[a.status] || statusMeta.open;
    const ackControls = a.status !== "open"
      ? `<div class="flex-row" style="justify-content:space-between; margin-top:10px; padding:8px; background:${meta.bg}; border-radius:6px">
           <div>
             <span class="badge ${meta.cls}">${meta.label}</span>
             ${a.acked_at ? `<span class="muted small">at ${fmt.ts(a.acked_at)}</span>` : ""}
             ${a.ack_notes ? `<div class="small" style="margin-top:4px">${escapeHtml(a.ack_notes)}</div>` : ""}
           </div>
           <button class="ghost small" data-set-status="open" data-aid="${a.id}">Re-open</button>
         </div>`
      : `<div class="flex-col" style="margin-top:10px; gap:6px">
           <input type="text" placeholder="resolution note (optional)" data-status-notes="${a.id}" style="width:100%">
           <div class="flex-row" style="gap:6px; flex-wrap:wrap">
             <button class="small" data-set-status="tp_remediated" data-aid="${a.id}" title="True Positive — Remediated">✓ TP &mdash; Remediated</button>
             <button class="warn small" data-set-status="false_positive" data-aid="${a.id}">✕ False Positive</button>
             <button class="secondary small" data-set-status="acknowledged" data-aid="${a.id}">Acknowledge</button>
             <button class="ghost small" data-set-status="in_progress" data-aid="${a.id}">▸ In Progress</button>
           </div>
         </div>`;

    td.innerHTML = `
      <div class="card-row cols-2">
        <div>${leftPanel}</div>
        <div>
          <h3>Raw JSON</h3>
          <pre class="pre" style="max-height:300px">${escapeHtml(JSON.stringify(a.raw_json, null, 2))}</pre>
        </div>
      </div>
      <div class="related-activity" data-related="${a.id}" style="margin-top:12px">
        <h3 style="margin:0 0 6px">Related activity <span class="muted tiny">(last 24h, by indicator)</span></h3>
        <div class="related-body muted small">Looking for related activity…</div>
      </div>
      <div class="ai-explain" data-alert-id="${a.id}" style="margin-top:12px">
        <div class="flex-row" style="justify-content:space-between">
          <h3 style="margin:0">AI Explanation <span class="muted tiny">(web-enabled)</span></h3>
          <div class="flex-row">
            <button class="small" data-explain="${a.id}">✨ Explain with AI</button>
            <button class="ghost small hidden" data-explain-refresh="${a.id}" title="Regenerate">↻</button>
          </div>
        </div>
        <div class="ai-explain-body markdown" style="margin-top:8px"></div>

        <div class="ai-chat hidden" data-alert-chat-id="${a.id}" style="margin-top:14px">
          <div class="divider"></div>
          <div class="flex-row" style="justify-content:space-between">
            <h3 style="margin:0">Follow-up Questions</h3>
            <button class="ghost small" data-chat-clear="${a.id}">Clear chat</button>
          </div>
          <div class="chat-log" style="margin:8px 0"></div>
          <form class="chat-form" data-chat-form="${a.id}">
            <div class="flex-row">
              <input type="text" placeholder="Ask a follow-up… (e.g. 'is there a public PoC?')" style="flex:1" data-chat-input="${a.id}">
              <button type="submit">Send</button>
            </div>
          </form>
        </div>
      </div>
      ${ackControls}`;
    linkifyIpsInEl(td);
    x.appendChild(td);
    tr.parentNode.insertBefore(x, tr.nextSibling);

    // Related activity (non-AI IOC correlation) — best-effort, loaded async
    loadRelated(a.id, td.querySelector(`[data-related="${a.id}"] .related-body`));

    // AI explain button — fetch (or generate) the explanation
    const aiBtn = td.querySelector(`[data-explain="${a.id}"]`);
    const aiRefresh = td.querySelector(`[data-explain-refresh="${a.id}"]`);
    const aiBody = td.querySelector(`.ai-explain[data-alert-id="${a.id}"] .ai-explain-body`);
    const aiChat = td.querySelector(`.ai-chat[data-alert-chat-id="${a.id}"]`);
    const chatLog = aiChat?.querySelector(".chat-log");
    const chatInput = aiChat?.querySelector(`[data-chat-input="${a.id}"]`);
    const chatForm = aiChat?.querySelector(`[data-chat-form="${a.id}"]`);
    const chatClearBtn = aiChat?.querySelector(`[data-chat-clear="${a.id}"]`);

    let lastHistory = [];   // last rendered chat history (for optimistic appends)
    function renderChatLog(history) {
      if (!chatLog) return;
      lastHistory = history;
      chatLog.innerHTML = history.map(m =>
        `<div class="chat-msg chat-${m.role}">
           <div class="chat-role">${m.role === "user" ? "You" : "Claude"}</div>
           <div class="chat-content markdown">${m.html || escapeHtml(m.content)}</div>
         </div>`
      ).join("");
      linkifyIpsInEl(chatLog);
      chatLog.scrollTop = chatLog.scrollHeight;
    }

    async function loadChat() {
      if (!aiChat) return;
      const r = await api(`/api/alerts/${a.id}/chat`);
      if (r.success) renderChatLog(r.data.history || []);
    }

    chatForm?.addEventListener("submit", async (e) => {
      e.preventDefault();
      const msg = chatInput.value.trim();
      if (!msg) return;
      // Optimistically append the user message + a placeholder to what's
      // already shown (no extra round-trip, no .data.history throw on a failed GET)
      const optimistic = [...lastHistory,
        { role: "user", content: msg, html: escapeHtml(msg) },
        { role: "assistant", content: "...",
          html: `<div class="flex-row"><div class="spinner"></div><span class="muted small">Claude is thinking (web search may take ~30s)…</span></div>` }];
      renderChatLog(optimistic);
      chatInput.value = "";
      chatInput.disabled = true;
      const r = await api(`/api/alerts/${a.id}/chat`, {
        method: "POST",
        body: JSON.stringify({ message: msg }),
      });
      chatInput.disabled = false;
      if (!r.success) {
        toast("Chat failed: " + r.error, "danger");
        // remove the optimistic placeholders
        loadChat();
        return;
      }
      renderChatLog(r.data.history);
      chatInput.focus();
    });

    chatClearBtn?.addEventListener("click", async () => {
      if (!confirm("Clear the follow-up conversation for this alert?")) return;
      await api(`/api/alerts/${a.id}/chat`, { method: "DELETE" });
      loadChat();
    });

    function renderExplanation(d) {
      const cacheMeta = d.from_cache && d.created_at
        ? `<span class="badge muted" title="Cached ${d.created_at}">cached · ${fmt.age(d.created_at)}</span>` : "";
      const modelMeta = d.model ? `<span class="muted tiny"> · ${escapeHtml(d.model)}</span>` : "";
      aiBody.innerHTML = `
        <div class="flex-row" style="margin-bottom:6px">${cacheMeta}${modelMeta}</div>
        ${d.html || ""}`;
      linkifyIpsInEl(aiBody);
      // Reveal the follow-up chat UI now that we have an explanation to anchor on
      aiChat?.classList.remove("hidden");
      loadChat();
    }

    async function loadExplanation(forceRefresh = false) {
      aiBody.innerHTML = `<div class="flex-row"><div class="spinner"></div>
        <span class="muted small">Asking Claude (web-enabled lookup, ~60-90s)…</span></div>`;
      aiBtn.disabled = true;
      // POST always (re)generates server-side; the GET auto-load handles the
      // cached case separately. forceRefresh is kept for call-site clarity.
      const r = await api(`/api/alerts/${a.id}/explain`, { method: "POST" });
      aiBtn.disabled = false;
      if (!r.success) {
        aiBody.innerHTML = `<div class="muted small">⚠ ${escapeHtml(r.error)}</div>`;
        return;
      }
      renderExplanation(r.data);
      aiBtn.textContent = "✨ Re-explain";
      aiRefresh.classList.remove("hidden");
    }

    // Try to load cached explanation immediately (GET — no generation)
    fetch(`/api/alerts/${a.id}/explain`).then(r => r.json()).then(r => {
      if (r.success && r.data.from_cache) {
        renderExplanation(r.data);
        aiBtn.textContent = "✨ Re-explain";
        aiRefresh.classList.remove("hidden");
      }
    }).catch(() => {});

    aiBtn.addEventListener("click", () => loadExplanation(false));
    aiRefresh.addEventListener("click", () => loadExplanation(true));

    // Wire up status-change buttons (resolve as TP/FP/Ack, mark in-progress, re-open)
    td.querySelectorAll(`[data-set-status][data-aid="${a.id}"]`).forEach(b => {
      b.addEventListener("click", async () => {
        const newStatus = b.dataset.setStatus;
        const notes = td.querySelector(`[data-status-notes="${a.id}"]`)?.value || null;
        const r = await api("/api/alerts/" + a.id, {
          method: "PATCH",
          body: JSON.stringify({ status: newStatus, notes }),
        });
        if (r.success) {
          const friendly = { tp_remediated: "Marked TP — remediated",
                             false_positive: "Marked false positive",
                             acknowledged: "Acknowledged",
                             in_progress: "Marked in progress",
                             open: "Re-opened" }[newStatus] || "Updated";
          toast(friendly, "info");
          loadAlerts();
        } else { toast("Failed: " + r.error, "danger"); }
      });
    });
  }

  // Render the `data` field of a Wazuh alert as a readable structure.
  // Known shapes: data.vulnerability (CVE), data.srcip / data.dstip
  // (network), data.title (audit), generic flat key-value.
  function renderAlertData(data) {
    // CVE / vulnerability-detector
    if (data.vulnerability) {
      const v = data.vulnerability;
      const cvss = v.cvss?.cvss3?.base_score || v.score?.base;
      const refs = (v.reference || "").split(",").map(s => s.trim()).filter(Boolean);
      const sevCls = v.severity === "Critical" || v.severity === "High" ? "danger"
                   : v.severity === "Medium" ? "warn" : "muted";
      return `
        <dl class="kv">
          <dt>CVE</dt><dd class="mono"><a href="https://www.cve.org/CVERecord?id=${encodeURIComponent(v.cve || "")}" target="_blank" rel="noopener">${escapeHtml(v.cve || "")}</a></dd>
          <dt>Severity</dt><dd><span class="badge ${sevCls}">${escapeHtml(v.severity || "—")}</span> ${cvss ? `(CVSS ${escapeHtml(String(cvss))})` : ""}</dd>
          <dt>Status</dt><dd>${escapeHtml(v.status || "—")}</dd>
          <dt>Package</dt><dd class="mono">${escapeHtml(v.package?.name || "—")} ${escapeHtml(v.package?.version || "")} <span class="muted">${escapeHtml(v.package?.architecture || "")}</span></dd>
          ${v.published ? `<dt>Published</dt><dd>${escapeHtml(v.published.slice(0,10))}</dd>` : ""}
          ${v.updated ? `<dt>Updated</dt><dd>${escapeHtml(v.updated.slice(0,10))}</dd>` : ""}
        </dl>
        ${v.rationale ? `<div style="margin-top:8px"><strong>Rationale:</strong><div class="small">${escapeHtml(v.rationale)}</div></div>` : ""}
        ${refs.length ? `<div style="margin-top:8px"><strong>References:</strong>${refs.map(r => `<div class="tiny mono"><a href="${escapeHtml(safeUrl(r))}" target="_blank" rel="noopener">${escapeHtml(r)}</a></div>`).join("")}</div>` : ""}
      `;
    }

    // Generic shallow key-value (skip nested objects)
    const flat = Object.entries(data).filter(([_, v]) => typeof v !== "object" || v === null);
    const nested = Object.entries(data).filter(([_, v]) => typeof v === "object" && v !== null);
    let html = "";
    if (flat.length) {
      html += `<dl class="kv">${flat.map(([k, v]) =>
        `<dt>${escapeHtml(k)}</dt><dd class="mono small">${escapeHtml(String(v))}</dd>`).join("")}</dl>`;
    }
    if (nested.length) {
      html += nested.map(([k, v]) =>
        `<div style="margin-top:8px"><strong>${escapeHtml(k)}:</strong>
         <pre class="pre" style="max-height:200px">${escapeHtml(JSON.stringify(v, null, 2))}</pre></div>`).join("");
    }
    return html || `<div class="muted small">(empty)</div>`;
  }

  function alertsPage(d) { alertsState.page = Math.max(1, alertsState.page + d); loadAlerts(); }

  function exportAlerts() {
    const params = new URLSearchParams(Object.fromEntries(
      Object.entries(alertFiltersFromUi()).filter(([_, v]) => v && v !== "0")));
    window.location = "/api/alerts/export?" + params.toString();
  }

  async function syncAlerts() {
    toast("Syncing from Wazuh…", "info");
    const r = await api("/api/alerts/sync", { method: "POST" });
    if (r.success) {
      toast(`Inserted ${r.data.inserted} new alerts (fetched ${r.data.fetched}).`, "info");
      loadAlerts();
    } else { toast("Sync failed: " + r.error, "danger"); }
  }

  // ===== OSINT ==============================================================

  let currentIoc = null;

  async function initOsint(ioc) {
    initThemePicker();
    if (ioc) {
      currentIoc = ioc;
      const d = await api("/api/osint/detect?ioc=" + encodeURIComponent(ioc));
      if (d.success) document.getElementById("ioc-type").textContent = d.data.type;
      loadReferences(ioc);
    }
  }

  function osintNavigate() {
    const v = document.getElementById("ioc-input").value.trim();
    if (v) window.location.href = "/osint?ioc=" + encodeURIComponent(v);
  }

  function copyIoc() {
    if (!currentIoc) return;
    navigator.clipboard.writeText(currentIoc).then(() => toast("Copied", "info"));
  }

  async function osintRun(source) {
    if (!currentIoc) { toast("No IOC selected", "warn"); return; }
    const panel = document.querySelector(`.osint-panel[data-source="${source}"] .result`);
    panel.innerHTML = `<div class="flex-row"><div class="spinner"></div><span class="muted small">Looking up…</span></div>`;
    const r = await api(`/api/osint/${source}?ioc=${encodeURIComponent(currentIoc)}`);
    renderOsintResult(source, r);
  }

  async function osintRunAll() {
    if (!currentIoc) { toast("No IOC selected", "warn"); return; }
    ["virustotal", "abuseipdb", "urlscan"].forEach(s => {
      const p = document.querySelector(`.osint-panel[data-source="${s}"] .result`);
      p.innerHTML = `<div class="flex-row"><div class="spinner"></div><span class="muted small">Looking up…</span></div>`;
    });
    const r = await api(`/api/osint/all?ioc=${encodeURIComponent(currentIoc)}`);
    if (!r.success) { toast("Lookup failed", "danger"); return; }
    for (const [src, body] of Object.entries(r.data.results)) {
      renderOsintResult(src, body);
    }
  }

  function renderOsintResult(source, r) {
    const panel = document.querySelector(`.osint-panel[data-source="${source}"] .result`);
    if (!r.success) {
      panel.innerHTML = `<div class="muted small">⚠ ${escapeHtml(r.error || "lookup failed")}</div>`;
      return;
    }
    const d = r.data || {};
    const cacheBadge = r.from_cache
      ? `<span class="badge muted" title="Cached ${r.cached_at}">cached · ${fmt.age(r.cached_at)}</span>` : "";

    if (source === "virustotal") {
      if (d.not_found) {
        panel.innerHTML = `<div class="muted small">Not found in VT. ${cacheBadge}</div>`;
        return;
      }
      panel.innerHTML = `
        ${cacheBadge}
        <div class="value mono" style="font-size:26px; margin:6px 0">${escapeHtml(d.detection)}</div>
        <dl class="kv">
          <dt>Malicious</dt><dd>${escapeHtml(d.malicious)}</dd>
          <dt>Suspicious</dt><dd>${escapeHtml(d.suspicious)}</dd>
          <dt>Harmless</dt><dd>${escapeHtml(d.harmless)}</dd>
          <dt>Undetected</dt><dd>${escapeHtml(d.undetected)}</dd>
          ${d.country ? `<dt>Country</dt><dd>${escapeHtml(d.country)}</dd>` : ""}
          ${d.as_owner ? `<dt>ASN</dt><dd>${escapeHtml(d.as_owner)}</dd>` : ""}
          ${d.categories?.length ? `<dt>Categories</dt><dd>${d.categories.map(c => escapeHtml(c)).join(", ")}</dd>` : ""}
          ${d.last_analysis_date ? `<dt>Last analysed</dt><dd>${escapeHtml(new Date(d.last_analysis_date * 1000).toISOString().slice(0,19))}</dd>` : ""}
        </dl>
        <p><a href="${escapeHtml(safeUrl(d.report_url))}" target="_blank" rel="noopener">Open in VT →</a></p>`;
    } else if (source === "abuseipdb") {
      const c = d.abuse_confidence ?? 0;
      const cls = c >= 75 ? "high" : c >= 25 ? "med" : "low";
      panel.innerHTML = `
        ${cacheBadge}
        <div class="conf ${cls}" style="font-size:22px; padding:4px 14px; margin:6px 0">${escapeHtml(c)}% abuse</div>
        <dl class="kv">
          ${d.country_code ? `<dt>Country</dt><dd>${escapeHtml(d.country_code)} — ${escapeHtml(d.country_name || "")}</dd>` : ""}
          ${d.isp ? `<dt>ISP</dt><dd>${escapeHtml(d.isp)}</dd>` : ""}
          ${d.usage_type ? `<dt>Usage</dt><dd>${escapeHtml(d.usage_type)}</dd>` : ""}
          ${d.domain ? `<dt>Domain</dt><dd>${escapeHtml(d.domain)}</dd>` : ""}
          <dt>Total reports</dt><dd>${fmt.int(d.total_reports)}</dd>
          ${d.last_reported_at ? `<dt>Last report</dt><dd>${escapeHtml(d.last_reported_at.replace("T", " ").slice(0, 19))}</dd>` : ""}
          ${d.is_tor ? `<dt>TOR</dt><dd>yes</dd>` : ""}
          ${d.is_whitelisted ? `<dt>Whitelisted</dt><dd>yes</dd>` : ""}
        </dl>
        <p><a href="${escapeHtml(safeUrl(d.report_url))}" target="_blank" rel="noopener">Open in AbuseIPDB →</a></p>`;
    } else if (source === "urlscan") {
      if (!d.found) {
        panel.innerHTML = `<div class="muted small">No prior scans found. ${cacheBadge}</div>`;
        return;
      }
      panel.innerHTML = `
        ${cacheBadge}
        <dl class="kv">
          <dt>Verdict</dt><dd>${d.verdict === "malicious" ? '<span class="badge danger">malicious</span>' : '<span class="badge ok">clean</span>'}</dd>
          ${d.score != null ? `<dt>Score</dt><dd>${escapeHtml(d.score)}</dd>` : ""}
          ${d.scan_date ? `<dt>Scan date</dt><dd>${escapeHtml(d.scan_date.slice(0, 19))}</dd>` : ""}
          ${d.page_url ? `<dt>Page URL</dt><dd class="mono tiny">${escapeHtml(d.page_url)}</dd>` : ""}
          ${d.page_ip ? `<dt>Page IP</dt><dd>${ipLink(d.page_ip)}</dd>` : ""}
          ${d.categories?.length ? `<dt>Categories</dt><dd>${d.categories.map(c => escapeHtml(c)).join(", ")}</dd>` : ""}
        </dl>
        ${d.screenshot && safeUrl(d.screenshot) ? `<img src="${escapeHtml(safeUrl(d.screenshot))}" style="max-width:100%; border:1px solid var(--border); border-radius:6px; margin-top:8px">` : ""}
        ${d.scan_url && safeUrl(d.scan_url) ? `<p><a href="${escapeHtml(safeUrl(d.scan_url))}" target="_blank" rel="noopener">Open full scan →</a></p>` : ""}`;
    }
  }

  async function loadReferences(ioc) {
    const r = await api("/api/osint/references?ioc=" + encodeURIComponent(ioc));
    const host = document.getElementById("ioc-refs");
    if (!host) return;
    if (!r.success) { host.innerHTML = `<div class="muted small">${r.error}</div>`; return; }
    const d = r.data;
    let html = `<div class="card-row cols-2">`;
    html += `<div><h3>Alerts (${d.alerts.length})</h3>`;
    if (d.alerts.length) {
      html += `<table class="data"><tbody>`;
      d.alerts.forEach(a => {
        html += `<tr><td class="mono small">${fmt.ts(a.timestamp)}</td>
                     <td>${escapeHtml(a.agent_name || "")}</td>
                     <td><a href="/alerts?rule_id=${encodeURIComponent(a.rule_id)}">${escapeHtml(a.rule_id)}</a></td>
                     <td>${escapeHtml(fmt.short(a.rule_description, 60))}</td></tr>`;
      });
      html += `</tbody></table>`;
    } else { html += `<div class="muted small">None</div>`; }
    html += `</div><div><h3>Briefings (${d.briefings.length})</h3>`;
    if (d.briefings.length) {
      html += `<ul>`;
      d.briefings.forEach(b => {
        html += `<li><a href="/briefings#${b.id}">${b.date} (${b.type})</a></li>`;
      });
      html += `</ul>`;
    } else { html += `<div class="muted small">None</div>`; }
    html += `</div></div>`;
    host.innerHTML = html;
  }

  // ===== FP MANAGER =========================================================

  async function initFp() {
    initThemePicker();
    await loadFps();
  }

  async function loadFps() {
    const [list, xml] = await Promise.all([
      api("/api/fp/list"),
      api("/api/fp/rules-xml"),
    ]);
    const tbody = document.querySelector("#fp-table tbody");
    tbody.innerHTML = "";
    const fps = list.success ? list.data : [];
    const parsed = (xml.success && xml.data.parsed) || [];

    // Merge what's in DB with what's actually in local_rules.xml
    const dbByRid = Object.fromEntries(fps.map(f => [f.wazuh_rule_id, f]));
    parsed.forEach(p => {
      const db = dbByRid[p.wazuh_rule_id];
      const tr = el("tr");
      tr.innerHTML = `
        <td class="mono">${escapeHtml(p.wazuh_rule_id)}</td>
        <td class="mono">${escapeHtml(p.rule_id)}</td>
        <td>${p.agent_name ? escapeHtml(p.agent_name) : "<em class='muted'>all</em>"}</td>
        <td>${escapeHtml(p.description)}</td>
        <td class="muted small">${db ? fmt.ts(db.created_at) : "—"}</td>
        <td class="mono right">${db ? fmt.int(db.alert_count) : 0}</td>
        <td><button class="danger small" data-fp-id="${db?.id || ''}" data-wid="${escapeHtml(p.wazuh_rule_id)}">Delete</button></td>`;
      tbody.appendChild(tr);
    });
    tbody.querySelectorAll("button[data-fp-id]").forEach(b => {
      b.addEventListener("click", () => deleteFp(b.dataset.fpId, b.dataset.wid));
    });

    const host = document.getElementById("fp-banner-host");
    if (!xml.success) {
      host.innerHTML = `<div class="banner warn">Cannot read <code>local_rules.xml</code>: ${escapeHtml(xml.error)}</div>`;
    } else {
      host.innerHTML = "";
    }
    document.getElementById("fp-raw").textContent =
      xml.success ? xml.data.xml : "";
  }

  function fpRefresh() { loadFps(); }

  function fpOpenAdd() {
    const html = `
      <h2>Add Suppression</h2>
      <div class="flex-col">
        <div>
          <label>Wazuh Rule ID to Suppress</label>
          <input type="text" id="fp-rid" placeholder="e.g. 510" autofocus>
          <div class="muted small" id="fp-rid-desc">Enter a rule ID to look up its description.</div>
        </div>
        <div>
          <label>Agent Scope</label>
          <select id="fp-agent">
            <option value="">All agents</option>
          </select>
        </div>
        <div>
          <label>Reason / Description (required)</label>
          <textarea id="fp-desc" placeholder="Why is this rule being suppressed?"></textarea>
        </div>
        <div>
          <label>Live XML Preview</label>
          <pre class="pre" id="fp-preview" style="min-height:80px">—</pre>
        </div>
      </div>
      <div class="actions">
        <button class="ghost" onclick="SOC.closeModal()">Cancel</button>
        <button onclick="SOC.fpSubmit()">Apply & Restart Wazuh</button>
      </div>`;
    openModal(html, { onMount: () => {
      // populate agents
      api("/api/hosts").then(h => {
        if (!h.success) return;
        const sel = document.getElementById("fp-agent");
        h.data.filter(x => x.hostname).forEach(host => {
          const o = document.createElement("option");
          o.value = host.hostname;
          o.textContent = `${host.hostname} (${host.ip})`;
          sel.appendChild(o);
        });
      });
      const debouncedLookup = debounce(fpLookupAndPreview, 400);
      ["fp-rid","fp-agent","fp-desc"].forEach(id => {
        document.getElementById(id).addEventListener("input", debouncedLookup);
      });
    }});
  }

  function debounce(fn, ms) {
    let t; return (...args) => { clearTimeout(t); t = setTimeout(() => fn(...args), ms); };
  }

  async function fpLookupAndPreview() {
    const rid = document.getElementById("fp-rid").value.trim();
    const agent = document.getElementById("fp-agent").value;
    const desc = document.getElementById("fp-desc").value.trim();
    const ridDesc = document.getElementById("fp-rid-desc");

    if (rid) {
      const r = await api("/api/fp/rule-lookup?rule_id=" + encodeURIComponent(rid));
      if (r.success) {
        ridDesc.textContent = r.data.description
          ? `Level ${r.data.level}: ${r.data.description}`
          : "Rule not seen in alerts yet — proceed if you're sure.";
      }
    }
    if (rid && desc) {
      const r = await api("/api/fp/preview", { method: "POST",
        body: JSON.stringify({ rule_id: rid, agent_name: agent, description: desc }),
      });
      document.getElementById("fp-preview").textContent =
        r.success ? r.data.snippet : ("⚠ " + r.error);
    }
  }

  async function fpSubmit() {
    const rid = document.getElementById("fp-rid").value.trim();
    const agent = document.getElementById("fp-agent").value;
    const desc = document.getElementById("fp-desc").value.trim();
    if (!rid || !desc) { toast("Rule ID and description required", "warn"); return; }
    toast("Writing rule, verifying, restarting Wazuh…", "info");
    const r = await api("/api/fp/add", { method: "POST",
      body: JSON.stringify({ rule_id: rid, agent_name: agent, description: desc }),
    });
    if (r.success) {
      toast("Suppression applied. Wazuh restarted.", "info");
      closeModal(); loadFps();
    } else { toast("Failed: " + r.error, "danger"); }
  }

  async function deleteFp(id, wid) {
    if (!confirm(`Delete suppression for Wazuh rule ${wid}? This restarts wazuh-manager.`)) return;
    let r;
    if (id) {
      r = await api("/api/fp/" + id, { method: "DELETE" });
    } else {
      toast("This suppression isn't tracked in DB — manual edit required.", "warn");
      return;
    }
    if (r.success) { toast("Deleted.", "info"); loadFps(); }
    else { toast("Delete failed: " + r.error, "danger"); }
  }

  // ===== ACTIONS KANBAN =====================================================

  async function initActions() {
    initThemePicker();
    actionsLoad();
    // simple drag-drop
    document.querySelectorAll(".kanban-cards").forEach(col => {
      col.addEventListener("dragover", e => { e.preventDefault(); });
      col.addEventListener("drop", e => {
        e.preventDefault();
        const id = e.dataTransfer.getData("text/plain");
        const status = col.dataset.drop;
        api("/api/actions/" + id, { method: "PATCH",
          body: JSON.stringify({ status }) }).then(() => actionsLoad());
      });
    });
  }

  async function actionsLoad() {
    const priority = document.getElementById("a-priority").value;
    const from = document.getElementById("a-from").value;
    const to = document.getElementById("a-to").value;
    const params = new URLSearchParams();
    if (priority) params.set("priority", priority);
    if (from) params.set("date_from", from);
    if (to) params.set("date_to", to);
    const [list, stats] = await Promise.all([
      api("/api/actions?" + params.toString()),
      api("/api/actions/stats"),
    ]);
    if (!list.success) return;

    const cols = { open: [], in_progress: [], resolved: [] };
    // Bucket any unknown status into "open" rather than silently dropping it.
    list.data.forEach(a => (cols[a.status] || cols.open).push(a));

    document.getElementById("kc-open").textContent = cols.open.length;
    document.getElementById("kc-inprog").textContent = cols.in_progress.length;
    document.getElementById("kc-resolved").textContent = cols.resolved.length;

    document.querySelectorAll(".kanban-col").forEach(c => {
      const status = c.dataset.status;
      const host = c.querySelector(".kanban-cards");
      host.innerHTML = "";
      cols[status].forEach(a => host.appendChild(actionCard(a)));
    });

    if (stats.success) {
      const avg = Object.fromEntries(
        stats.data.avg_resolution_hours.map(r => [r.priority, r.avg_hours]));
      document.getElementById("as-p1").textContent = avg.P1 ? avg.P1.toFixed(1) : "—";
      document.getElementById("as-p2").textContent = avg.P2 ? avg.P2.toFixed(1) : "—";
      document.getElementById("as-p3").textContent = avg.P3 ? avg.P3.toFixed(1) : "—";
      const wk = stats.data.this_week.find(r => r.status === "resolved");
      document.getElementById("as-wk").textContent = wk ? wk.n : 0;
    }
  }

  function ageHours(iso) {
    // Reuse parseUtc so timestamps that already carry a numeric offset
    // (e.g. +00:00) aren't double-suffixed into an Invalid Date → NaN.
    const t = parseUtc(iso);
    if (!t || isNaN(t)) return 0;
    return (Date.now() - t.getTime()) / 3600000;
  }

  function actionCard(a) {
    const card = el("div", { className: `kanban-card`, draggable: "true",
                             dataset: { id: a.id }});
    const ageH = ageHours(a.created_at);
    let overdue = "";
    if (a.status !== "resolved") {
      if (a.priority === "P1" && ageH > 24)   overdue = "overdue p1";
      else if (a.priority === "P2" && ageH > 168) overdue = "overdue p2";
      else if (a.priority === "P3" && ageH > 720) overdue = "overdue p3";
    }
    if (overdue) card.classList.add(...overdue.split(" "));
    card.innerHTML = `
      <div class="flex-row" style="justify-content:space-between">
        <span class="badge ${a.priority.toLowerCase()}">${a.priority}</span>
        <span class="tiny muted">${fmt.age(a.created_at)}</span>
      </div>
      <div style="margin-top:6px">${escapeHtml(fmt.short(stripBold(a.description), 220))}</div>
      <div class="meta">
        <a class="muted" href="/briefings">${a.briefing_date}</a>
        <select class="status-pick" data-id="${a.id}" style="min-width:120px">
          <option value="open"        ${a.status === "open" ? "selected" : ""}>Open</option>
          <option value="in_progress" ${a.status === "in_progress" ? "selected" : ""}>In Progress</option>
          <option value="resolved"    ${a.status === "resolved" ? "selected" : ""}>Resolved</option>
        </select>
      </div>`;
    card.addEventListener("dragstart", e => {
      e.dataTransfer.setData("text/plain", String(a.id));
      card.classList.add("dragging");
    });
    card.addEventListener("dragend", () => card.classList.remove("dragging"));
    card.addEventListener("click", e => {
      if (e.target.tagName === "SELECT" || e.target.tagName === "A") return;
      actionDetail(a);
    });
    card.querySelector(".status-pick").addEventListener("change", e => {
      e.stopPropagation();
      api("/api/actions/" + a.id, { method: "PATCH",
        body: JSON.stringify({ status: e.target.value })}).then(() => actionsLoad());
    });
    return card;
  }

  function actionDetail(a) {
    openModal(`
      <h2><span class="badge ${a.priority.toLowerCase()}">${a.priority}</span>
          Action from ${a.briefing_date}</h2>
      <p>${escapeHtml(a.description)}</p>
      <div class="muted small">Source: <a href="/briefings">${escapeHtml(a.source_briefing)}</a></div>
      <div class="divider"></div>
      <label>Resolution notes</label>
      <textarea id="a-notes">${escapeHtml(a.resolution_notes || "")}</textarea>
      <div class="actions">
        <button class="ghost" onclick="SOC.closeModal()">Close</button>
        <button onclick="SOC.actionResolve(${a.id})">Mark Resolved</button>
      </div>
    `);
  }

  async function actionResolve(id) {
    const notes = document.getElementById("a-notes").value;
    const r = await api("/api/actions/" + id, { method: "PATCH",
      body: JSON.stringify({ status: "resolved", notes })});
    if (r.success) { toast("Resolved.", "info"); closeModal(); actionsLoad(); }
  }

  // ===== HOSTS ==============================================================

  async function initHosts() {
    initThemePicker();
    await loadHosts();
  }

  async function loadHosts() {
    const r = await api("/api/hosts");
    if (!r.success) return;
    const tbody = document.querySelector("#hosts-table tbody");
    tbody.innerHTML = "";
    r.data.forEach(h => {
      const tr = el("tr");
      tr.innerHTML = `
        <td class="mono">${escapeHtml(h.ip)}</td>
        <td><input class="inline-edit" data-id="${h.id}" data-field="hostname" value="${escapeHtml(h.hostname || "")}"></td>
        <td><input class="inline-edit" data-id="${h.id}" data-field="role" value="${escapeHtml(h.role || "")}"></td>
        <td class="mono">${escapeHtml(h.agent_id || "—")}</td>
        <td><span class="dot ${h.agent_status || "no_agent"}"></span>${escapeHtml(h.agent_status || "—")}</td>
        <td class="muted small">${h.last_seen ? fmt.age(h.last_seen) : "—"}</td>
        <td class="mono right">${fmt.int(h.alert_count_7d)}</td>
        <td><input class="inline-edit" data-id="${h.id}" data-field="notes" value="${escapeHtml(h.notes || "")}"></td>
        <td>
          <button class="ghost small" data-host="${h.id}">Alerts</button>
          <button class="danger small" data-del="${h.id}">×</button>
        </td>`;
      tbody.appendChild(tr);
    });

    tbody.querySelectorAll(".inline-edit").forEach(inp => {
      inp.addEventListener("change", () => {
        api("/api/hosts/" + inp.dataset.id, { method: "PATCH",
          body: JSON.stringify({ [inp.dataset.field]: inp.value })})
          .then(r => r.success && toast("Saved", "info"));
      });
    });
    tbody.querySelectorAll("[data-host]").forEach(b =>
      b.addEventListener("click", () => hostsAlerts(b.dataset.host)));
    tbody.querySelectorAll("[data-del]").forEach(b =>
      b.addEventListener("click", () => {
        if (!confirm("Delete this host from the inventory?")) return;
        api("/api/hosts/" + b.dataset.del, { method: "DELETE" }).then(() => loadHosts());
      }));
  }

  async function hostsAlerts(hid) {
    const r = await api("/api/hosts/" + hid + "/alerts");
    if (!r.success) return;
    let html = `<h2>Last alerts</h2>`;
    if (!r.data.length) html += `<div class="muted">No alerts.</div>`;
    else {
      html += `<div class="alert-feed">`;
      r.data.forEach(a => html += `<div class="alert-row ${sevClass(a.rule_level)}">
        <span class="ts">${fmt.ts(a.timestamp)}</span>
        <span class="agent">${escapeHtml(a.agent_name || "—")}</span>
        <span class="level">${a.rule_level}</span>
        <span class="desc">${escapeHtml(fmt.short(a.rule_description, 200))}</span></div>`);
      html += `</div>`;
    }
    openSidePanel(html);
  }

  async function hostsRefresh() {
    toast("Refreshing agent status…", "info");
    const r = await api("/api/hosts/refresh", { method: "POST" });
    if (r.success) { toast("Updated " + r.data.updated + " hosts.", "info"); loadHosts(); }
    else { toast("Refresh failed: " + r.error, "danger"); }
  }

  function hostsOpenAdd() {
    openModal(`
      <h2>Add Host</h2>
      <div class="flex-col">
        <div><label>IP</label><input id="h-ip" placeholder="10.0.0.X"></div>
        <div><label>Hostname</label><input id="h-host"></div>
        <div><label>Role</label><input id="h-role"></div>
        <div><label>Notes</label><textarea id="h-notes"></textarea></div>
      </div>
      <div class="actions">
        <button class="ghost" onclick="SOC.closeModal()">Cancel</button>
        <button onclick="SOC.hostsSubmit()">Save</button>
      </div>
    `);
  }

  async function hostsSubmit() {
    const ip = document.getElementById("h-ip").value.trim();
    if (!ip) { toast("IP required", "warn"); return; }
    const r = await api("/api/hosts", { method: "POST", body: JSON.stringify({
      ip,
      hostname: document.getElementById("h-host").value.trim(),
      role: document.getElementById("h-role").value.trim(),
      notes: document.getElementById("h-notes").value.trim(),
    })});
    if (r.success) { toast("Added.", "info"); closeModal(); loadHosts(); }
    else { toast(r.error, "danger"); }
  }

  // ===== THREAT INTEL =======================================================

  let tiTab = "dns";

  async function initThreatIntel(tab) {
    initThemePicker();
    tiTab = tab || "dns";
    const showTab = () => {
      document.querySelectorAll("#ti-tabs button").forEach(x => x.classList.toggle("active", x.dataset.tab === tiTab));
      document.getElementById("ti-dns").classList.toggle("hidden", tiTab !== "dns");
      document.getElementById("ti-unifi").classList.toggle("hidden", tiTab !== "unifi");
      document.getElementById("ti-mitre")?.classList.toggle("hidden", tiTab !== "mitre");
      if (tiTab === "dns") loadDns();
      else if (tiTab === "unifi") loadUnifi();
      else if (tiTab === "mitre") loadMitre();
    };
    document.querySelectorAll("#ti-tabs button").forEach(b => b.addEventListener("click", () => {
      tiTab = b.dataset.tab;
      showTab();
    }));
    showTab();
    document.getElementById("dns-filter").addEventListener("change", renderDns);
    document.getElementById("dns-client").addEventListener("input", debounce(renderDns, 200));
  }

  async function loadMitre() {
    const r = await api("/api/mitre/summary?days=7");
    if (!r.success) return;
    const d = r.data;
    const meta = document.getElementById("mitre-meta");
    if (meta) meta.textContent =
      `${fmt.int(d.alerts_with_mitre)} alerts with ATT&CK mapping in the last ${d.days} days`;
    const rowHtml = (label, count) =>
      `<tr><td><a href="/alerts?mitre=${encodeURIComponent(label)}">${escapeHtml(label)}</a></td>
           <td class="right mono">${fmt.int(count)}</td></tr>`;
    const fill = (id, items) => {
      const body = document.querySelector(`#${id} tbody`);
      if (!body) return;
      body.innerHTML = items.length
        ? items.map(t => rowHtml(t.name, t.count)).join("")
        : `<tr><td colspan="2" class="muted small">No ATT&CK data in window.</td></tr>`;
    };
    fill("mitre-tactics", d.tactics || []);
    fill("mitre-techniques", d.techniques || []);
  }

  let dnsData = null;
  async function loadDns() {
    const r = await api("/api/dns/today");
    if (!r.success) return;
    dnsData = r.data;
    renderDns();
  }

  function renderDns() {
    if (!dnsData) return;
    document.getElementById("dns-q").textContent = fmt.int(dnsData.total_queries);
    document.getElementById("dns-b").textContent = fmt.int(dnsData.blocked_queries);
    const rate = dnsData.total_queries
      ? ((dnsData.blocked_queries * 100 / dnsData.total_queries).toFixed(1) + "%")
      : "—";
    document.getElementById("dns-r").textContent = rate;
    document.getElementById("dns-updated").textContent =
      dnsData.updated_at ? `updated ${fmt.age(dnsData.updated_at)}` : "never synced";

    const filter = document.getElementById("dns-filter").value;
    const clientFilter = document.getElementById("dns-client").value.trim();

    const fillDomTbl = (id, rows) => {
      const tbody = document.querySelector(`#${id} tbody`);
      tbody.innerHTML = "";
      rows.forEach(r => {
        const tr = el("tr");
        tr.innerHTML = `<td class="mono small">${escapeHtml(r.domain)}</td>
                        <td class="right mono">${fmt.int(r.count)}</td>`;
        tbody.appendChild(tr);
      });
    };
    fillDomTbl("dns-top-queried", dnsData.top_queried || []);
    fillDomTbl("dns-top-blocked", dnsData.top_blocked || []);

    const cbody = document.querySelector("#dns-clients tbody");
    cbody.innerHTML = "";
    let clients = dnsData.per_client || [];
    if (filter === "blocked") clients = clients.filter(c => c.blocked > 0);
    if (clientFilter) clients = clients.filter(c => c.client.includes(clientFilter));
    clients.slice(0, 30).forEach(c => {
      const tr = el("tr");
      tr.innerHTML = `<td class="mono">${ipLink(c.client)}</td>
                      <td>${escapeHtml(c.hostname || "")}</td>
                      <td class="right mono">${fmt.int(c.queries)}</td>
                      <td class="right mono">${fmt.int(c.blocked)}</td>`;
      cbody.appendChild(tr);
    });

    const labels = (dnsData.hourly || []).map(h => String(h.hour).padStart(2, "0"));
    const queries = (dnsData.hourly || []).map(h => h.queries);
    const blocked = (dnsData.hourly || []).map(h => h.blocked);
    drawChart("chart-hourly", {
      type: "bar",
      data: {
        labels,
        datasets: [
          { label: "Allowed", data: queries.map((q, i) => q - blocked[i]),
            backgroundColor: getCssVar("--accent-secondary"), stack: "x" },
          { label: "Blocked", data: blocked,
            backgroundColor: getCssVar("--danger"), stack: "x" },
        ],
      },
      options: { scales: { x: { stacked: true }, y: { stacked: true } },
                 plugins: { legend: { display: true } } },
    });
  }

  async function dnsSync() {
    toast("Pulling AdGuard query log…", "info");
    const r = await api("/api/dns/sync?days=7", { method: "POST" });
    if (r.success) { toast("DNS sync complete.", "info"); loadDns(); }
    else { toast("DNS sync failed: " + r.error, "danger"); }
  }

  async function loadUnifi() {
    const [recent, top] = await Promise.all([
      api("/api/unifi/recent"), api("/api/unifi/top-sources"),
    ]);
    if (recent.success) {
      const tbody = document.querySelector("#unifi-events tbody");
      tbody.innerHTML = "";
      recent.data.forEach(a => {
        const srcMatch = (a.full_log || "").match(/\bsrc=([0-9.]+)|\bSRC=([0-9.]+)/i);
        const src = srcMatch ? (srcMatch[1] || srcMatch[2]) : "";
        const tr = el("tr");
        tr.innerHTML = `
          <td class="mono small">${fmt.ts(a.timestamp)}</td>
          <td>${escapeHtml(a.agent_name || "")}</td>
          <td>${src ? ipLink(src) : ""}</td>
          <td>${escapeHtml(fmt.short(a.rule_description, 80))}</td>
          <td class="mono">${a.rule_level}</td>`;
        tbody.appendChild(tr);
      });
    }
    if (top.success) {
      const tbody = document.querySelector("#unifi-top tbody");
      tbody.innerHTML = "";
      if (!top.data.length) tbody.innerHTML = `<tr><td colspan=2 class="muted">No external source IPs detected.</td></tr>`;
      top.data.forEach(t => {
        const tr = el("tr");
        tr.innerHTML = `<td>${ipLink(t.ip)}</td><td class="right mono">${fmt.int(t.count)}</td>`;
        tbody.appendChild(tr);
      });
      // Geo description from cache
      buildGeoDescription(top.data.map(t => t.ip));
    }
  }

  async function buildGeoDescription(ips) {
    const host = document.getElementById("unifi-geo");
    if (!ips.length) { host.innerHTML = "<div class='muted small'>No IPs.</div>"; return; }
    // Use cached AbuseIPDB data only — no network call
    const all = await Promise.all(ips.map(ip =>
      fetch("/api/osint/abuseipdb?ioc=" + encodeURIComponent(ip)).then(r => r.json()).catch(() => null)));
    const countries = {};
    all.forEach(r => {
      if (r && r.success && r.from_cache && r.data?.country_code) {
        countries[r.data.country_code] = (countries[r.data.country_code] || 0) + 1;
      }
    });
    if (!Object.keys(countries).length) {
      host.innerHTML = "<div class='muted small'>No AbuseIPDB cache data. Investigate IPs via OSINT to populate.</div>";
      return;
    }
    host.innerHTML = Object.entries(countries)
      .sort((a, b) => b[1] - a[1])
      .map(([c, n]) => `<span class="badge muted" style="margin-right:6px">${c} × ${n}</span>`)
      .join("");
  }

  // ===== SETTINGS ===========================================================

  async function initSettings() {
    initThemePicker();    // wires every .theme-swatch[data-theme="..."]
    await Promise.all([
      loadHostConfig(), loadHomeApi(),
      loadKeys(), loadPipeline(), loadWazuhStatus(),
      loadWebhooks(), loadAiUsage(), loadBackupConfig(), loadBackupHistory(),
      loadUsers(), loadAuditLog(),
    ]);
  }

  // ----- Home consumer API -----------------------------------------------

  async function loadHomeApi() {
    const r = await api("/api/settings/home-api");
    if (!r.success) return;
    const d = r.data;
    const host = document.getElementById("home-api-status");
    if (host) {
      host.innerHTML = d.configured
        ? `<div><span class="badge ok">enabled</span> token set · ····${escapeHtml(d.last4 || "")}</div>`
        : `<div><span class="badge muted">disabled</span> no token — /api/home/* returns 403</div>`;
    }
    const mut = document.getElementById("home-api-mutations");
    if (mut) {
      mut.checked = !!d.mutations_enabled;
      mut.onchange = async () => {
        const r = await api("/api/settings/home-api/mutations", {
          method: "POST", body: JSON.stringify({ enabled: mut.checked }) });
        toast(r.success ? `Mutations ${mut.checked ? "enabled" : "disabled"}` : r.error,
              r.success ? "info" : "danger");
      };
    }
  }

  async function homeApiGenerate() {
    if (!confirm("Generate a new token? Any existing consumer using the old token will stop working until updated.")) return;
    const r = await api("/api/settings/home-api/token", { method: "POST" });
    if (!r.success) { toast(r.error, "danger"); return; }
    const reveal = document.getElementById("home-api-token-reveal");
    reveal.classList.remove("hidden");
    reveal.innerHTML = `
      <div class="banner warn">
        <div style="flex:1">
          <strong>Copy this token now — it won't be shown again:</strong>
          <pre class="pre" style="margin-top:6px; user-select:all">${escapeHtml(r.data.token)}</pre>
          <div class="tiny muted">Send it from your consumer as <code>X-HomeSOC-Token: &lt;token&gt;</code>
          (or <code>?token=</code> on the SSE <code>/api/home/events</code> stream).</div>
        </div>
      </div>`;
    loadHomeApi();
  }

  async function homeApiClear() {
    if (!confirm("Disable the home API by clearing the token? /api/home/* will return 403 until you set a new one.")) return;
    const r = await api("/api/settings/home-api/token", { method: "DELETE" });
    if (r.success) {
      toast("Home API disabled.", "info");
      document.getElementById("home-api-token-reveal").classList.add("hidden");
      loadHomeApi();
    } else toast(r.error, "danger");
  }

  // ----- Host config -----------------------------------------------------

  const HOST_FIELDS = [
    { group: "Wazuh manager (alerts, agents, FP suppressions)", fields: [
      { key: "wazuh_host", label: "Host / IP", placeholder: "wazuh-manager.local" },
      { key: "wazuh_user", label: "User",       placeholder: "wazuh" },
    ]},
    { group: "AdGuard Home host (DNS deep-dive)", fields: [
      { key: "adguard_host", label: "Host / IP", placeholder: "adguard.local" },
      { key: "adguard_user", label: "User",      placeholder: "root" },
      { key: "adguard_querylog_path", label: "Querylog path",
        placeholder: "/opt/AdGuardHome/data/querylog.json", wide: true },
    ]},
    { group: "SIEM pipeline / Claude CLI host (auto-explain, daily briefings)", fields: [
      { key: "claudedev_host", label: "Host / IP",   placeholder: "siem-host.local" },
      { key: "claudedev_user", label: "User",        placeholder: "dev" },
      { key: "siem_scripts_dir", label: "Scripts directory",
        placeholder: "/opt/siem/scripts", wide: true },
      { key: "claude_cli_path", label: "Claude CLI binary path",
        placeholder: "/usr/local/bin/claude", wide: true },
    ]},
    { group: "SSH credentials", fields: [
      { key: "ssh_key_path", label: "Private key path (used for all outbound SSH)",
        placeholder: "/opt/dashboard/.ssh/id_ed25519", wide: true },
    ]},
  ];

  async function loadHostConfig() {
    const r = await api("/api/host-config");
    if (!r.success) return;
    const host = document.getElementById("host-config-form");
    if (!host) return;
    host.innerHTML = "";
    HOST_FIELDS.forEach(group => {
      const g = el("div", { className: "card", style: "padding:10px; margin:0; background:var(--bg-secondary)" });
      g.innerHTML = `<h3 style="margin-bottom:6px">${escapeHtml(group.group)}</h3>`;
      const grid = el("div", { className: "flex-row", style: "gap:8px; flex-wrap:wrap" });
      group.fields.forEach(f => {
        const flex = f.wide ? "flex:1 0 100%" : "flex:1 0 220px";
        grid.innerHTML += `<div style="${flex}">
          <label class="tiny">${escapeHtml(f.label)}</label>
          <input type="text" data-host-key="${f.key}" placeholder="${escapeHtml(f.placeholder)}" value="${escapeHtml(r.data[f.key] || "")}" style="width:100%">
        </div>`;
      });
      g.appendChild(grid);
      host.appendChild(g);
    });
  }

  async function hostConfigSave() {
    const body = {};
    document.querySelectorAll("[data-host-key]").forEach(inp => {
      body[inp.dataset.hostKey] = inp.value.trim();
    });
    const r = await api("/api/host-config", {
      method: "POST", body: JSON.stringify(body),
    });
    if (r.success) {
      toast("Host config saved.", "info");
      document.getElementById("host-config-status").textContent =
        `saved · ${Object.keys(body).length} fields`;
      loadWazuhStatus();    // refresh the connection status panel
    } else {
      toast("Save failed: " + r.error, "danger");
    }
  }

  async function hostConfigTest() {
    const status = document.getElementById("host-config-status");
    status.innerHTML = `<span class="spinner" style="vertical-align:middle"></span> testing…`;
    const r = await api("/api/host-config/test", { method: "POST" });
    if (!r.success) { status.textContent = "test failed: " + r.error; return; }
    const parts = [];
    for (const [name, res] of Object.entries(r.data)) {
      if (!res.configured) parts.push(`<span class="badge muted">${name}: not configured</span>`);
      else if (res.reachable) parts.push(`<span class="badge ok">${name}: reachable</span>`);
      else parts.push(`<span class="badge danger" title="${escapeHtml(res.stderr || '')}">${name}: unreachable</span>`);
    }
    status.innerHTML = parts.join(" ");
  }

  // ----- Users -----------------------------------------------------------

  async function loadUsers() {
    const r = await api("/api/users");
    if (!r.success) return;
    const tbody = document.querySelector("#users-table tbody");
    tbody.innerHTML = "";
    r.data.forEach(u => {
      const tr = el("tr");
      const status = u.disabled ? '<span class="badge muted">disabled</span>' : '<span class="badge ok">active</span>';
      tr.innerHTML = `
        <td><strong>${escapeHtml(u.username)}</strong></td>
        <td><span class="badge accent">${escapeHtml(u.role)}</span></td>
        <td class="muted small">${u.last_login_at ? fmt.age(u.last_login_at) : "never"}</td>
        <td>${status}</td>
        <td class="flex-row" style="gap:4px">
          <button class="ghost small" data-pw="${u.id}" data-name="${escapeHtml(u.username)}">Reset PW</button>
          <button class="ghost small" data-toggle="${u.id}" data-disabled="${u.disabled ? 1 : 0}">${u.disabled ? "Enable" : "Disable"}</button>
          <button class="danger small" data-del="${u.id}" data-name="${escapeHtml(u.username)}">×</button>
        </td>`;
      tbody.appendChild(tr);
    });
    tbody.querySelectorAll("[data-pw]").forEach(b => b.addEventListener("click", async () => {
      const pw = prompt(`New password for ${b.dataset.name} (min 8 chars):`);
      if (!pw) return;
      const r = await api("/api/users/" + b.dataset.pw, {
        method: "PATCH", body: JSON.stringify({ password: pw }) });
      toast(r.success ? "Password updated." : r.error, r.success ? "info" : "danger");
    }));
    tbody.querySelectorAll("[data-toggle]").forEach(b => b.addEventListener("click", async () => {
      const disabled = b.dataset.disabled === "1";
      await api("/api/users/" + b.dataset.toggle, {
        method: "PATCH", body: JSON.stringify({ disabled: !disabled }) });
      loadUsers();
    }));
    tbody.querySelectorAll("[data-del]").forEach(b => b.addEventListener("click", async () => {
      if (!confirm(`Delete user ${b.dataset.name}?`)) return;
      const r = await api("/api/users/" + b.dataset.del, { method: "DELETE" });
      if (r.success) { toast("User deleted.", "info"); loadUsers(); }
      else toast(r.error, "danger");
    }));
  }

  function userOpenAdd() {
    openModal(`
      <h2>Add User</h2>
      <div class="flex-col">
        <div><label>Username</label><input id="u-name" autofocus></div>
        <div><label>Password (min 8 chars)</label><input type="password" id="u-pw" minlength="8"></div>
        <div><label>Role</label>
          <select id="u-role"><option value="user">user</option><option value="admin">admin</option></select>
        </div>
      </div>
      <div class="actions">
        <button class="ghost" onclick="SOC.closeModal()">Cancel</button>
        <button onclick="SOC.userSubmit()">Create</button>
      </div>
    `);
  }

  async function userSubmit() {
    const body = {
      username: document.getElementById("u-name").value.trim(),
      password: document.getElementById("u-pw").value,
      role: document.getElementById("u-role").value,
    };
    if (!body.username || body.password.length < 8) {
      toast("Username and 8+ char password required", "warn"); return;
    }
    const r = await api("/api/users", { method: "POST", body: JSON.stringify(body) });
    if (r.success) { toast("User created.", "info"); closeModal(); loadUsers(); }
    else toast(r.error, "danger");
  }

  // ----- Audit log --------------------------------------------------------

  async function loadAuditLog() {
    const r = await api("/api/audit-log?limit=50");
    if (!r.success) return;
    const tbody = document.querySelector("#audit-table tbody");
    tbody.innerHTML = "";
    if (!r.data.length) {
      tbody.innerHTML = `<tr><td colspan="5" class="muted small">No audit entries yet.</td></tr>`;
      return;
    }
    r.data.forEach(a => {
      const tr = el("tr");
      const target = a.target_type ? `${a.target_type}/${a.target_id || ""}` : "—";
      let details = a.details || "";
      try { details = JSON.stringify(JSON.parse(details), null, 0).slice(0, 100); } catch {}
      tr.innerHTML = `
        <td class="mono tiny">${fmt.ts(a.created_at)}</td>
        <td>${escapeHtml(a.username || "—")}</td>
        <td class="mono">${escapeHtml(a.action)}</td>
        <td class="mono tiny">${escapeHtml(target)}</td>
        <td class="tiny muted">${escapeHtml(details)}</td>`;
      tbody.appendChild(tr);
    });
  }

  // ----- Backup ----------------------------------------------------------

  async function loadBackupConfig() {
    const r = await api("/api/backup/nas/config");
    if (!r.success) return;
    if (r.data && r.data.host) {
      document.getElementById("bk-host").value = r.data.host || "";
      document.getElementById("bk-user").value = r.data.user || "";
      document.getElementById("bk-path").value = r.data.remote_path || "";
    }
  }

  async function backupNasSave() {
    const body = {
      host: document.getElementById("bk-host").value.trim(),
      user: document.getElementById("bk-user").value.trim(),
      remote_path: document.getElementById("bk-path").value.trim(),
    };
    if (!body.host || !body.user || !body.remote_path) {
      toast("All three fields required", "warn"); return;
    }
    const r = await api("/api/backup/nas/config", {
      method: "POST", body: JSON.stringify(body),
    });
    if (r.success) toast("NAS target saved.", "info");
    else toast(r.error, "danger");
  }

  async function backupNasClear() {
    if (!confirm("Clear NAS backup target?")) return;
    await api("/api/backup/nas/config", { method: "DELETE" });
    ["bk-host", "bk-user", "bk-path"].forEach(id => document.getElementById(id).value = "");
    toast("Cleared.", "info");
  }

  async function backupNasPush(kind) {
    const status = document.getElementById("bk-status");
    status.innerHTML = `<div class="flex-row"><div class="spinner"></div> Pushing ${kind} backup…</div>`;
    const r = await api("/api/backup/nas/push", {
      method: "POST", body: JSON.stringify({ kind }),
    });
    if (r.success) {
      status.innerHTML = `<span class="badge ok">ok</span> sent ${(r.data.size/1024).toFixed(1)} KB → ${escapeHtml(r.data.destination)}`;
      loadBackupHistory();
    } else {
      status.innerHTML = `<span class="badge danger">fail</span> ${escapeHtml(r.error)}`;
    }
  }

  async function loadBackupHistory() {
    const r = await api("/api/backup/history");
    if (!r.success) return;
    const tbody = document.querySelector("#bk-history tbody");
    tbody.innerHTML = "";
    if (!r.data.length) {
      tbody.innerHTML = `<tr><td colspan="5" class="muted small">No backups yet.</td></tr>`;
      return;
    }
    r.data.forEach(b => {
      const tr = el("tr");
      const okBadge = b.success
        ? '<span class="badge ok">ok</span>'
        : '<span class="badge danger">fail</span>';
      tr.innerHTML = `
        <td class="mono small">${fmt.ts(b.created_at)}</td>
        <td>${b.kind}</td>
        <td class="mono tiny" title="${escapeHtml(b.destination)}">${escapeHtml(fmt.short(b.destination, 40))}</td>
        <td class="mono right">${b.size_bytes ? (b.size_bytes/1024).toFixed(1) + " KB" : "—"}</td>
        <td>${okBadge}${b.error ? ` <span class="tiny muted" title="${escapeHtml(b.error)}">⚠</span>` : ""}</td>`;
      tbody.appendChild(tr);
    });
  }

  // ----- Webhooks --------------------------------------------------------

  async function loadWebhooks() {
    const r = await api("/api/webhooks");
    if (!r.success) return;
    const tbody = document.querySelector("#webhook-table tbody");
    tbody.innerHTML = "";
    if (!r.data.length) {
      tbody.innerHTML = `<tr><td colspan="8" class="muted small">No webhooks configured. Click "Add Webhook" to wire up Mattermost / Slack / Discord.</td></tr>`;
      return;
    }
    r.data.forEach(w => {
      const tr = el("tr");
      tr.innerHTML = `
        <td><strong>${escapeHtml(w.name)}</strong>
            <div class="tiny muted">${escapeHtml(w.url_hint)}</div></td>
        <td>${w.platform}</td>
        <td class="mono right">${w.severity_min}</td>
        <td class="mono right tiny">${w.dedup_minutes}m</td>
        <td>${w.include_ai ? '<span class="badge ok">yes</span>' : '<span class="badge muted">no</span>'}</td>
        <td>${w.enabled ? '<span class="badge ok">on</span>' : '<span class="badge muted">off</span>'}
            ${w.last_error ? `<div class="tiny" style="color:var(--danger)" title="${escapeHtml(w.last_error)}">⚠ last error</div>` : ''}</td>
        <td class="muted small">${w.last_used_at ? fmt.age(w.last_used_at) : '—'}</td>
        <td class="flex-row" style="gap:4px">
          <button class="ghost small" data-wh-test="${w.id}">Test</button>
          <button class="ghost small" data-wh-toggle="${w.id}" data-wh-enabled="${w.enabled ? 1 : 0}">${w.enabled ? "Disable" : "Enable"}</button>
          <button class="danger small" data-wh-del="${w.id}">×</button>
        </td>`;
      tbody.appendChild(tr);
    });
    tbody.querySelectorAll("[data-wh-test]").forEach(b => b.addEventListener("click", async () => {
      toast("Sending test message…", "info");
      const r = await api("/api/webhooks/" + b.dataset.whTest + "/test", { method: "POST" });
      if (r.success && r.data.success) toast("Test delivered ✓", "info");
      else toast("Test failed: " + (r.data?.response || r.error), "danger");
    }));
    tbody.querySelectorAll("[data-wh-toggle]").forEach(b => b.addEventListener("click", async () => {
      const enabled = b.dataset.whEnabled === "1";
      await api("/api/webhooks/" + b.dataset.whToggle, {
        method: "PATCH", body: JSON.stringify({ enabled: !enabled })});
      loadWebhooks();
    }));
    tbody.querySelectorAll("[data-wh-del]").forEach(b => b.addEventListener("click", async () => {
      if (!confirm("Delete this webhook?")) return;
      await api("/api/webhooks/" + b.dataset.whDel, { method: "DELETE" });
      loadWebhooks();
    }));
  }

  function webhookOpenAdd() {
    openModal(`
      <h2>Add Webhook</h2>
      <div class="flex-col">
        <div><label>Name</label><input id="wh-name" placeholder="e.g. SOC Alerts → Mattermost"></div>
        <div><label>Platform</label>
          <select id="wh-platform">
            <option value="mattermost">Mattermost</option>
            <option value="slack">Slack</option>
            <option value="discord">Discord</option>
            <option value="generic">Generic (raw JSON)</option>
          </select>
        </div>
        <div><label>Webhook URL</label><input type="password" id="wh-url" placeholder="https://chat.example.com/hooks/abc123…"></div>
        <div class="flex-row">
          <div style="flex:1"><label>Min Severity (0–15)</label><input type="number" id="wh-sev" value="7" min="0" max="15"></div>
          <div style="flex:1"><label>Dedup Window (mins)</label><input type="number" id="wh-dedup" value="240" min="0" max="10080"></div>
        </div>
        <label><input type="checkbox" id="wh-ai" checked> Include AI explanation in payload (when available)</label>
      </div>
      <div class="actions">
        <button class="ghost" onclick="SOC.closeModal()">Cancel</button>
        <button onclick="SOC.webhookSubmit()">Save</button>
      </div>
    `);
  }

  async function webhookSubmit() {
    const body = {
      name: document.getElementById("wh-name").value.trim(),
      platform: document.getElementById("wh-platform").value,
      url: document.getElementById("wh-url").value.trim(),
      severity_min: parseInt(document.getElementById("wh-sev").value, 10),
      dedup_minutes: parseInt(document.getElementById("wh-dedup").value, 10),
      include_ai: document.getElementById("wh-ai").checked,
    };
    if (!body.name || !body.url) { toast("Name and URL required", "warn"); return; }
    const r = await api("/api/webhooks", { method: "POST", body: JSON.stringify(body) });
    if (r.success) { toast("Webhook added.", "info"); closeModal(); loadWebhooks(); }
    else toast(r.error, "danger");
  }

  // ----- AI usage --------------------------------------------------------

  async function loadAiUsage() {
    const r = await api("/api/ai/usage");
    if (!r.success) return;
    const d = r.data;
    const pct = Math.min(100, Math.round(d.auto_explain_24h / d.daily_cap * 100));
    const cls = pct >= 80 ? "danger" : pct >= 50 ? "warn" : "ok";
    document.getElementById("ai-usage").innerHTML = `
      <dl class="kv">
        <dt>Auto-explain (24h)</dt><dd>
          <strong>${d.auto_explain_24h}</strong> / ${d.daily_cap}
          <span class="badge ${cls}">${pct}%</span>
        </dd>
        <dt>Manual explain</dt><dd>${d.manual_explain_24h}</dd>
        <dt>Follow-up chat</dt><dd>${d.chat_24h}</dd>
      </dl>`;
  }

  async function loadKeys() {
    const r = await api("/api/settings/keys");
    if (!r.success) return;
    const host = document.getElementById("key-rows");
    host.innerHTML = "";
    ["virustotal", "abuseipdb", "urlscan"].forEach(svc => {
      const k = r.data[svc] || {};
      const row = el("div", { className: "flex-row", style: "border-bottom:1px solid var(--border); padding:8px 0" });
      row.innerHTML = `
        <strong style="min-width:120px">${svc}</strong>
        <span class="muted small" style="min-width:120px">${k.configured ? "configured ····" + (k.last4 || "") : "not configured"}</span>
        <input type="password" placeholder="paste key…" style="flex:1" data-key-input="${svc}">
        <button class="small" data-save="${svc}">Save</button>
        <button class="ghost small" data-test="${svc}">Test</button>
        <button class="danger small" data-clear="${svc}">Clear</button>`;
      host.appendChild(row);
    });
    host.querySelectorAll("[data-save]").forEach(b => b.addEventListener("click", async () => {
      const svc = b.dataset.save;
      const v = document.querySelector(`[data-key-input="${svc}"]`).value.trim();
      if (!v) return;
      const r = await api("/api/settings/keys/" + svc, { method: "POST", body: JSON.stringify({ key: v }) });
      if (r.success) { toast(svc + " key saved.", "info"); loadKeys(); }
    }));
    host.querySelectorAll("[data-test]").forEach(b => b.addEventListener("click", async () => {
      const svc = b.dataset.test;
      const r = await fetch("/api/settings/keys/" + svc + "/test", { method: "POST" }).then(r => r.json());
      toast(svc + ": " + (r.success ? `OK (${r.status_code})` : "FAIL — " + (r.error || r.snippet)),
            r.success ? "info" : "danger");
    }));
    host.querySelectorAll("[data-clear]").forEach(b => b.addEventListener("click", async () => {
      if (!confirm("Clear " + b.dataset.clear + " key?")) return;
      await api("/api/settings/keys/" + b.dataset.clear, { method: "DELETE" });
      loadKeys();
    }));
  }

  async function loadPipeline() {
    const r = await api("/api/pipeline/status");
    if (!r.success) return;
    const host = document.getElementById("pipeline-rows");
    host.innerHTML = "";
    [["collect", "Collection", r.data.collect, r.data.next_collect],
     ["analyse", "Analysis", r.data.analyse, r.data.next_analyse]].forEach(([k, label, last, next]) => {
      const row = el("div", { className: "flex-row" });
      row.innerHTML = `
        <strong style="min-width:100px">${label}</strong>
        ${last
          ? `<span class="badge ${last.success ? "ok" : "danger"}">${last.success ? "ok" : "fail"}</span>
             <span class="muted small">${fmt.ts(last.finished_at)}</span>
             ${last.briefing_size ? `<span class="muted small">${fmt.int(last.briefing_size)} chars</span>` : ""}`
          : `<span class="muted small">never run</span>`}
        <span style="flex:1"></span>
        <span class="muted small">next: ${next}</span>`;
      host.appendChild(row);
    });
  }

  async function pipelineRun(kind) {
    document.getElementById("pipeline-output").textContent = "Running " + kind + "…";
    const r = await api("/api/pipeline/run", { method: "POST", body: JSON.stringify({ kind }) });
    if (r.success) {
      document.getElementById("pipeline-output").innerHTML =
        `<strong>${r.data.success ? "OK" : "FAILED"}</strong><pre class="pre">${escapeHtml(r.data.output || "")}</pre>`;
      loadPipeline();
    } else {
      document.getElementById("pipeline-output").textContent = "Failed: " + r.error;
    }
  }

  async function loadWazuhStatus() {
    const r = await api("/api/wazuh/status");
    const host = document.getElementById("wazuh-conn");
    if (!r.success) { host.innerHTML = `<div class="muted small">${r.error}</div>`; return; }
    const d = r.data;
    host.innerHTML = `
      <dl class="kv">
        <dt>SSH</dt><dd>${d.connected
          ? '<span class="badge ok">connected</span>' : '<span class="badge danger">unreachable</span>'}</dd>
        ${d.version ? `<dt>Manager version</dt><dd>${escapeHtml(d.version)}</dd>` : ""}
        ${d.agent_count != null ? `<dt>Agents</dt><dd>${d.agent_count}</dd>` : ""}
        ${d.error ? `<dt>Note</dt><dd class="muted">${escapeHtml(d.error)}</dd>` : ""}
      </dl>`;
  }

  // ===== expose =============================================================

  return {
    initDashboard, initBriefings, initAlerts, initOsint, initFp, initActions,
    initHosts, initThreatIntel, initSettings,
    // dashboard
    quickOsint, calNav,
    // briefings
    syncBriefings,
    // alerts
    applyAlertFilters, clearAlertFilters, alertsPage, exportAlerts, syncAlerts,
    alertsPreset,
    // osint
    osintNavigate, osintRun, osintRunAll, copyIoc,
    // fp
    fpRefresh, fpOpenAdd, fpSubmit,
    // actions
    actionsLoad, actionResolve,
    // hosts
    hostsRefresh, hostsOpenAdd, hostsSubmit,
    // dns
    dnsSync,
    // settings
    pipelineRun, webhookOpenAdd, webhookSubmit,
    backupNasSave, backupNasClear, backupNasPush,
    userOpenAdd, userSubmit,
    hostConfigSave, hostConfigTest,
    homeApiGenerate, homeApiClear,
    // generic
    closeModal, closeSidePanel,
  };
})();
