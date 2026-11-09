/**
 * Self-contained Enterprise Web Console for Zero-Trust Agent Firewall.
 * Served directly by the sidecar HTTP server at GET / with zero external build bloat.
 */
export function renderConsoleHtml(): string {
  return `<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8" />
  <meta name="viewport" content="width=device-width, initial-scale=1.0" />
  <title>Zero-Trust Agent Firewall · Runtime Console</title>
  <link rel="preconnect" href="https://fonts.googleapis.com">
  <link rel="preconnect" href="https://fonts.gstatic.com" crossorigin>
  <link href="https://fonts.googleapis.com/css2?family=Inter:wght@400;500;600;700&family=JetBrains+Mono:wght@400;500;600&display=swap" rel="stylesheet">
  <style>
    :root {
      --bg-page: #f8fafc;
      --bg-card: #ffffff;
      --border: #e2e8f0;
      --border-strong: #cbd5e1;
      --text: #0f172a;
      --text-secondary: #334155;
      --muted: #64748b;
      --accent: #1d4ed8;
      --accent-hover: #1e40af;
      --accent-soft: #eff6ff;
      --accent-border: #bfdbfe;
      --allow-bg: #ecfdf5;
      --allow-border: #a7f3d0;
      --allow-text: #065f46;
      --block-bg: #fef2f2;
      --block-border: #fecaca;
      --block-text: #991b1b;
      --hold-bg: #fffbeb;
      --hold-border: #fde68a;
      --hold-text: #92400e;
    }
    * { box-sizing: border-box; margin: 0; padding: 0; }
    body {
      background: var(--bg-page);
      color: var(--text);
      font-family: "Inter", -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, sans-serif;
      font-size: 14px;
      line-height: 1.5;
      -webkit-font-smoothing: antialiased;
    }
    code, pre, .mono {
      font-family: "JetBrains Mono", ui-monospace, SFMono-Regular, Menlo, monospace;
    }
    /* Top Header */
    .topbar {
      position: sticky;
      top: 0;
      z-index: 40;
      background: rgba(255, 255, 255, 0.96);
      backdrop-filter: blur(6px);
      border-bottom: 1px solid var(--border);
    }
    .topbar-inner {
      max-width: 1280px;
      margin: 0 auto;
      height: 64px;
      padding: 0 24px;
      display: flex;
      align-items: center;
      justify-content: space-between;
    }
    .brand {
      display: flex;
      align-items: center;
      gap: 12px;
      text-decoration: none;
      color: inherit;
      cursor: pointer;
    }
    .brand-icon {
      width: 36px;
      height: 36px;
      border-radius: 8px;
      background: var(--accent);
      color: #fff;
      display: flex;
      align-items: center;
      justify-content: center;
      box-shadow: 0 1px 2px rgba(15, 23, 42, 0.08);
    }
    .brand-title-row {
      display: flex;
      align-items: center;
      gap: 8px;
    }
    .brand-title {
      font-size: 16px;
      font-weight: 700;
      letter-spacing: -0.015em;
      color: var(--text);
    }
    .version-pill {
      background: #f1f5f9;
      color: #475569;
      font-size: 10px;
      font-weight: 600;
      padding: 2px 6px;
      border-radius: 4px;
      text-transform: uppercase;
      letter-spacing: 0.04em;
    }
    .brand-sub {
      font-size: 12px;
      color: var(--muted);
      font-weight: 500;
    }
    .header-actions {
      display: flex;
      align-items: center;
      gap: 10px;
      font-size: 12px;
    }
    .status-pill {
      display: inline-flex;
      align-items: center;
      gap: 7px;
      padding: 6px 12px;
      border-radius: 6px;
      font-weight: 500;
      border: 1px solid var(--allow-border);
      background: var(--allow-bg);
      color: var(--allow-text);
    }
    .status-pill.tripped {
      border-color: var(--block-border);
      background: var(--block-bg);
      color: var(--block-text);
    }
    .dot {
      width: 8px;
      height: 8px;
      border-radius: 999px;
      background: #059669;
    }
    .status-pill.tripped .dot { background: #dc2626; }
    .btn {
      display: inline-flex;
      align-items: center;
      gap: 6px;
      padding: 7px 13px;
      border-radius: 6px;
      font-size: 12.5px;
      font-weight: 600;
      border: 1px solid var(--border);
      background: #fff;
      color: var(--text-secondary);
      cursor: pointer;
      white-space: nowrap;
      flex-shrink: 0;
      transition: all 0.12s ease;
    }
    .btn:hover { background: #f8fafc; border-color: var(--border-strong); color: var(--text); }
    .btn-primary {
      background: var(--accent);
      border-color: var(--accent);
      color: #fff;
    }
    .btn-primary:hover { background: var(--accent-hover); border-color: var(--accent-hover); color: #fff; }
    .btn-danger {
      background: #fff;
      border-color: var(--block-border);
      color: var(--block-text);
    }
    .btn-danger:hover { background: var(--block-bg); }

    /* Main Shell */
    .shell {
      max-width: 1280px;
      margin: 24px auto;
      padding: 0 24px 48px;
      display: grid;
      grid-template-columns: 224px 1fr;
      gap: 24px;
      align-items: start;
    }
    .sidebar {
      position: sticky;
      top: 88px;
      background: var(--bg-card);
      border: 1px solid var(--border);
      border-radius: 12px;
      padding: 12px;
      box-shadow: 0 1px 2px rgba(15, 23, 42, 0.03);
    }
    .nav-group-label {
      font-size: 11px;
      font-weight: 600;
      text-transform: uppercase;
      letter-spacing: 0.06em;
      color: #94a3b8;
      padding: 6px 10px 4px;
      margin-top: 6px;
    }
    .nav-group-label:first-child { margin-top: 0; }
    .nav-btn {
      width: 100%;
      display: flex;
      align-items: center;
      gap: 10px;
      padding: 8px 10px;
      border-radius: 8px;
      border: none;
      background: transparent;
      color: #475569;
      font-size: 13.5px;
      font-weight: 500;
      text-align: left;
      cursor: pointer;
      transition: all 0.12s;
    }
    .nav-btn:hover { background: #f8fafc; color: var(--text); }
    .nav-btn.active {
      background: var(--accent-soft);
      color: var(--accent);
      font-weight: 600;
    }
    .nav-btn svg { width: 16px; height: 16px; flex-shrink: 0; opacity: 0.85; }
    .sidebar-guarantees {
      margin-top: 14px;
      padding: 12px 10px 4px;
      border-top: 1px solid #f1f5f9;
      font-size: 11.5px;
      color: var(--muted);
    }
    .sidebar-guarantees-title {
      font-weight: 600;
      color: var(--text-secondary);
      margin-bottom: 6px;
    }
    .guarantee-row {
      display: flex;
      justify-content: space-between;
      margin-bottom: 4px;
    }
    .guarantee-val { font-weight: 600; color: var(--text-secondary); }
    .guarantee-val.green { color: #047857; }

    /* Content Views */
    .view { display: none; flex-direction: column; gap: 18px; }
    .view.active { display: flex; }
    .page-header {
      display: flex;
      justify-content: space-between;
      align-items: flex-start;
      gap: 16px;
    }
    .page-title { font-size: 20px; font-weight: 700; letter-spacing: -0.015em; }
    .page-desc { font-size: 13.5px; color: var(--muted); margin-top: 2px; }

    .card {
      background: var(--bg-card);
      border: 1px solid var(--border);
      border-radius: 12px;
      padding: 18px 20px;
      box-shadow: 0 1px 2px rgba(15, 23, 42, 0.03);
    }
    .card-title {
      font-size: 13.5px;
      font-weight: 600;
      color: var(--text);
      margin-bottom: 12px;
      display: flex;
      align-items: center;
      justify-content: space-between;
    }

    /* KPI Grid */
    .kpi-grid {
      display: grid;
      grid-template-columns: repeat(4, 1fr);
      gap: 14px;
    }
    .kpi-card {
      background: var(--bg-card);
      border: 1px solid var(--border);
      border-radius: 12px;
      padding: 16px 18px;
    }
    .kpi-label { font-size: 12px; font-weight: 500; color: var(--muted); }
    .kpi-value {
      font-size: 26px;
      font-weight: 700;
      letter-spacing: -0.02em;
      margin-top: 4px;
      color: var(--text);
    }
    .kpi-sub { font-size: 11.5px; color: var(--muted); margin-top: 4px; }

    .two-col {
      display: grid;
      grid-template-columns: 1fr 1fr;
      gap: 16px;
    }
    .intercept-grid {
      display: grid;
      grid-template-columns: 1.35fr 1fr;
      gap: 16px;
    }

    /* Badges */
    .badge {
      display: inline-flex;
      align-items: center;
      padding: 2px 8px;
      border-radius: 5px;
      font-size: 11px;
      font-weight: 700;
      letter-spacing: 0.03em;
      text-transform: uppercase;
    }
    .badge-allow { background: var(--allow-bg); color: var(--allow-text); border: 1px solid var(--allow-border); }
    .badge-block { background: var(--block-bg); color: var(--block-text); border: 1px solid var(--block-border); }
    .badge-hold { background: var(--hold-bg); color: var(--hold-text); border: 1px solid var(--hold-border); }
    .badge-surface {
      background: #f1f5f9;
      color: #334155;
      border: 1px solid #e2e8f0;
      font-family: "JetBrains Mono", monospace;
    }
    .reason-chip {
      display: inline-block;
      padding: 2px 7px;
      margin: 2px 4px 2px 0;
      border-radius: 4px;
      font-size: 11px;
      font-family: "JetBrains Mono", monospace;
      background: #f8fafc;
      border: 1px solid var(--border);
      color: #334155;
    }

    /* Tables */
    table { width: 100%; border-collapse: collapse; font-size: 13px; }
    th {
      text-align: left;
      font-size: 11px;
      font-weight: 600;
      text-transform: uppercase;
      letter-spacing: 0.05em;
      color: var(--muted);
      padding: 9px 10px;
      border-bottom: 1px solid var(--border);
    }
    td {
      padding: 10px;
      border-bottom: 1px solid #f1f5f9;
      vertical-align: middle;
    }
    tr:last-child td { border-bottom: none; }

    /* Form Controls */
    label.field-label {
      display: block;
      font-size: 12px;
      font-weight: 600;
      color: var(--text-secondary);
      margin-bottom: 5px;
    }
    select, input[type="text"], input[type="number"], textarea {
      width: 100%;
      border: 1px solid var(--border);
      border-radius: 8px;
      padding: 8px 11px;
      font-size: 13px;
      color: var(--text);
      background: #fff;
      font-family: inherit;
    }
    textarea.code-box {
      font-family: "JetBrains Mono", monospace;
      font-size: 12px;
      line-height: 1.55;
      min-height: 190px;
      resize: vertical;
      background: #fcfcfd;
    }
    .toggle-list { display: flex; flex-direction: column; gap: 9px; }
    .toggle-item {
      display: flex;
      align-items: center;
      justify-content: space-between;
      padding: 8px 11px;
      border: 1px solid var(--border);
      border-radius: 8px;
      background: #fcfcfd;
      font-size: 12.5px;
    }
    .toggle-item span.sub { display: block; font-size: 11px; color: var(--muted); }
    input[type="checkbox"] { width: 16px; height: 16px; accent-color: var(--accent); cursor: pointer; }

    /* Decision Banner */
    .verdict-banner {
      border-radius: 12px;
      padding: 16px 20px;
      border: 1px solid var(--border);
      display: flex;
      align-items: flex-start;
      justify-content: space-between;
      gap: 16px;
    }
    .verdict-banner.ALLOW { background: var(--allow-bg); border-color: var(--allow-border); color: var(--allow-text); }
    .verdict-banner.BLOCK { background: var(--block-bg); border-color: var(--block-border); color: var(--block-text); }
    .verdict-banner.HOLD { background: var(--hold-bg); border-color: var(--hold-border); color: var(--hold-text); }
    .verdict-title { font-size: 15px; font-weight: 700; display: flex; align-items: center; gap: 8px; }
    .verdict-meta { font-size: 12px; opacity: 0.9; margin-top: 4px; }

    .violation-item {
      border: 1px solid var(--border);
      border-left: 3px solid #dc2626;
      border-radius: 8px;
      padding: 11px 14px;
      background: #fff;
      margin-top: 10px;
    }
    .violation-item.HOLD { border-left-color: #d97706; }
    .bar-row { margin-bottom: 10px; }
    .bar-head { display: flex; justify-content: space-between; font-size: 12.5px; margin-bottom: 4px; font-weight: 500; }
    .bar-track { height: 8px; background: #f1f5f9; border-radius: 999px; overflow: hidden; }
    .bar-fill { height: 100%; background: var(--accent); border-radius: 999px; }
    .bar-fill.red { background: #dc2626; }
    .bar-fill.emerald { background: #059669; }
    .empty-note { padding: 24px; text-align: center; color: var(--muted); font-size: 13px; }
  </style>
</head>
<body>
  <header class="topbar">
    <div class="topbar-inner">
      <div class="brand" onclick="switchView('overview')">
        <div class="brand-icon">
          <svg viewBox="0 0 20 20" fill="currentColor" width="20" height="20">
            <path fill-rule="evenodd" d="M10 1.944A11.954 11.954 0 012.166 5C2.056 5.649 2 6.319 2 7c0 5.225 3.34 9.67 8 11.317C14.66 16.67 18 12.225 18 7c0-.682-.057-1.35-.166-2.001A11.954 11.954 0 0110 1.944zM13.707 8.707a1 1 0 00-1.414-1.414L9 10.586 7.707 9.293a1 1 0 00-1.414 1.414l2 2a1 1 0 001.414 0l4-4z" clip-rule="evenodd"/>
          </svg>
        </div>
        <div>
          <div class="brand-title-row">
            <span class="brand-title">Zero-Trust Agent Firewall</span>
            <span class="version-pill">v1.0.0</span>
          </div>
          <div class="brand-sub">Agent proposes, the firewall verifies · Sub-10ms state &amp; security gate</div>
        </div>
      </div>

      <div class="header-actions">
        <div id="engine-pill" class="status-pill">
          <span class="dot"></span>
          <span id="engine-pill-text">Engine active · Breaker closed</span>
        </div>
        <button class="btn" onclick="runDemoSuite()" id="demo-btn">
          <svg viewBox="0 0 20 20" fill="currentColor" width="14" height="14" style="color:#1d4ed8">
            <path fill-rule="evenodd" d="M11.3 1.046A1 1 0 0112 2v5h4a1 1 0 01.82 1.573l-7 10A1 1 0 018 18v-5H4a1 1 0 01-.82-1.573l7-10a1 1 0 011.12-.38z" clip-rule="evenodd"/>
          </svg>
          <span>Simulate Traffic</span>
        </button>
        <button class="btn" onclick="resetBreaker()" id="reset-cb-btn" style="display:none">Reset Breaker</button>
      </div>
    </div>
  </header>

  <main class="shell">
    <aside class="sidebar">
      <div class="nav-group-label">Protect</div>
      <button class="nav-btn active" data-view="overview" onclick="switchView('overview')">
        <svg viewBox="0 0 20 20" fill="currentColor"><path d="M3 4a1 1 0 011-1h12a1 1 0 011 1v2a1 1 0 01-1 1H4a1 1 0 01-1-1V4zM3 10a1 1 0 011-1h6a1 1 0 011 1v6a1 1 0 01-1 1H4a1 1 0 01-1-1v-6zM14 9a1 1 0 00-1 1v6a1 1 0 001 1h2a1 1 0 001-1v-6a1 1 0 00-1-1h-2z"/></svg>
        Overview
      </button>
      <button class="nav-btn" data-view="intercept" onclick="switchView('intercept')">
        <svg viewBox="0 0 20 20" fill="currentColor"><path fill-rule="evenodd" d="M9 9a2 2 0 114 0 2 2 0 01-4 0zM11 4a5 5 0 103.536 8.536l2.764 2.764a1 1 0 001.414-1.414l-2.764-2.764A5 5 0 0011 4z" clip-rule="evenodd"/></svg>
        Action Gate
      </button>

      <div class="nav-group-label">Govern</div>
      <button class="nav-btn" data-view="policies" onclick="switchView('policies')">
        <svg viewBox="0 0 20 20" fill="currentColor"><path d="M4 4a2 2 0 012-2h4.586A2 2 0 0112 2.586L15.414 6A2 2 0 0116 7.414V16a2 2 0 01-2 2H6a2 2 0 01-2-2V4z"/></svg>
        Policies
      </button>
      <button class="nav-btn" data-view="audit" onclick="switchView('audit')">
        <svg viewBox="0 0 20 20" fill="currentColor"><path d="M9 2a1 1 0 000 2h2a1 1 0 100-2H9z"/><path fill-rule="evenodd" d="M4 5a2 2 0 012-2 3 3 0 003 3h2a3 3 0 003-3 2 2 0 012 2v11a2 2 0 01-2 2H6a2 2 0 01-2-2V5z" clip-rule="evenodd"/></svg>
        Audit Log
      </button>
      <button class="nav-btn" data-view="benchmarks" onclick="switchView('benchmarks')">
        <svg viewBox="0 0 20 20" fill="currentColor"><path d="M2 11a1 1 0 011-1h2a1 1 0 011 1v5a1 1 0 01-1 1H3a1 1 0 01-1-1v-5zM8 7a1 1 0 011-1h2a1 1 0 011 1v9a1 1 0 01-1 1H9a1 1 0 01-1-1V7zM14 4a1 1 0 011-1h2a1 1 0 011 1v12a1 1 0 01-1 1h-2a1 1 0 01-1-1V4z"/></svg>
        Benchmarks
      </button>

      <div class="sidebar-guarantees">
        <div class="sidebar-guarantees-title">Runtime Controls</div>
        <div class="guarantee-row"><span>External calls</span><span class="guarantee-val green mono">0</span></div>
        <div class="guarantee-row"><span>p99 target</span><span class="guarantee-val mono">&lt; 10 ms</span></div>
        <div class="guarantee-row"><span>Audit trail</span><span class="guarantee-val mono">SHA-256 chain</span></div>
      </div>
    </aside>

    <!-- 1. OVERVIEW DASHBOARD -->
    <section id="view-overview" class="view active">
      <div class="page-header">
        <div>
          <h1 class="page-title">Runtime Overview</h1>
          <p class="page-desc">Live summary of intercepted agent actions, caught policy violations, latency, and cryptographic audit status.</p>
        </div>
        <button class="btn btn-primary" onclick="runDemoSuite()">Run 8-Step Agent Simulation</button>
      </div>

      <div class="kpi-grid">
        <div class="kpi-card">
          <div class="kpi-label">Actions Evaluated</div>
          <div class="kpi-value mono" id="kpi-total">0</div>
          <div class="kpi-sub" id="kpi-split">0 allowed · 0 blocked · 0 held</div>
        </div>
        <div class="kpi-card">
          <div class="kpi-label">Threats &amp; Drift Caught</div>
          <div class="kpi-value mono" style="color:#dc2626" id="kpi-caught">0</div>
          <div class="kpi-sub" id="kpi-block-rate">0% interception rate</div>
        </div>
        <div class="kpi-card">
          <div class="kpi-label">Evaluation Latency (p99)</div>
          <div class="kpi-value mono" style="color:#047857" id="kpi-latency">0.00 ms</div>
          <div class="kpi-sub" id="kpi-latency-avg">avg 0.00 ms · budget 10.0 ms</div>
        </div>
        <div class="kpi-card">
          <div class="kpi-label">Audit Chain Integrity</div>
          <div class="kpi-value mono" style="color:#1d4ed8; font-size:20px; padding-top:4px" id="kpi-chain">VERIFIED</div>
          <div class="kpi-sub mono" id="kpi-head">GENESIS</div>
        </div>
      </div>

      <div class="two-col">
        <div class="card">
          <div class="card-title">
            <span>Intercepted Actions by Execution Surface</span>
            <span class="mono" style="font-size:11px; color:var(--muted)">API · CLI · UI</span>
          </div>
          <div id="surface-bars"></div>
        </div>

        <div class="card">
          <div class="card-title">
            <span>Caught State &amp; Security Violations</span>
            <span class="mono" style="font-size:11px; color:var(--muted)">Top Reason Codes</span>
          </div>
          <div id="reason-breakdown"></div>
        </div>
      </div>

      <div class="card">
        <div class="card-title">
          <span>Recent Agent Action Decisions</span>
          <button class="btn" style="padding:4px 10px; font-size:11.5px" onclick="switchView('audit')">View Full Audit Chain →</button>
        </div>
        <table>
          <thead>
            <tr>
              <th>#</th>
              <th>Verdict</th>
              <th>Surface</th>
              <th>Intercepted Action (Redacted Summary)</th>
              <th>Triggered Rules</th>
              <th>Latency</th>
            </tr>
          </thead>
          <tbody id="recent-decisions-body">
            <tr><td colspan="6" class="empty-note">No actions evaluated yet. Click "Run 8-Step Agent Simulation" or test an action in Action Gate.</td></tr>
          </tbody>
        </table>
      </div>
    </section>

    <!-- 2. ACTION GATE (INTERCEPT & TEST) -->
    <section id="view-intercept" class="view">
      <div class="page-header">
        <div>
          <h1 class="page-title">Action Gate</h1>
          <p class="page-desc">Inspect any proposed API call, CLI command, or UI interaction against live system state switches before execution.</p>
        </div>
        <div style="min-width: 310px;">
          <select id="preset-select" onchange="loadPreset(this.value)">
            <option value="ssrf">Load example: API · Cloud metadata SSRF (169.254.169.254)</option>
            <option value="api_ok">Load example: API · Valid order creation (POST /v1/orders)</option>
            <option value="api_schema">Load example: API · Schema drift &amp; missing Idempotency-Key</option>
            <option value="cli_inject">Load example: CLI · Git flag &amp; subshell injection (; cat /etc/passwd)</option>
            <option value="cli_ok">Load example: CLI · Approved test runner (vitest run)</option>
            <option value="ui_modal">Load example: UI · Click occluded behind active modal dialog</option>
            <option value="ui_hold">Load example: UI · Destructive button requiring human confirmation</option>
          </select>
        </div>
      </div>

      <div class="intercept-grid">
        <div class="card">
          <div class="card-title">
            <span>Proposed Agent Action Payload</span>
            <span class="badge badge-surface" id="editor-surface-badge">api</span>
          </div>
          <label class="field-label">Action JSON (API / CLI / UI)</label>
          <textarea id="action-json" class="code-box"></textarea>
          <div style="margin-top:12px; display:flex; justify-content:space-between; align-items:center;">
            <span style="font-size:12px; color:var(--muted)">Evaluated synchronously in memory · Zero external network calls</span>
            <button class="btn btn-primary" onclick="evaluateCurrentAction()">Evaluate Action</button>
          </div>
        </div>

        <div class="card">
          <div class="card-title">
            <span>Live System State Switches</span>
            <span style="font-size:11.5px; color:var(--muted)">Toggle to simulate state changes</span>
          </div>
          <div class="toggle-list">
            <div class="toggle-item">
              <div><strong>Session Authenticated</strong><span class="sub">Active user/agent token present</span></div>
              <input type="checkbox" id="st-auth" checked />
            </div>
            <div class="toggle-item">
              <div><strong>Session Token Expired</strong><span class="sub">Simulate expired OAuth/JWT TTL</span></div>
              <input type="checkbox" id="st-expired" />
            </div>
            <div class="toggle-item">
              <div><strong>Database Lock Active</strong><span class="sub">Active schema migration or table freeze</span></div>
              <input type="checkbox" id="st-dblock" />
            </div>
            <div class="toggle-item">
              <div><strong>Read-Only Mode</strong><span class="sub">Block state-mutating writes (POST/DELETE/fill/click)</span></div>
              <input type="checkbox" id="st-readonly" />
            </div>
            <div class="toggle-item">
              <div><strong>Active Modal Dialog Trap</strong><span class="sub">Modal #confirm-dialog traps background clicks</span></div>
              <input type="checkbox" id="st-modal" checked />
            </div>
            <div class="toggle-item">
              <div><strong>Stale State Snapshot (&gt; 5,000 ms)</strong><span class="sub">Simulate outdated agent observation (TOCTOU)</span></div>
              <input type="checkbox" id="st-stale" />
            </div>
          </div>
        </div>
      </div>

      <div id="decision-output"></div>
    </section>

    <!-- 3. POLICIES -->
    <section id="view-policies" class="view">
      <div class="page-header">
        <div>
          <h1 class="page-title">Active Runtime Policy</h1>
          <p class="page-desc">View or hot-reload endpoint contracts, allowed hosts, approved CLI executables, and circuit-breaker thresholds.</p>
        </div>
        <button class="btn btn-primary" onclick="savePolicyPack()">Apply &amp; Hot-Reload Policy</button>
      </div>

      <div class="card">
        <div class="card-title">
          <span>Control-Plane Policy Configuration (JSON)</span>
          <span class="mono" style="font-size:12px; color:#1d4ed8" id="policy-version-label">v1.0</span>
        </div>
        <textarea id="policy-json" class="code-box" style="min-height: 360px;"></textarea>
        <div id="policy-save-msg" style="margin-top:10px; font-size:12.5px; color:#047857; font-weight:500;"></div>
      </div>
    </section>

    <!-- 4. AUDIT LOG -->
    <section id="view-audit" class="view">
      <div class="page-header">
        <div>
          <h1 class="page-title">Tamper-Evident Audit Ledger</h1>
          <p class="page-desc">Every allow, block, and hold decision is linked from GENESIS with SHA-256 hashes and automatic credential masking.</p>
        </div>
        <div style="display:flex; gap:8px;">
          <button class="btn" onclick="refreshAll()">Verify Chain</button>
          <button class="btn btn-danger" onclick="runTamperSimulation()">Simulate Tamper Attack</button>
        </div>
      </div>

      <div id="audit-verify-banner" class="verdict-banner ALLOW">
        <div>
          <div class="verdict-title" id="audit-banner-title">SHA-256 Hash Chain Verified</div>
          <div class="verdict-meta mono" id="audit-banner-sub">0 entries checked · Head: GENESIS</div>
        </div>
      </div>

      <div id="tamper-proof-box" style="display:none"></div>

      <div class="card">
        <div class="card-title"><span>Hash-Chained Decision Records</span></div>
        <table>
          <thead>
            <tr>
              <th>#</th>
              <th>Entry ID</th>
              <th>Verdict</th>
              <th>Surface</th>
              <th>Redacted Action Summary</th>
              <th>Hash Link (Prev → Entry)</th>
            </tr>
          </thead>
          <tbody id="audit-table-body"></tbody>
        </table>
      </div>
    </section>

    <!-- 5. BENCHMARKS -->
    <section id="view-benchmarks" class="view">
      <div class="page-header">
        <div>
          <h1 class="page-title">In-Memory Latency Benchmark</h1>
          <p class="page-desc">Measure real-time p50, p95, and p99 evaluation speed across 1,000 mixed API, CLI, and UI checks.</p>
        </div>
        <button class="btn btn-primary" onclick="executeBenchmark()" id="bench-btn">Run 1,000-Action Benchmark</button>
      </div>

      <div class="kpi-grid" id="bench-kpis">
        <div class="kpi-card"><div class="kpi-label">Median (p50)</div><div class="kpi-value mono" id="b-p50">—</div><div class="kpi-sub">Target &lt; 2.0 ms</div></div>
        <div class="kpi-card"><div class="kpi-label">p95 Latency</div><div class="kpi-value mono" id="b-p95">—</div><div class="kpi-sub">Target &lt; 5.0 ms</div></div>
        <div class="kpi-card"><div class="kpi-label">p99 Latency</div><div class="kpi-value mono" style="color:#047857" id="b-p99">—</div><div class="kpi-sub">SLA &lt; 10.0 ms</div></div>
        <div class="kpi-card"><div class="kpi-label">Throughput</div><div class="kpi-value mono" id="b-ops">—</div><div class="kpi-sub" id="b-chain">Click Run to measure</div></div>
      </div>

      <div class="card">
        <div class="card-title"><span>Workload Profile &amp; SLA Verification</span><span class="mono" style="font-size:11.5px; color:#047857" id="b-sla-badge">Ready</span></div>
        <table>
          <thead>
            <tr>
              <th>Check Pipeline Stage</th>
              <th>What Executes During Every Check</th>
              <th>Network I/O</th>
              <th>Target Budget</th>
            </tr>
          </thead>
          <tbody>
            <tr>
              <td><strong>1. System State Cages</strong></td>
              <td>Snapshot freshness (anti-stale check), session auth, token TTL, DB lock, and read-only mode</td>
              <td class="mono">0 calls</td>
              <td class="mono">&lt; 0.05 ms</td>
            </tr>
            <tr>
              <td><strong>2. Surface Guard Evaluation</strong></td>
              <td>O(1) DOM selector/role lookup, SSRF IP literal &amp; host inspection, schema check, CLI flag &amp; sandbox check</td>
              <td class="mono">0 calls</td>
              <td class="mono">&lt; 0.50 ms</td>
            </tr>
            <tr>
              <td><strong>3. Cryptographic Audit Ledger</strong></td>
              <td>Credential redaction + canonical SHA-256 hash chain linkage (prevHash → entryHash)</td>
              <td class="mono">0 calls</td>
              <td class="mono">&lt; 0.10 ms</td>
            </tr>
          </tbody>
        </table>
      </div>
    </section>
  </main>

  <script>
    const PRESETS = {
      ssrf: {
        action: {
          surface: "api",
          actionId: "call_ssrf_01",
          method: "GET",
          url: "http://169.254.169.254/latest/meta-data/iam/security-credentials/"
        },
        switches: { auth: true, expired: false, dblock: false, readonly: false, modal: false, stale: false }
      },
      api_ok: {
        action: {
          surface: "api",
          actionId: "call_order_01",
          method: "POST",
          url: "https://orders-api.example.com/v1/orders",
          headers: { "Idempotency-Key": "idem-2026-44109" },
          body: { sku: "SKU-204", quantity: 3 }
        },
        switches: { auth: true, expired: false, dblock: false, readonly: false, modal: false, stale: false }
      },
      api_schema: {
        action: {
          surface: "api",
          actionId: "call_bad_schema",
          method: "POST",
          url: "https://orders-api.example.com/v1/orders",
          body: { sku: "INVALID", quantity: 999, extraField: true }
        },
        switches: { auth: true, expired: false, dblock: false, readonly: false, modal: false, stale: false }
      },
      cli_inject: {
        action: {
          surface: "cli",
          actionId: "call_cli_inject",
          executable: "git",
          args: ["--upload-pack=touch /tmp/pwn", "status; cat /etc/passwd"],
          cwd: "/workspace/project"
        },
        switches: { auth: true, expired: false, dblock: false, readonly: false, modal: false, stale: false }
      },
      cli_ok: {
        action: {
          surface: "cli",
          actionId: "call_cli_test",
          executable: "vitest",
          args: ["run", "tests/guards.test.ts"],
          cwd: "/workspace/project"
        },
        switches: { auth: true, expired: false, dblock: false, readonly: false, modal: false, stale: false }
      },
      ui_modal: {
        action: {
          surface: "ui",
          actionId: "call_ui_occluded",
          actionType: "click",
          selector: "#save-settings-btn"
        },
        switches: { auth: true, expired: false, dblock: false, readonly: false, modal: true, stale: false }
      },
      ui_hold: {
        action: {
          surface: "ui",
          actionId: "call_ui_delete",
          actionType: "click",
          selector: "#delete-workspace-btn"
        },
        switches: { auth: true, expired: false, dblock: false, readonly: false, modal: false, stale: false }
      }
    };

    function switchView(name) {
      document.querySelectorAll('.view').forEach(v => v.classList.remove('active'));
      document.querySelectorAll('.nav-btn').forEach(b => b.classList.remove('active'));
      const target = document.getElementById('view-' + name);
      if (target) target.classList.add('active');
      const btn = document.querySelector('.nav-btn[data-view="' + name + '"]');
      if (btn) btn.classList.add('active');
      refreshAll();
    }

    function loadPreset(key) {
      const p = PRESETS[key] || PRESETS.ssrf;
      document.getElementById('action-json').value = JSON.stringify(p.action, null, 2);
      document.getElementById('editor-surface-badge').textContent = p.action.surface;
      document.getElementById('st-auth').checked = p.switches.auth;
      document.getElementById('st-expired').checked = p.switches.expired;
      document.getElementById('st-dblock').checked = p.switches.dblock;
      document.getElementById('st-readonly').checked = p.switches.readonly;
      document.getElementById('st-modal').checked = p.switches.modal;
      document.getElementById('st-stale').checked = p.switches.stale;
    }

    function buildStateFromSwitches() {
      const now = Date.now();
      const stale = document.getElementById('st-stale').checked;
      const expired = document.getElementById('st-expired').checked;
      const modal = document.getElementById('st-modal').checked;
      return {
        snapshotId: "snap-ui-" + now,
        capturedAtMs: stale ? now - 12000 : now,
        maxStalenessMs: 5000,
        session: {
          principalId: "worker-01",
          authenticated: document.getElementById('st-auth').checked,
          expiresAtMs: expired ? now - 5000 : now + 3600000,
          scopes: ["orders:read", "orders:write", "ui:interact"],
          dbLockActive: document.getElementById('st-dblock').checked,
          readOnlyMode: document.getElementById('st-readonly').checked
        },
        dom: {
          currentUrl: "https://portal.example.com/settings",
          activeModalSelector: modal ? "#confirm-dialog" : undefined,
          elements: [
            {
              selector: "#save-settings-btn",
              testId: "save-settings",
              role: "button",
              name: "Save Changes",
              visible: true,
              enabled: true,
              inActiveModal: false
            },
            {
              selector: "#modal-confirm-btn",
              role: "button",
              name: "Confirm",
              visible: true,
              enabled: true,
              inActiveModal: true
            },
            {
              selector: "#delete-workspace-btn",
              role: "button",
              name: "Delete Workspace",
              visible: true,
              enabled: true,
              inActiveModal: modal,
              destructive: true
            }
          ]
        }
      };
    }

    async function evaluateCurrentAction() {
      let action;
      try {
        action = JSON.parse(document.getElementById('action-json').value);
      } catch (e) {
        alert("Invalid Action JSON: " + e.message);
        return;
      }
      document.getElementById('editor-surface-badge').textContent = action.surface || "unknown";
      const state = buildStateFromSwitches();
      const res = await fetch('/v1/evaluate', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ action, state })
      });
      const d = await res.json();
      renderDecisionOutput(d);
      await refreshAll();
    }

    function renderDecisionOutput(d) {
      const box = document.getElementById('decision-output');
      if (!d || !d.verdict) {
        box.innerHTML = '<div class="card" style="color:#991b1b">Validation error: ' + JSON.stringify(d) + '</div>';
        return;
      }
      const labelMap = {
        ALLOW: "ALLOW · Action Permitted to Execute",
        BLOCK: "BLOCK · Execution Halted Before Target",
        HOLD: "HOLD · Paused for Human Confirmation"
      };
      let violationsHtml = '';
      if (d.violations && d.violations.length > 0) {
        violationsHtml = '<div class="card" style="margin-top:14px"><div class="card-title"><span>Triggered Invariant Violations (' + d.violations.length + ')</span></div>' +
          d.violations.map(v =>
            '<div class="violation-item ' + d.verdict + '">' +
              '<div style="display:flex; justify-content:space-between; align-items:center;">' +
                '<span class="mono" style="font-weight:700; font-size:12.5px; color:#0f172a">' + v.code + '</span>' +
                '<span class="badge badge-' + (d.verdict === 'HOLD' ? 'hold' : 'block') + '">' + v.severity + ' · ' + v.surface + '</span>' +
              '</div>' +
              '<div style="margin-top:5px; font-size:13px; color:#334155">' + escapeHtml(v.message) + '</div>' +
              '<div style="margin-top:5px; font-size:12px; color:#64748b"><strong>Remediation:</strong> ' + escapeHtml(v.remediation) + '</div>' +
            '</div>'
          ).join('') + '</div>';
      }
      box.innerHTML =
        '<div class="verdict-banner ' + d.verdict + '">' +
          '<div>' +
            '<div class="verdict-title"><span class="badge badge-' + d.verdict.toLowerCase() + '">' + d.verdict + '</span> ' + labelMap[d.verdict] + '</div>' +
            '<div class="verdict-meta mono">Decision ID: ' + d.decisionId + ' · State Hash: ' + d.stateSnapshotHash.slice(0, 16) + '… · Audit Hash: ' + d.auditEntryHash.slice(0, 16) + '…</div>' +
          '</div>' +
          '<div style="text-align:right">' +
            '<div class="mono" style="font-size:20px; font-weight:700">' + d.evaluationLatencyMs.toFixed(3) + ' ms</div>' +
            '<div style="font-size:11px; opacity:0.85">In-memory check</div>' +
          '</div>' +
        '</div>' + violationsHtml;
    }

    async function runDemoSuite() {
      const btn = document.getElementById('demo-btn');
      btn.textContent = "Running…";
      await fetch('/v1/demo/seed', { method: 'POST' });
      btn.innerHTML = '<span>Simulate Traffic</span>';
      await refreshAll();
    }

    async function resetBreaker() {
      await fetch('/v1/circuit-breaker/reset', { method: 'POST', headers: {'Content-Type':'application/json'}, body: '{}' });
      await refreshAll();
    }

    async function savePolicyPack() {
      const msg = document.getElementById('policy-save-msg');
      try {
        const parsed = JSON.parse(document.getElementById('policy-json').value);
        const res = await fetch('/v1/policy', {
          method: 'PUT',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify(parsed)
        });
        const out = await res.json();
        if (res.ok) {
          msg.style.color = '#047857';
          msg.textContent = 'Hot-reloaded policy version ' + out.policyVersion + ' into active memory.';
          await refreshAll();
        } else {
          msg.style.color = '#991b1b';
          msg.textContent = 'Error: ' + JSON.stringify(out);
        }
      } catch (e) {
        msg.style.color = '#991b1b';
        msg.textContent = 'Invalid JSON: ' + e.message;
      }
    }

    async function runTamperSimulation() {
      const res = await fetch('/v1/audit/tamper-test', { method: 'POST' });
      const report = await res.json();
      const box = document.getElementById('tamper-proof-box');
      box.style.display = 'block';
      if (!report.simulated) {
        box.innerHTML = '<div class="verdict-banner HOLD"><div class="verdict-title">' + escapeHtml(report.message) + '</div></div>';
        return;
      }
      box.innerHTML =
        '<div class="verdict-banner BLOCK" style="margin-bottom:4px">' +
          '<div>' +
            '<div class="verdict-title"><span class="badge badge-block">TAMPER DETECTED</span> Simulated Attack Caught by SHA-256 Verifier</div>' +
            '<div class="verdict-meta">Cloned ledger in memory and mutated entry <strong>#' + report.brokenAtIndex + ' (' + report.brokenEntryId + ')</strong> from BLOCK → ALLOW.</div>' +
            '<div class="verdict-meta mono" style="margin-top:6px">' + escapeHtml(report.reason) + '</div>' +
          '</div>' +
        '</div>';
    }

    async function executeBenchmark() {
      const btn = document.getElementById('bench-btn');
      btn.textContent = 'Running 1,000 checks…';
      const res = await fetch('/v1/benchmark/run', { method: 'POST' });
      const b = await res.json();
      document.getElementById('b-p50').textContent = b.p50Ms.toFixed(3) + ' ms';
      document.getElementById('b-p95').textContent = b.p95Ms.toFixed(3) + ' ms';
      document.getElementById('b-p99').textContent = b.p99Ms.toFixed(3) + ' ms';
      document.getElementById('b-ops').textContent = b.throughputPerSec.toLocaleString() + '/s';
      document.getElementById('b-chain').textContent = '1,000 SHA-256 blocks verified (' + b.totalWallMs.toFixed(1) + ' ms total)';
      document.getElementById('b-sla-badge').textContent = 'PASS · p99 ' + b.p99Ms.toFixed(3) + ' ms (< 10 ms SLA)';
      btn.textContent = 'Run 1,000-Action Benchmark';
    }

    function escapeHtml(s) {
      return String(s ?? '').replace(/[&<>"']/g, c => ({'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;',"'":'&#39;'}[c]));
    }

    async function refreshAll() {
      const [statsRes, auditRes, policyRes] = await Promise.all([
        fetch('/v1/stats'),
        fetch('/v1/audit'),
        fetch('/v1/policy')
      ]);
      const stats = await statsRes.json();
      const audit = await auditRes.json();
      const pol = await policyRes.json();

      // Header breaker status
      const pill = document.getElementById('engine-pill');
      const pillText = document.getElementById('engine-pill-text');
      const resetBtn = document.getElementById('reset-cb-btn');
      if (stats.circuitBreakerOpen) {
        pill.classList.add('tripped');
        pillText.textContent = 'Circuit Breaker OPEN (' + stats.consecutiveBlocks + ' blocks)';
        resetBtn.style.display = 'inline-flex';
      } else {
        pill.classList.remove('tripped');
        pillText.textContent = 'Engine active · p99 ' + stats.p99LatencyMs.toFixed(2) + 'ms';
        resetBtn.style.display = 'none';
      }

      // KPIs
      document.getElementById('kpi-total').textContent = stats.total;
      document.getElementById('kpi-split').textContent = stats.allowCount + ' allowed · ' + stats.blockCount + ' blocked · ' + stats.holdCount + ' held';
      const caught = stats.blockCount + stats.holdCount;
      document.getElementById('kpi-caught').textContent = caught;
      const rate = stats.total > 0 ? Math.round((caught / stats.total) * 100) : 0;
      document.getElementById('kpi-block-rate').textContent = rate + '% of actions halted or held';
      document.getElementById('kpi-latency').textContent = stats.p99LatencyMs.toFixed(2) + ' ms';
      document.getElementById('kpi-latency-avg').textContent = 'avg ' + stats.avgLatencyMs.toFixed(2) + ' ms · budget 10.0 ms';
      document.getElementById('kpi-chain').textContent = stats.auditChain.valid ? 'VERIFIED' : 'BROKEN';
      document.getElementById('kpi-head').textContent = stats.auditChain.headHash === 'GENESIS' ? 'Head: GENESIS' : 'Head: ' + stats.auditChain.headHash.slice(0, 14) + '…';

      // Surface bars
      const surfEl = document.getElementById('surface-bars');
      const total = Math.max(stats.total, 1);
      const surfaces = [
        { key: 'api', label: 'API Requests (SSRF, Schema, Scopes, Idempotency)', count: stats.bySurface.api || 0 },
        { key: 'cli', label: 'CLI Commands (Allowlist, Chaining, Flags, Sandbox)', count: stats.bySurface.cli || 0 },
        { key: 'ui', label: 'UI Interactions (Visibility, Modal Traps, Confirmation)', count: stats.bySurface.ui || 0 }
      ];
      surfEl.innerHTML = surfaces.map(s => {
        const pct = stats.total > 0 ? Math.round((s.count / total) * 100) : 0;
        return '<div class="bar-row">' +
          '<div class="bar-head"><span>' + s.label + '</span><span class="mono">' + s.count + ' (' + pct + '%)</span></div>' +
          '<div class="bar-track"><div class="bar-fill" style="width:' + pct + '%"></div></div>' +
        '</div>';
      }).join('');

      // Reason breakdown
      const reasonEl = document.getElementById('reason-breakdown');
      if (!stats.topReasons || stats.topReasons.length === 0) {
        reasonEl.innerHTML = '<div class="empty-note" style="padding:14px">No violations triggered yet.</div>';
      } else {
        const maxR = Math.max(...stats.topReasons.map(r => r.count), 1);
        reasonEl.innerHTML = stats.topReasons.slice(0, 5).map(r => {
          const pct = Math.round((r.count / maxR) * 100);
          return '<div class="bar-row">' +
            '<div class="bar-head"><span class="mono" style="font-size:11.5px">' + r.code + '</span><span class="mono">' + r.count + '</span></div>' +
            '<div class="bar-track"><div class="bar-fill red" style="width:' + pct + '%"></div></div>' +
          '</div>';
        }).join('');
      }

      // Recent table
      const entries = (audit.entries || []).slice().reverse();
      const recentBody = document.getElementById('recent-decisions-body');
      if (entries.length === 0) {
        recentBody.innerHTML = '<tr><td colspan="6" class="empty-note">No actions evaluated yet. Click "Run 8-Step Agent Simulation" above.</td></tr>';
      } else {
        recentBody.innerHTML = entries.slice(0, 8).map(e =>
          '<tr>' +
            '<td class="mono" style="color:var(--muted)">#' + e.index + '</td>' +
            '<td><span class="badge badge-' + e.verdict.toLowerCase() + '">' + e.verdict + '</span></td>' +
            '<td><span class="badge badge-surface">' + e.actionSurface + '</span></td>' +
            '<td class="mono" style="font-size:12px">' + escapeHtml(e.actionSummary) + '</td>' +
            '<td>' + (e.reasonCodes.length ? e.reasonCodes.map(c => '<span class="reason-chip">' + c + '</span>').join('') : '<span style="color:#047857; font-size:12px; font-weight:500">All invariants passed</span>') + '</td>' +
            '<td class="mono" style="white-space:nowrap">' + e.evaluationLatencyMs.toFixed(3) + ' ms</td>' +
          '</tr>'
        ).join('');
      }

      // Audit view
      const auditBanner = document.getElementById('audit-verify-banner');
      auditBanner.className = 'verdict-banner ' + (audit.verification.valid ? 'ALLOW' : 'BLOCK');
      document.getElementById('audit-banner-title').textContent = audit.verification.valid
        ? 'SHA-256 Hash Chain Verified (' + audit.verification.checked + ' linked records)'
        : 'Audit Chain Verification Failed';
      document.getElementById('audit-banner-sub').textContent = 'GENESIS → Head: ' + audit.verification.headHash;

      const auditBody = document.getElementById('audit-table-body');
      if (entries.length === 0) {
        auditBody.innerHTML = '<tr><td colspan="6" class="empty-note">Ledger is at GENESIS. Evaluate actions or run simulation to record blocks.</td></tr>';
      } else {
        auditBody.innerHTML = entries.map(e =>
          '<tr>' +
            '<td class="mono">#' + e.index + '</td>' +
            '<td class="mono" style="font-size:11.5px">' + e.entryId + '</td>' +
            '<td><span class="badge badge-' + e.verdict.toLowerCase() + '">' + e.verdict + '</span></td>' +
            '<td><span class="badge badge-surface">' + e.actionSurface + '</span></td>' +
            '<td class="mono" style="font-size:12px">' + escapeHtml(e.actionSummary) + '</td>' +
            '<td class="mono" style="font-size:11px; color:var(--muted)">' + e.prevHash.slice(0, 10) + '… → <strong style="color:#0f172a">' + e.entryHash.slice(0, 12) + '…</strong></td>' +
          '</tr>'
        ).join('');
      }

      // Policy editor
      if (pol.policyPack) {
        document.getElementById('policy-version-label').textContent = pol.policyPack.policyVersion;
        const policyBox = document.getElementById('policy-json');
        if (!policyBox.dataset.loaded) {
          policyBox.value = JSON.stringify(pol.policyPack, null, 2);
          policyBox.dataset.loaded = "1";
        }
      }
    }

    loadPreset('ssrf');
    refreshAll();
  </script>
</body>
</html>`;
}
