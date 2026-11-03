import { useState } from "react";
import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import {
  Activity,
  ArrowDownToLine,
  ArrowRight,
  Check,
  ChevronRight,
  Code2,
  FileCode2,
  FolderGit2,
  History,
  LayoutDashboard,
  LockKeyhole,
  LogOut,
  Package,
  Plus,
  Search,
  Settings2,
  Shield,
  ShieldCheck,
  Sparkles,
  Terminal,
  TriangleAlert,
  Upload,
  X,
} from "lucide-react";
import { Cell, Pie, PieChart, ResponsiveContainer, Tooltip } from "recharts";
import { api, download, setToken } from "./api";
import type {
  Dependency,
  Explanation,
  Finding,
  Scan,
  Settings,
  Severity,
} from "./types";

const sections = [
  ["Overview", LayoutDashboard],
  ["Scan Repository", FolderGit2],
  ["Findings Explorer", ShieldCheck],
  ["Vulnerable Dependencies", Package],
  ["AI Remediation", Sparkles],
  ["Scan History", History],
  ["Reports", ArrowDownToLine],
  ["Settings", Settings2],
] as const;
const colors: Record<Severity, string> = {
  critical: "#b64050",
  high: "#df8853",
  medium: "#d8b34f",
  low: "#68a799",
};
const severityOrder: Severity[] = ["critical", "high", "medium", "low"];
function Badge({ value }: { value: string }) {
  return <span className={`badge ${value}`}>{value.replaceAll("-", " ")}</span>;
}
function Empty({ title, detail }: { title: string; detail: string }) {
  return (
    <div className="empty">
      <Shield size={32} />
      <h3>{title}</h3>
      <p>{detail}</p>
    </div>
  );
}
function ErrorNotice({ error }: { error: unknown }) {
  return error ? (
    <div role="alert" className="notice error">
      <TriangleAlert size={17} />
      {error instanceof Error ? error.message : String(error)}
    </div>
  ) : null;
}

export default function App() {
  const [connected, setConnected] = useState(false);
  const [key, setKey] = useState("");
  const [page, setPage] = useState("Overview");
  const [active, setActive] = useState("");
  const [selected, setSelected] = useState<Finding | null>(null);
  const [search, setSearch] = useState("");
  const [severity, setSeverity] = useState("");
  const [language, setLanguage] = useState("");
  const [rule, setRule] = useState("");
  const [notice, setNotice] = useState("");
  const cache = useQueryClient();
  const login = useMutation({
    mutationFn: async () => {
      setToken(key.trim());
      await api<Scan[]>("/scans");
    },
    onSuccess: () => {
      setConnected(true);
      setKey("");
    },
  });
  const scans = useQuery({
    queryKey: ["scans"],
    queryFn: () => api<Scan[]>("/scans"),
    enabled: connected,
    refetchInterval: 3000,
  });
  const current =
    (scans.data ?? []).find((s) => s.id === active) ?? scans.data?.[0];
  const scanId = current?.id;
  const busy = current?.status === "queued" || current?.status === "running";
  const findings = useQuery({
    queryKey: ["findings", scanId, current?.status],
    queryFn: () => api<Finding[]>(`/scans/${scanId}/findings`),
    enabled: connected && !!scanId,
    refetchInterval: busy ? 2500 : false,
  });
  const deps = useQuery({
    queryKey: ["deps", scanId, current?.status],
    queryFn: () => api<Dependency[]>(`/scans/${scanId}/dependencies`),
    enabled: connected && !!scanId,
    refetchInterval: busy ? 3000 : false,
  });
  const settings = useQuery({
    queryKey: ["settings"],
    queryFn: () => api<Settings>("/settings"),
    enabled: connected,
  });
  const start = useMutation({
    mutationFn: (body: object) =>
      api<Scan>("/scans", { method: "POST", body: JSON.stringify(body) }),
    onSuccess: (s) => {
      setActive(s.id);
      setPage("Overview");
      void cache.invalidateQueries({ queryKey: ["scans"] });
    },
  });
  const upload = useMutation({
    mutationFn: (file: File) =>
      api<Scan>("/scans/upload?authorized=true", {
        method: "POST",
        headers: { "Content-Type": "application/zip" },
        body: file,
      }),
    onSuccess: (s) => {
      setActive(s.id);
      setPage("Overview");
      void cache.invalidateQueries({ queryKey: ["scans"] });
    },
  });
  const all = findings.data ?? [];
  const filtered = all.filter(
    (f) =>
      (!severity || f.severity === severity) &&
      (!language || f.language === language) &&
      (!rule || f.rule_id === rule) &&
      `${f.title} ${f.file} ${f.rule_id}`
        .toLowerCase()
        .includes(search.toLowerCase()),
  );
  const counts = current?.summary.severities ?? {
    critical: 0,
    high: 0,
    medium: 0,
    low: 0,
  };
  const chartData = severityOrder.map((s) => ({ name: s, value: counts[s] }));
  const downloadFile = async (format: string) => {
    if (!scanId) return;
    try {
      await download(
        `/scans/${scanId}/report?format=${format}`,
        `reposentinel-report.${format}`,
      );
      setNotice(`${format.toUpperCase()} report downloaded.`);
    } catch (e) {
      setNotice(e instanceof Error ? e.message : "Download failed");
    }
  };

  if (!connected)
    return (
      <div className="login-shell">
        <div className="login-copy">
          <div className="brand">
            <div className="brand-icon">
              <Shield size={24} />
            </div>
            RepoSentinel <span>AI</span>
          </div>
          <div className="eyebrow">SOURCE CODE. CLEARER SIGNALS.</div>
          <h1>
            Security findings,
            <br />
            <em>made understandable.</em>
          </h1>
          <p>
            A focused workspace to scan code, review dependency advisories, and
            turn potential risks into informed decisions.
          </p>
          <div className="login-features">
            <span>
              <Code2 />
              Static analysis
            </span>
            <span>
              <LockKeyhole />
              Secret detection
            </span>
            <span>
              <Sparkles />
              Assisted remediation
            </span>
          </div>
          <small>
            Built for learning. Designed for evidence. Always reviewed by you.
          </small>
        </div>
        <form
          className="login-card"
          onSubmit={(e) => {
            e.preventDefault();
            login.mutate();
          }}
        >
          <span className="round-icon">
            <LockKeyhole />
          </span>
          <h2>Open your workspace</h2>
          <p>Enter your administrator API token to access scans and reports.</p>
          <label htmlFor="token">Workspace token</label>
          <input
            id="token"
            type="password"
            autoComplete="off"
            value={key}
            onChange={(e) => setKey(e.target.value)}
            placeholder="Your RS_API_TOKEN"
            required
            minLength={32}
          />
          <button className="primary" disabled={login.isPending}>
            {login.isPending ? "Connecting…" : "Connect securely"}
            <ArrowRight size={16} />
          </button>
          <ErrorNotice error={login.error} />
          <div className="subtle">
            <ShieldCheck size={15} /> Your token stays in memory and clears on
            refresh.
          </div>
          <p className="setup-hint">
            First time? Run <code>python scripts/bootstrap.py</code> and open
            the generated <code>.env</code> file on your machine.
          </p>
        </form>
      </div>
    );

  return (
    <div className="app-shell">
      <aside className="sidebar">
        <div className="brand">
          <div className="brand-icon">
            <Shield size={23} />
          </div>
          <div>
            RepoSentinel <span>AI</span>
            <small>SECURITY WORKSPACE</small>
          </div>
        </div>
        <div className="workspace">
          <span className="workspace-mark">S</span>
          <div>
            Source review<small>Personal workspace</small>
          </div>
          <Badge value="local" />
        </div>
        <div className="nav-label">WORKSPACE</div>
        <nav aria-label="Main navigation">
          {sections.map(([name, Icon]) => (
            <button
              key={name}
              className={page === name ? "nav-active" : ""}
              onClick={() => setPage(name)}
            >
              <Icon size={18} />
              <span>{name}</span>
              {name === "Findings Explorer" && all.length > 0 && (
                <b>{all.length}</b>
              )}
            </button>
          ))}
        </nav>
        <div className="sidebar-note">
          <ShieldCheck size={20} />
          <strong>Evidence before action</strong>
          <p>
            Every finding is a starting point for review, not proof of
            exploitation.
          </p>
        </div>
        <button
          className="logout"
          onClick={() => {
            setToken("");
            setConnected(false);
            cache.clear();
            setSelected(null);
          }}
        >
          <LogOut size={16} />
          Lock workspace
        </button>
      </aside>
      <div className="main-wrap">
        <header className="topbar">
          <div>
            Workspace <ChevronRight size={14} />
            <strong>{page}</strong>
          </div>
          <div className="topbar-right">
            <span className="connection-dot" />
            Authenticated session<span className="avatar">SS</span>
          </div>
        </header>
        <main>
          <div className="page-heading">
            <div>
              <div className="eyebrow">REPOSITORY SECURITY</div>
              <h1>{page === "Overview" ? "Your security overview" : page}</h1>
              <p>
                {page === "Overview"
                  ? "Understand the findings. Focus your next review."
                  : "A clear path from detection to a reviewed decision."}
              </p>
            </div>
            <button
              className="primary"
              onClick={() => setPage("Scan Repository")}
            >
              <Plus size={17} />
              New scan
            </button>
          </div>
          <ErrorNotice
            error={
              scans.error ||
              findings.error ||
              deps.error ||
              settings.error ||
              start.error ||
              upload.error
            }
          />
          {notice && (
            <div className="notice">
              <Check size={16} />
              {notice}
              <button
                className="icon-button"
                aria-label="Dismiss notification"
                onClick={() => setNotice("")}
              >
                <X size={14} />
              </button>
            </div>
          )}
          {page !== "Scan Repository" && page !== "Settings" && (
            <div className="scan-bar">
              <div>
                <FolderGit2 size={19} />
                <select
                  aria-label="Selected scan"
                  value={scanId ?? ""}
                  onChange={(e) => {
                    setActive(e.target.value);
                    setSelected(null);
                  }}
                >
                  <option value="" disabled>
                    Select a scan
                  </option>
                  {scans.data?.map((s) => (
                    <option key={s.id} value={s.id}>
                      {s.name} · {new Date(s.created_at).toLocaleString()}
                    </option>
                  ))}
                </select>
              </div>
              {current && (
                <>
                  <Badge value={current.status} />
                  <span className="mono">{current.id.slice(0, 8)}</span>
                </>
              )}
            </div>
          )}
          {busy && (
            <div className="notice">
              <Activity size={17} />
              Scan {current?.status}. Results will update automatically. If it
              stays queued, start the worker.
            </div>
          )}
          {current?.error && (
            <div role="alert" className="notice error">
              {current.error}
            </div>
          )}
          {page === "Overview" && (
            <>
              {!current ? (
                <div className="welcome panel">
                  <div className="eyebrow">YOUR FIRST REVIEW STARTS HERE</div>
                  <h2>
                    Bring a repository.
                    <br />
                    Leave with a clearer picture.
                  </h2>
                  <p>
                    Run the built-in example to explore the workflow, or scan an
                    authorized source archive.
                  </p>
                  <button
                    className="primary"
                    disabled={start.isPending}
                    onClick={() => start.mutate({ source: "demo" })}
                  >
                    Scan the demo project <ArrowRight size={17} />
                  </button>
                  <span className="subtle">
                    Intentionally vulnerable sample · no credentials needed
                  </span>
                </div>
              ) : (
                <>
                  <div className="stat-grid">
                    <Stat
                      title="Active findings"
                      value={current.summary.active ?? 0}
                      sub={`${current.summary.suppressed ?? 0} suppressed with review`}
                      icon={<Shield size={18} />}
                    />
                    <Stat
                      title="Critical + high"
                      value={counts.critical + counts.high}
                      sub="Source severity · review first"
                      icon={<TriangleAlert size={18} />}
                    />
                    <Stat
                      title="Files analyzed"
                      value={current.summary.files_scanned ?? 0}
                      sub={`${(current.summary.lines_scanned ?? 0).toLocaleString()} lines of source`}
                      icon={<FileCode2 size={18} />}
                    />
                    <Stat
                      title="Dependencies"
                      value={current.summary.dependency_count ?? 0}
                      sub="Declared versions · direct packages"
                      icon={<Package size={18} />}
                    />
                  </div>
                  <div className="overview-grid">
                    <section className="panel distribution">
                      <div className="panel-heading">
                        <div>
                          <h2>Finding distribution</h2>
                          <p>Active findings by source severity</p>
                        </div>
                        <Badge value={current.summary.coverage ?? "pending"} />
                      </div>
                      <div className="chart-row">
                        <div className="donut">
                          {all.length > 0 ? (
                            <ResponsiveContainer width="100%" height={210}>
                              <PieChart>
                                <Pie
                                  data={chartData}
                                  dataKey="value"
                                  innerRadius={65}
                                  outerRadius={88}
                                  paddingAngle={4}
                                  stroke="none"
                                >
                                  {chartData.map((d) => (
                                    <Cell key={d.name} fill={colors[d.name]} />
                                  ))}
                                </Pie>
                                <Tooltip />
                              </PieChart>
                            </ResponsiveContainer>
                          ) : (
                            <div className="zero-ring" />
                          )}
                          <div className="donut-center">
                            <strong>{current.summary.active ?? 0}</strong>
                            <span>active findings</span>
                          </div>
                        </div>
                        <div className="legend">
                          {chartData.map((d) => (
                            <div key={d.name}>
                              <i style={{ background: colors[d.name] }} />
                              <span>{d.name}</span>
                              <b>{d.value}</b>
                            </div>
                          ))}
                        </div>
                      </div>
                    </section>
                    <section className="panel engine-panel">
                      <div className="panel-heading">
                        <div>
                          <h2>Analysis coverage</h2>
                          <p>Engine status is part of the evidence</p>
                        </div>
                        <Activity size={18} />
                      </div>
                      <div className="engine-line">
                        <span>Python AST + secret patterns</span>
                        <Badge
                          value={
                            busy
                              ? "pending"
                              : current.finished_at
                                ? "completed"
                                : "pending"
                          }
                        />
                      </div>
                      {Object.entries(current.summary.engines ?? {}).map(
                        ([name, status]) => (
                          <div className="engine-line" key={name}>
                            <span title={status.detail}>{name}</span>
                            <Badge value={status.status} />
                          </div>
                        ),
                      )}
                      <div className="footnote">
                        {current.summary.duration_seconds ?? "—"}s scan time ·{" "}
                        {current.summary.warnings?.length ?? 0} scope warnings
                      </div>
                    </section>
                  </div>
                  <section className="panel">
                    <div className="panel-heading">
                      <div>
                        <h2>Needs your attention</h2>
                        <p>
                          Sorted by contextual priority, not a claim of
                          exploitability
                        </p>
                      </div>
                      <button
                        className="text-button"
                        onClick={() => setPage("Findings Explorer")}
                      >
                        View all findings
                        <ArrowRight size={16} />
                      </button>
                    </div>
                    <FindingTable
                      findings={all.filter((f) => !f.suppressed).slice(0, 6)}
                      onSelect={setSelected}
                    />
                  </section>
                  {(current.summary.warnings?.length ?? 0) > 0 && (
                    <details className="panel warnings">
                      <summary>
                        {current.summary.warnings?.length} coverage warnings —
                        inspect before using the report
                      </summary>
                      <ul>
                        {current.summary.warnings?.map((w, i) => (
                          <li key={i}>{w}</li>
                        ))}
                      </ul>
                    </details>
                  )}
                </>
              )}
              <div className="review-note">
                <ShieldCheck size={18} />
                <span>
                  A clean scan does not prove an application is secure. Validate
                  reachability, configuration and affected versions.
                </span>
              </div>
            </>
          )}
          {page === "Scan Repository" && (
            <ScanForm
              settings={settings.data}
              onDemo={() => start.mutate({ source: "demo" })}
              onGit={(url) =>
                start.mutate({ source: "git", url, authorized: true })
              }
              onUpload={(file) => upload.mutate(file)}
              pending={start.isPending || upload.isPending}
            />
          )}
          {page === "Findings Explorer" && (
            <section className="panel">
              <div className="filters">
                <div className="search-input">
                  <Search size={16} />
                  <input
                    aria-label="Search findings"
                    placeholder="Search file, rule or finding…"
                    value={search}
                    onChange={(e) => setSearch(e.target.value)}
                  />
                </div>
                <select
                  aria-label="Severity"
                  value={severity}
                  onChange={(e) => setSeverity(e.target.value)}
                >
                  <option value="">All severities</option>
                  {severityOrder.map((s) => (
                    <option key={s}>{s}</option>
                  ))}
                </select>
                <select
                  aria-label="Language"
                  value={language}
                  onChange={(e) => setLanguage(e.target.value)}
                >
                  <option value="">All languages</option>
                  {[...new Set(all.map((f) => f.language))].map((s) => (
                    <option key={s}>{s}</option>
                  ))}
                </select>
                <select
                  aria-label="Rule"
                  value={rule}
                  onChange={(e) => setRule(e.target.value)}
                >
                  <option value="">All rules</option>
                  {[...new Set(all.map((f) => f.rule_id))].map((s) => (
                    <option key={s}>{s}</option>
                  ))}
                </select>
              </div>
              <FindingTable findings={filtered} onSelect={setSelected} />
            </section>
          )}
          {page === "Vulnerable Dependencies" && (
            <section className="panel">
              <div className="panel-heading">
                <div>
                  <h2>Dependency intelligence</h2>
                  <p>
                    OSV advisory correlation against exact declared versions.
                    Ranges are explicitly unresolved.
                  </p>
                </div>
              </div>
              {!deps.data?.length ? (
                <Empty
                  title="No dependency declarations"
                  detail="Run a scan containing a supported manifest to inspect packages."
                />
              ) : (
                <div className="table-scroll">
                  <table>
                    <thead>
                      <tr>
                        <th>Package / ecosystem</th>
                        <th>Version</th>
                        <th>Lookup</th>
                        <th>Advisories</th>
                      </tr>
                    </thead>
                    <tbody>
                      {deps.data.map((d, i) => (
                        <tr key={i}>
                          <td>
                            <strong>{d.name}</strong>
                            <small>
                              {d.ecosystem} · {d.file}
                            </small>
                          </td>
                          <td className="mono">
                            {d.version}
                            <small>{d.version_kind}</small>
                          </td>
                          <td>
                            <Badge value={d.lookup_status} />
                          </td>
                          <td>
                            {d.advisories.length
                              ? d.advisories.map((a) => (
                                  <div className="advisory" key={a.id}>
                                    <strong>{a.id}</strong>
                                    <small>
                                      {a.aliases.join(", ")} · Severity:{" "}
                                      {a.source_severity ?? "not supplied"}
                                    </small>
                                    {a.references[0] && (
                                      <a
                                        href={a.references[0]}
                                        rel="noreferrer"
                                        target="_blank"
                                      >
                                        Read source ↗
                                      </a>
                                    )}
                                  </div>
                                ))
                              : d.lookup_status === "live" ||
                                  d.lookup_status === "cached"
                                ? "No matches returned"
                                : "Not verified"}
                          </td>
                        </tr>
                      ))}
                    </tbody>
                  </table>
                </div>
              )}
            </section>
          )}
          {page === "AI Remediation" && (
            <section className="panel">
              <div className="panel-heading">
                <div>
                  <h2>A second explanation. Your final decision.</h2>
                  <p>
                    Choose a finding to see local guidance, then optionally
                    request a model explanation.
                  </p>
                </div>
                <Sparkles size={20} />
              </div>
              <div className="notice">
                {settings.data?.ai_payload} Provider:{" "}
                {settings.data?.ai_provider ?? "loading"}.
              </div>
              <FindingTable findings={all} onSelect={setSelected} />
            </section>
          )}
          {page === "Scan History" && (
            <HistoryView
              scans={scans.data ?? []}
              onSelect={(id) => {
                setActive(id);
                setPage("Overview");
              }}
            />
          )}
          {page === "Reports" && (
            <>
              <div className="report-grid">
                {[
                  [
                    "json",
                    "Machine-readable results",
                    "Full finding data, coverage and dependencies.",
                  ],
                  [
                    "html",
                    "Review-ready report",
                    "A self-contained, escaped report for human review.",
                  ],
                  [
                    "sarif",
                    "Developer tooling",
                    "SARIF 2.1.0 for compatible code-scanning tools.",
                  ],
                  [
                    "csv",
                    "Spreadsheet export",
                    "A flat finding list with formula-injection protection.",
                  ],
                ].map(([format, title, detail]) => (
                  <section className="panel report-card" key={format}>
                    <div className="file-format">{format.toUpperCase()}</div>
                    <h2>{title}</h2>
                    <p>{detail}</p>
                    <button
                      className="secondary"
                      disabled={
                        !current ||
                        !["completed", "partial"].includes(current.status)
                      }
                      onClick={() => void downloadFile(format)}
                    >
                      <ArrowDownToLine size={16} />
                      Download {format.toUpperCase()}
                    </button>
                  </section>
                ))}
              </div>
              <div className="panel panel-heading">
                <div>
                  <h2>Reviewed suppression baseline</h2>
                  <p>
                    Export only findings you have explicitly suppressed. Keep
                    the reasons in your review record.
                  </p>
                </div>
                <button
                  className="secondary"
                  disabled={!scanId}
                  onClick={() => {
                    if (scanId)
                      void download(
                        `/scans/${scanId}/baseline`,
                        "reposentinel-baseline.json",
                      ).catch((e) => setNotice(e.message));
                  }}
                >
                  Download baseline
                </button>
              </div>
            </>
          )}
          {page === "Settings" && settings.data && (
            <SettingsForm
              value={settings.data}
              onSaved={() =>
                void cache.invalidateQueries({ queryKey: ["settings"] })
              }
            />
          )}
          <footer>
            <span>
              RepoSentinel AI <b>v0.1</b>
            </span>
            <span>Potential risks. Transparent coverage. Human review.</span>
          </footer>
        </main>
      </div>
      {selected && (
        <FindingDetail
          finding={selected}
          external={settings.data?.ai_external ?? false}
          onClose={() => setSelected(null)}
          onSuppressed={() => {
            setSelected(null);
            void cache.invalidateQueries({ queryKey: ["findings"] });
            void cache.invalidateQueries({ queryKey: ["scans"] });
          }}
        />
      )}
    </div>
  );
}

function Stat({
  title,
  value,
  sub,
  icon,
}: {
  title: string;
  value: number;
  sub: string;
  icon: React.ReactNode;
}) {
  return (
    <section className="stat panel">
      <div>
        {title}
        <span>{icon}</span>
      </div>
      <strong>{value.toLocaleString()}</strong>
      <p>{sub}</p>
    </section>
  );
}
function FindingTable({
  findings,
  onSelect,
}: {
  findings: Finding[];
  onSelect: (f: Finding) => void;
}) {
  return !findings.length ? (
    <Empty
      title="No findings in this view"
      detail="Check the scan status and coverage before interpreting this as a clean result."
    />
  ) : (
    <div className="table-scroll">
      <table>
        <thead>
          <tr>
            <th>Finding</th>
            <th>Location</th>
            <th>Severity</th>
            <th>Priority</th>
            <th>Review</th>
          </tr>
        </thead>
        <tbody>
          {findings.map((f) => (
            <tr key={f.id}>
              <td>
                <button className="finding-title" onClick={() => onSelect(f)}>
                  {f.title}
                </button>
                <small>
                  {f.rule_id} · {f.cwe.join(", ") || "CWE unavailable"}
                </small>
              </td>
              <td>
                <code>{f.file}</code>
                <small>
                  {f.line ? `Line ${f.line}` : "Manifest"} · {f.language}
                </small>
              </td>
              <td>
                <Badge value={f.severity} />
              </td>
              <td>
                <Badge value={f.priority} />
                <small>{f.priority_score}/100 · heuristic</small>
              </td>
              <td>
                <button className="text-button" onClick={() => onSelect(f)}>
                  {f.suppressed ? "Suppressed" : "Review"}
                  <ChevronRight size={15} />
                </button>
              </td>
            </tr>
          ))}
        </tbody>
      </table>
    </div>
  );
}

function ScanForm({
  settings,
  onDemo,
  onGit,
  onUpload,
  pending,
}: {
  settings: Settings | undefined;
  onDemo: () => void;
  onGit: (url: string) => void;
  onUpload: (f: File) => void;
  pending: boolean;
}) {
  const [url, setUrl] = useState("");
  const [file, setFile] = useState<File | null>(null);
  const [authorized, setAuthorized] = useState(false);
  const [error, setError] = useState("");
  return (
    <div className="scan-grid">
      <section className="panel scan-form">
        <div className="round-icon">
          <FolderGit2 />
        </div>
        <h2>Scan an authorized repository</h2>
        <p>
          Repository files are analyzed as data. They are never installed or
          executed.
        </p>
        <label htmlFor="git-url">Public GitHub repository</label>
        <input
          id="git-url"
          type="url"
          placeholder="https://github.com/owner/repository"
          value={url}
          onChange={(e) => setUrl(e.target.value)}
        />
        <p className="subtle">
          Allowed repositories:{" "}
          {settings?.allowed_repos ||
            "None configured. Use a ZIP upload or the demo."}
        </p>
        <label className="checkbox">
          <input
            type="checkbox"
            checked={authorized}
            onChange={(e) => setAuthorized(e.target.checked)}
          />
          I am authorized to review this source code.
        </label>
        <button
          className="primary"
          disabled={pending || !authorized || !url}
          onClick={() => onGit(url)}
        >
          Start repository scan
          <ArrowRight size={16} />
        </button>
        <div className="divider">or upload source</div>
        <label className="upload-zone">
          <Upload size={25} />
          <strong>{file?.name ?? "Choose a source ZIP"}</strong>
          <span>
            Up to {settings?.max_archive_mb ?? 8} MB compressed · 20 MB expanded
          </span>
          <input
            type="file"
            accept=".zip,application/zip"
            onChange={(e) => {
              setError("");
              const picked = e.target.files?.[0] ?? null;
              if (
                picked &&
                picked.size > (settings?.max_archive_mb ?? 8) * 1024 * 1024
              ) {
                setError("Archive is too large.");
                setFile(null);
              } else setFile(picked);
            }}
          />
        </label>
        <ErrorNotice error={error} />
        <button
          className="secondary"
          disabled={pending || !authorized || !file}
          onClick={() => file && onUpload(file)}
        >
          Upload and scan
          <ArrowRight size={16} />
        </button>
      </section>
      <div>
        <section className="panel demo-panel">
          <div className="eyebrow">EXPLORE WITH A SAFE EXAMPLE</div>
          <Terminal size={32} />
          <h2>See the whole workflow</h2>
          <p>
            The bundled source intentionally contains suspicious SQL, invented
            credentials, and insecure settings. The scanner analyzes it without
            running it.
          </p>
          <button className="primary" disabled={pending} onClick={onDemo}>
            Run demo scan
            <ArrowRight size={16} />
          </button>
          <small>Clearly labeled fixture · real scanner results</small>
        </section>
        <section className="panel scan-notes">
          <h3>Before you scan</h3>
          <p>
            Remove data you do not need to review. Findings omit raw source and
            credential values. Temporary source files are removed when the job
            ends.
          </p>
          <p>
            Exact dependency names and versions are sent to OSV when advisory
            lookup is enabled. Disable this with{" "}
            <code>RS_OSV_ENABLED=false</code> for offline work.
          </p>
        </section>
      </div>
    </div>
  );
}

function FindingDetail({
  finding: f,
  external,
  onClose,
  onSuppressed,
}: {
  finding: Finding;
  external: boolean;
  onClose: () => void;
  onSuppressed: () => void;
}) {
  const [consent, setConsent] = useState(false);
  const [reason, setReason] = useState("");
  const explain = useMutation({
    mutationFn: (useAI: boolean) =>
      api<Explanation>(`/findings/${f.id}/explain`, {
        method: "POST",
        body: JSON.stringify({ use_ai: useAI, consent_external: consent }),
      }),
  });
  const suppress = useMutation({
    mutationFn: () =>
      api(`/findings/${f.id}/suppress`, {
        method: "POST",
        body: JSON.stringify({ reason }),
      }),
    onSuccess: onSuppressed,
  });
  return (
    <div className="drawer-backdrop" onClick={onClose}>
      <section
        className="drawer"
        role="dialog"
        aria-modal="true"
        aria-label="Finding details"
        onClick={(e) => e.stopPropagation()}
      >
        <div className="drawer-header">
          <span className="eyebrow">FINDING REVIEW</span>
          <button
            className="icon-button"
            aria-label="Close details"
            onClick={onClose}
          >
            <X />
          </button>
        </div>
        <div className="badge-row">
          <Badge value={f.severity} />
          <span className="mono">{f.rule_id}</span>
        </div>
        <h2>{f.title}</h2>
        <p className="mono location">
          {f.file}:{f.line ?? "manifest"}
        </p>
        <p>{f.description}</p>
        <dl>
          <dt>Finding ID</dt>
          <dd className="mono">{f.id}</dd>
          <dt>Confidence</dt>
          <dd>{f.confidence}</dd>
          <dt>CWE / OWASP</dt>
          <dd>
            {f.cwe.join(", ") || "Not supplied"} · {f.owasp ?? "Not mapped"}
          </dd>
          <dt>Detection engines</dt>
          <dd>{f.engines.join(", ")}</dd>
          <dt>Source advisory severity</dt>
          <dd>{f.source_severity ?? "Not supplied / static rule severity"}</dd>
        </dl>
        <h3>Masked evidence</h3>
        <pre>{f.evidence}</pre>
        <h3>Contextual priority</h3>
        <p>{f.priority_reason}</p>
        <h3>Safer approach</h3>
        <p>{f.remediation}</p>
        {f.cvss.length > 0 && (
          <>
            <h3>Source CVSS vectors</h3>
            {f.cvss.map((c, i) => (
              <pre key={i}>
                {c.type}: {c.score}
              </pre>
            ))}
          </>
        )}
        <div className="references">
          {f.references
            .filter((r) => r.startsWith("https://"))
            .map((r) => (
              <a href={r} key={r} target="_blank" rel="noreferrer">
                Reference ↗ {new URL(r).hostname}
              </a>
            ))}
        </div>
        <section className="ai-box">
          <h3>
            <Sparkles size={18} />
            Remediation assistant
          </h3>
          <p>
            Local guidance is always available. Model responses are generic
            suggestions and never modify files.
          </p>
          {external && (
            <label className="checkbox">
              <input
                type="checkbox"
                checked={consent}
                onChange={(e) => setConsent(e.target.checked)}
              />
              Send trusted rule metadata to the configured external model for
              this request.
            </label>
          )}
          <div className="button-row">
            <button
              className="secondary"
              disabled={explain.isPending}
              onClick={() => explain.mutate(false)}
            >
              Local guidance
            </button>
            <button
              className="primary"
              disabled={explain.isPending || (external && !consent)}
              onClick={() => explain.mutate(true)}
            >
              {explain.isPending ? "Explaining…" : "Explain with AI"}
            </button>
          </div>
          <ErrorNotice error={explain.error} />
          {explain.data && (
            <div className="explanation">
              <Badge value={explain.data.provider} />
              {explain.data.warning && (
                <div className="notice">{explain.data.warning}</div>
              )}
              {(
                [
                  "summary",
                  "impact",
                  "concept",
                  "safer_pattern",
                  "proposed_change",
                  "false_positive",
                ] as const
              ).map((k) => (
                <section key={k}>
                  <h4>{k.replaceAll("_", " ")}</h4>
                  <p>{explain.data![k]}</p>
                </section>
              ))}
            </div>
          )}
        </section>
        <section className="suppression">
          <h3>Record a suppression decision</h3>
          <p>
            Only suppress after review. Future scans of this repository use the
            same fingerprint baseline.
          </p>
          <textarea
            aria-label="Suppression reason"
            placeholder="Describe the evidence and why this finding can be accepted…"
            value={reason}
            onChange={(e) => setReason(e.target.value)}
            minLength={12}
          />
          <button
            className="secondary"
            disabled={
              f.suppressed || reason.trim().length < 12 || suppress.isPending
            }
            onClick={() => suppress.mutate()}
          >
            {f.suppressed ? "Already suppressed" : "Suppress with reason"}
          </button>
          <ErrorNotice error={suppress.error} />
        </section>
      </section>
    </div>
  );
}

function HistoryView({
  scans,
  onSelect,
}: {
  scans: Scan[];
  onSelect: (id: string) => void;
}) {
  const [base, setBase] = useState("");
  const [target, setTarget] = useState("");
  const compare = useMutation({
    mutationFn: () =>
      api<{
        new: string[];
        resolved: string[];
        unchanged: number;
        notice: string;
      }>(`/scans/${target}/compare/${base}`),
  });
  return (
    <section className="panel">
      <div className="panel-heading">
        <div>
          <h2>Scan activity</h2>
          <p>Persistent runs with honest completion and coverage status</p>
        </div>
      </div>
      {!scans.length ? (
        <Empty
          title="No scans yet"
          detail="Start with the demo project or an authorized source archive."
        />
      ) : (
        <div className="table-scroll">
          <table>
            <thead>
              <tr>
                <th>Repository</th>
                <th>Started</th>
                <th>Status</th>
                <th>Findings</th>
                <th>Open</th>
              </tr>
            </thead>
            <tbody>
              {scans.map((s) => (
                <tr key={s.id}>
                  <td>
                    <strong>{s.name}</strong>
                    <small className="mono">{s.id.slice(0, 8)}</small>
                  </td>
                  <td>{new Date(s.created_at).toLocaleString()}</td>
                  <td>
                    <Badge value={s.status} />
                  </td>
                  <td>{s.summary.total ?? "—"}</td>
                  <td>
                    <button
                      className="text-button"
                      onClick={() => onSelect(s.id)}
                    >
                      View
                      <ArrowRight size={15} />
                    </button>
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      )}
      <div className="comparison">
        <h3>Compare scans of the same repository</h3>
        <div className="button-row">
          <select
            aria-label="Previous scan"
            value={base}
            onChange={(e) => setBase(e.target.value)}
          >
            <option value="">Previous scan</option>
            {scans.map((s) => (
              <option value={s.id} key={s.id}>
                {s.name} · {s.id.slice(0, 8)}
              </option>
            ))}
          </select>
          <select
            aria-label="Current scan"
            value={target}
            onChange={(e) => setTarget(e.target.value)}
          >
            <option value="">Current scan</option>
            {scans.map((s) => (
              <option value={s.id} key={s.id}>
                {s.name} · {s.id.slice(0, 8)}
              </option>
            ))}
          </select>
          <button
            className="secondary"
            disabled={!base || !target || base === target || compare.isPending}
            onClick={() => compare.mutate()}
          >
            Compare
          </button>
        </div>
        <ErrorNotice error={compare.error} />
        {compare.data && (
          <div className="notice">
            {compare.data.new.length} new · {compare.data.resolved.length}{" "}
            resolved · {compare.data.unchanged} unchanged. {compare.data.notice}
          </div>
        )}
      </div>
    </section>
  );
}

function SettingsForm({
  value,
  onSaved,
}: {
  value: Settings;
  onSaved: () => void;
}) {
  const [form, setForm] = useState(value);
  const save = useMutation({
    mutationFn: () =>
      api("/settings", {
        method: "PUT",
        body: JSON.stringify({
          fail_on: form.fail_on,
          exposure: form.exposure,
          critical_asset: form.critical_asset,
          exclusions: form.exclusions,
        }),
      }),
    onSuccess: onSaved,
  });
  return (
    <div className="scan-grid">
      <form
        className="panel scan-form"
        onSubmit={(e) => {
          e.preventDefault();
          save.mutate();
        }}
      >
        <h2>Risk context</h2>
        <p>
          Applies to future scans. Source severity stays unchanged; contextual
          priority can increase.
        </p>
        <label htmlFor="exposure">Deployment exposure</label>
        <select
          id="exposure"
          value={form.exposure}
          onChange={(e) =>
            setForm({
              ...form,
              exposure: e.target.value as Settings["exposure"],
            })
          }
        >
          <option value="internal">Internal application</option>
          <option value="internet">Internet-facing application</option>
        </select>
        <label className="checkbox">
          <input
            type="checkbox"
            checked={form.critical_asset}
            onChange={(e) =>
              setForm({ ...form, critical_asset: e.target.checked })
            }
          />
          Critical asset context
        </label>
        <label htmlFor="threshold">Review threshold</label>
        <select
          id="threshold"
          value={form.fail_on}
          onChange={(e) =>
            setForm({ ...form, fail_on: e.target.value as Severity })
          }
        >
          {severityOrder.map((s) => (
            <option key={s}>{s}</option>
          ))}
        </select>
        <label htmlFor="exclusions">Excluded paths (one glob per line)</label>
        <textarea
          id="exclusions"
          value={form.exclusions.join("\n")}
          onChange={(e) =>
            setForm({
              ...form,
              exclusions: e.target.value.split("\n").filter(Boolean),
            })
          }
          placeholder="generated/*"
        />
        <button className="primary" disabled={save.isPending}>
          Save settings
          <Check size={16} />
        </button>
        {save.isSuccess && (
          <div className="notice">Settings saved for future scans.</div>
        )}
        <ErrorNotice error={save.error} />
      </form>
      <section className="panel scan-notes">
        <h2>Model & access configuration</h2>
        <dl>
          <dt>AI provider</dt>
          <dd>{value.ai_provider}</dd>
          <dt>Model</dt>
          <dd>{value.ai_model || "Not configured"}</dd>
          <dt>Access model</dt>
          <dd>{value.deployment_mode}</dd>
          <dt>Configured engines</dt>
          <dd>{value.engines}</dd>
        </dl>
        <p>
          Set provider endpoints, model name, API keys and repository allowlists
          through server environment variables. Keys are never returned to the
          browser.
        </p>
        <pre>
          RS_AI_PROVIDER=ollama
          <br />
          RS_AI_MODEL=your-installed-model
          <br />
          RS_OLLAMA_URL=http://127.0.0.1:11434
        </pre>
        <p>{value.ai_payload}</p>
      </section>
    </div>
  );
}
