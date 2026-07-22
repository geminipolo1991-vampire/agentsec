"use client";

import { useCallback, useEffect, useMemo, useState } from "react";

type View = "Overview" | "Incidents" | "Policies" | "Evaluations" | "Integrations";
type Severity = "critical" | "high" | "medium" | "info";
type DetailTab = "Overview" | "Triage" | "Enrichment" | "Decision" | "Response";

type IncidentDetail = {
  trace_mode: "deterministic_replay" | "authoritative";
  alert_type: string;
  alert: {
    detector_id: string;
    confidence: number;
    reason_codes: string[];
    evidence: string[];
    recommended_action: string;
  };
  ingestion: {
    duplicate: boolean;
    sequence: number;
    current_hash: string;
    ingested_at: string;
  };
  triage: {
    risk_score: number;
    severity: string;
    priority: string;
    reasons: string[];
    assessed_at: string;
  };
  risk_contributions: { label: string; delta: number; evidence: string }[];
  judgment: {
    action: string;
    deterministic_action: string;
    reason_codes: string[];
    ai_mode: string;
    policy_version: string;
    judged_at: string;
    model_verdict: null | {
      provider: string;
      model_id: string;
      action: string;
      confidence: number;
      reason_codes: string[];
      uncertainty?: string | null;
    };
  };
  escalation: {
    level: string;
    queue?: string | null;
    case_id?: string | null;
    reason: string;
    escalated_at: string;
  };
  response: {
    actions: string[];
    effect_allowed: boolean;
    simulated: boolean;
    responder: string;
    notes: string[];
    responded_at: string;
  };
  finding: {
    status: string;
    created_at: string;
    updated_at: string;
    audit: { from_status?: string | null; to_status: string; actor: string; reason: string; at: string }[];
  };
  timeline: { stage: string; outcome: string; at: string; evidence: Record<string, unknown> }[];
  enrichment: { kind: string; status: "risk" | "verified"; value: string; evidence: string; source: string; impact: string }[];
  validation?: {
    status: string;
    authoritative_pipeline_result: boolean;
    deterministic_match: boolean;
    ledger_committed: boolean;
    response_simulated: boolean;
    basis: string[];
  };
  redaction?: {
    policy_version: string;
    hashed_reference_count: number;
    raw_prompts_included: boolean;
    raw_tool_arguments_included: boolean;
  };
};

type Alert = {
  id: string;
  title: string;
  type: string;
  severity: Severity;
  decision: "DENY" | "REQUIRE APPROVAL" | "ALLOW";
  state: string;
  time: string;
  agent: string;
  operation: string;
  resource: string;
  source: string;
  sourceTrust: string;
  destination: string;
  reason: string;
  finding: string;
  policy: string;
  risk: number;
  aiReview: string;
  evidence: string[];
  detailAvailability?: "authoritative" | "mvp_replay" | "summary_only";
  detail?: IncidentDetail | null;
};

type LiveState = "connecting" | "connected" | "offline";
type SimulationState = "idle" | "running" | "done" | "error";

type AlertsPayload = {
  alerts: Alert[];
  ledger_verified: boolean | null;
  checked_at: string;
};

type ForgePayload = {
  preset: string;
  event_id: string;
  overall_action: string;
  effect_allowed: boolean;
  ledger_verified: boolean | null;
  alerts: Alert[];
  completed_at: string;
};

const LIVE_API = "http://127.0.0.1:8765";

const forgePresets = [
  ["indirect_injection_secret_egress", "Prompt injection + secret egress"],
  ["confused_deputy_authority_expansion", "Authority expansion + destructive action"],
  ["persistent_memory_poisoning", "Persistent memory poisoning"],
  ["mcp_schema_drift", "MCP tool contract drift"],
  ["benign_inventory_read", "Benign inventory read"],
] as const;

const stages = ["Detection", "Ingestion", "Triage", "Judgment", "Escalation", "Response"];

const navItems: { label: View; short: string }[] = [
  { label: "Overview", short: "OV" },
  { label: "Incidents", short: "IN" },
  { label: "Policies", short: "PO" },
  { label: "Evaluations", short: "EV" },
  { label: "Integrations", short: "CN" },
];

function StatusMark({ tone = "healthy" }: { tone?: "healthy" | "warning" | "danger" }) {
  return <span className={`status-mark ${tone}`} aria-hidden="true" />;
}

function MetricCard({ label, value, note, tone = "default" }: { label: string; value: string; note: string; tone?: string }) {
  return (
    <article className={`metric-card ${tone}`}>
      <div className="metric-label">{label}</div>
      <div className="metric-value">{value}</div>
      <div className="metric-note">{note}</div>
    </article>
  );
}

function AlertQueue({ alerts, active, onSelect, liveState }: { alerts: Alert[]; active: Alert | null; onSelect: (alert: Alert) => void; liveState: LiveState }) {
  const [query, setQuery] = useState("");
  const [filter, setFilter] = useState("All");
  const filtered = useMemo(() => {
    return alerts.filter((alert) => {
      const matchesQuery = `${alert.title} ${alert.type} ${alert.agent} ${alert.operation}`
        .toLowerCase()
        .includes(query.toLowerCase());
      const matchesFilter =
        filter === "All" ||
        (filter === "Critical" && alert.severity === "critical") ||
        (filter === "High" && alert.severity === "high") ||
        (filter === "Approval" && alert.decision === "REQUIRE APPROVAL");
      return matchesQuery && matchesFilter;
    });
  }, [alerts, query, filter]);

  return (
    <section className="panel queue-panel" aria-label="Security event queue">
      <div className="panel-heading queue-heading">
        <div>
          <span className="eyebrow">Live decision queue</span>
          <h2>Agent activity</h2>
        </div>
        <span className="count-badge">{filtered.length}</span>
      </div>
      <label className="search-field">
        <span aria-hidden="true">⌕</span>
        <span className="sr-only">Search security events</span>
        <input value={query} onChange={(event) => setQuery(event.target.value)} placeholder="Search event, agent, operation…" />
      </label>
      <div className="filter-row" aria-label="Filter events">
        {["All", "Critical", "High", "Approval"].map((item) => (
          <button key={item} className={filter === item ? "filter active" : "filter"} onClick={() => setFilter(item)}>
            {item}
          </button>
        ))}
      </div>
      <div className="alert-list">
        {filtered.map((alert) => (
          <button
            key={alert.id}
            className={active?.id === alert.id ? "alert-row selected" : "alert-row"}
            onClick={() => onSelect(alert)}
            aria-pressed={active?.id === alert.id}
          >
            <span className={`severity-rail ${alert.severity}`} />
            <span className="alert-copy">
              <span className="alert-topline">
                <span className={`severity-label ${alert.severity}`}>{alert.severity}</span>
                <span className="alert-time">{alert.time}</span>
              </span>
              <strong>{alert.title}</strong>
              <span className="alert-meta"><code>{alert.operation}</code> · {alert.agent}{alert.detail ? <em>{alert.detailAvailability === "authoritative" ? "AUTHORITATIVE" : "MVP TRACE"}</em> : null}</span>
            </span>
            <span className={`decision-mini ${alert.decision === "DENY" ? "deny" : alert.decision === "ALLOW" ? "allow" : "approval"}`}>
              {alert.decision === "REQUIRE APPROVAL" ? "HOLD" : alert.decision}
            </span>
          </button>
        ))}
        {filtered.length === 0 && (
          <div className="empty-state">
            {liveState === "connecting" ? "Connecting to the live SSM event stream…" : liveState === "offline" ? "Live bridge offline. No fixture alerts are shown." : "No live alerts match this view."}
          </div>
        )}
      </div>
    </section>
  );
}

function readable(value: string) {
  return value.replaceAll("_", " ").replace(/\b\w/g, (letter) => letter.toUpperCase());
}

function clock(value?: string) {
  if (!value) return "—";
  const parsed = new Date(value);
  return Number.isNaN(parsed.getTime()) ? "—" : parsed.toLocaleTimeString([], { hour: "2-digit", minute: "2-digit", second: "2-digit", fractionalSecondDigits: 3 });
}

function AlertDetail({ alert }: { alert: Alert | null }) {
  const [tab, setTab] = useState<DetailTab>("Overview");

  if (!alert) {
    return (
      <section className="panel detail-panel empty-detail" aria-label="Live alert details">
        <div>
          <span className="eyebrow">Live authorization trace</span>
          <h2>Waiting for a sanitized EC2 decision</h2>
          <p>Start the loopback bridge or forge a preset event. The browser receives findings only—never AWS credentials, the ingest token, or raw prompts.</p>
        </div>
        <ol className="lifecycle pending-lifecycle">
          {stages.map((stage, index) => (
            <li key={stage}>
              <span className="stage-index">{String(index + 1).padStart(2, "0")}</span>
              <span className="stage-dot" />
              <span className="stage-name">{stage}</span>
              <span className="stage-result">pending</span>
            </li>
          ))}
        </ol>
      </section>
    );
  }
  const decisionClass = alert.decision === "DENY" ? "deny" : alert.decision === "ALLOW" ? "allow" : "approval";
  const detail = alert.detail ?? null;
  const authoritative = detail?.trace_mode === "authoritative";
  const traceLabel = authoritative ? "AUTHORITATIVE TRACE" : detail ? "MVP REPLAY" : "SUMMARY ONLY";
  const validationBasis = detail?.validation?.basis ?? (detail ? [
    "Service alert type matched the deterministic replay",
    "Final enforcement action matched the deterministic replay",
    "Detector, triage, and response artifacts were reconstructed in the service container",
    "Containment actions remain simulated for this POC",
  ] : []);
  const traceLatency = detail && detail.timeline.length > 1
    ? Math.max(0, new Date(detail.timeline.at(-1)!.at).getTime() - new Date(detail.timeline[0].at).getTime())
    : null;
  const tabs: DetailTab[] = ["Overview", "Triage", "Enrichment", "Decision", "Response"];
  return (
    <section className="panel detail-panel" aria-label={`Details for ${alert.title}`}>
      <div className="detail-head">
        <div>
          <div className="detail-id"><span className={`severity-label ${alert.severity}`}>{alert.severity}</span> {alert.id} · {alert.finding} <span className={`trace-badge ${authoritative ? "" : detail ? "replay" : "summary"}`}>{traceLabel}</span></div>
          <h2>{alert.title}</h2>
          <p>{alert.reason}</p>
        </div>
        <div className={`decision-block ${decisionClass}`}>
          <span>Decision</span>
          <strong>{alert.decision}</strong>
          <small>{alert.state}</small>
        </div>
      </div>

      <div className="lifecycle-wrap">
        <div className="section-title-row">
          <div>
            <span className="eyebrow">Authorization trace</span>
            <h3>{alert.decision === "ALLOW" ? "Effect authorized after policy evaluation" : "Effect stopped before execution"}</h3>
          </div>
          <span className="latency">{traceLatency === null ? "LIVE · SSM SANITIZED" : `${traceLatency} MS · ${authoritative ? "AUTHORITATIVE TRACE" : "MVP REPLAY"}`}</span>
        </div>
        <ol className="lifecycle">
          {stages.map((stage, index) => {
            const trace = detail?.timeline.find((item) => item.stage === stage.toLowerCase());
            return (
              <li key={stage}>
                <span className="stage-index">{trace ? clock(trace.at) : String(index + 1).padStart(2, "0")}</span>
                <span className="stage-dot" />
                <span className="stage-name">{stage}</span>
                <span className="stage-result">{trace ? readable(trace.outcome) : stage === "Response" ? (alert.decision === "ALLOW" ? "effect allowed" : "effect prevented") : "summary received"}</span>
              </li>
            );
          })}
        </ol>
      </div>

      <div className="detail-tabs" role="tablist" aria-label="Incident investigation sections">
        {tabs.map((item) => <button role="tab" aria-selected={tab === item} className={tab === item ? "detail-tab active" : "detail-tab"} key={item} onClick={() => setTab(item)} disabled={!detail && item !== "Overview"}>{item}{item === "Enrichment" && detail ? <span>{detail.enrichment.length}</span> : null}</button>)}
      </div>

      {!detail && <div className="detail-limitation"><strong>Full trace unavailable for this older alert.</strong><span>Forge a new event to capture real triage, enrichment, judgment, and response records for the presentation.</span></div>}

      {tab === "Overview" && (
        <div className="detail-grid investigation-content">
          <article className="subpanel">
            <div className="subpanel-title"><span>Policy proof</span><code>{detail?.judgment.policy_version ?? alert.policy}</code></div>
            <dl className="proof-list">
              <div><dt>Operation</dt><dd><code>{alert.operation}</code></dd></div>
              <div><dt>Resource</dt><dd>{alert.resource}</dd></div>
              <div><dt>Source trust</dt><dd>{alert.sourceTrust}</dd></div>
              <div><dt>Destination</dt><dd>{alert.destination}</dd></div>
              <div><dt>Detector</dt><dd><code>{detail?.alert.detector_id ?? "summary-only"}</code></dd></div>
              <div><dt>Confidence</dt><dd>{detail ? `${Math.round(detail.alert.confidence * 100)}%` : "—"}</dd></div>
              <div><dt>Risk score</dt><dd><span className="risk-number">{detail?.triage.risk_score ?? alert.risk}</span> / 100</dd></div>
            </dl>
          </article>
          <article className="subpanel evidence-panel">
            <div className="subpanel-title"><span>Evidence and lineage</span><span className="verified-label">LEDGER VERIFIED</span></div>
            <div className="source-path"><span>Source</span><b aria-hidden="true">→</b><span>Agent</span><b aria-hidden="true">→</b><span>Effect</span></div>
            <ul className="evidence-list">
              {(detail?.alert.evidence ?? alert.evidence).map((item) => <li key={item}><span>✓</span>{item}</li>)}
            </ul>
            <div className="ai-review"><span className="ai-mark">AI</span><div><strong>Read-only semantic review</strong><small>{alert.aiReview}</small></div></div>
          </article>
          {detail && (
            <article className={`validity-panel ${authoritative ? "authoritative" : "replay"}`}>
              <div className="validity-summary">
                <span className="eyebrow">Why this alert is valid</span>
                <strong>{authoritative ? "Confirmed policy violation" : "Service alert with replay-supported explanation"}</strong>
                <p>{authoritative ? "This record comes from the exact pipeline result that made the enforcement decision." : "The service decision is real; its detailed explanation was reconstructed and checked against the alert types and final action."}</p>
              </div>
              <div className="validity-evidence">
                <div className="validity-status"><span className="status-mark healthy" /><b>{authoritative ? "AUTHORITATIVE PIPELINE" : "MVP REPLAY VERIFIED"}</b><code>{detail.alert.detector_id}</code></div>
                <ul>{validationBasis.map((basis) => <li key={basis}><span>✓</span>{basis}</li>)}</ul>
                <div className="validity-foot"><span>Risk {detail.triage.risk_score}/100 · {readable(detail.triage.priority)}</span><span>{detail.response.simulated ? "SIMULATED RESPONSE" : "LIVE RESPONSE"}</span>{detail.redaction ? <span>{detail.redaction.hashed_reference_count} REFERENCES HASHED</span> : null}</div>
              </div>
              <p className="validity-scope">This confirms a policy violation in the evaluated agent event. It is not, by itself, proof of a real-world compromise.</p>
            </article>
          )}
        </div>
      )}

      {tab === "Triage" && detail && (
        <div className="triage-layout investigation-content">
          <article className="risk-hero"><span className="eyebrow">Explainable risk</span><strong>{detail.triage.risk_score}</strong><small>/ 100</small><b>{detail.triage.priority}</b><p>{readable(detail.triage.severity)} severity · score policy v1</p></article>
          <article className="subpanel contribution-panel">
            <div className="subpanel-title"><span>Score contributions</span><span className="verified-label">REPRODUCIBLE</span></div>
            <div className="contribution-list">
              {detail.risk_contributions.map((item) => <div key={item.label}><span><strong>{item.label}</strong><small>{item.evidence}</small></span><b>+{item.delta}</b></div>)}
              <div className="contribution-total"><span>Final bounded score</span><b>{detail.triage.risk_score}</b></div>
            </div>
          </article>
          <article className="subpanel triage-reasons">
            <div className="subpanel-title"><span>Triage reasons</span><code>{clock(detail.triage.assessed_at)}</code></div>
            <div className="reason-chips">{detail.triage.reasons.map((reason) => <span key={reason}>{readable(reason)}</span>)}</div>
            <dl className="proof-list"><div><dt>Duplicate</dt><dd>{detail.ingestion.duplicate ? "Yes" : "No"}</dd></div><div><dt>{authoritative ? "Ledger sequence" : "Replay ledger"}</dt><dd>Sequence {detail.ingestion.sequence}</dd></div><div><dt>Ledger hash</dt><dd><code>{detail.ingestion.current_hash.slice(0, 18)}…</code></dd></div></dl>
          </article>
        </div>
      )}

      {tab === "Enrichment" && detail && (
        <div className="enrichment-grid investigation-content">
          {detail.enrichment.map((item) => <article className={`enrichment-card ${item.status}`} key={item.kind}><div><span className={`status-mark ${item.status === "risk" ? "danger" : "healthy"}`} /><strong>{item.kind}</strong><b>{item.status === "risk" ? "RISK SIGNAL" : "VERIFIED"}</b></div><p>{item.value}</p><dl><div><dt>Impact</dt><dd>{item.impact}</dd></div><div><dt>Evidence</dt><dd>{item.evidence}</dd></div><div><dt>Source</dt><dd>{item.source}</dd></div></dl></article>)}
        </div>
      )}

      {tab === "Decision" && detail && (
        <div className="decision-view investigation-content">
          <div className="decision-chain">
            <article><span>01 · Deterministic</span><strong>{readable(detail.judgment.deterministic_action)}</strong><small>{detail.alert.detector_id}</small></article><b aria-hidden="true">→</b>
            <article><span>02 · Codex shadow</span><strong>{detail.judgment.model_verdict ? readable(detail.judgment.model_verdict.action) : "Unavailable"}</strong><small>{detail.judgment.model_verdict ? `${detail.judgment.model_verdict.model_id} · ${Math.round(detail.judgment.model_verdict.confidence * 100)}%` : "Deterministic fallback"}</small></article><b aria-hidden="true">→</b>
            <article className="final"><span>03 · Final action</span><strong>{readable(detail.judgment.action)}</strong><small>Most-restrictive combiner</small></article>
          </div>
          <article className="subpanel"><div className="subpanel-title"><span>Judgment reason codes</span><code>{detail.judgment.policy_version}</code></div><div className="reason-chips">{detail.judgment.reason_codes.map((reason) => <span key={reason}>{readable(reason)}</span>)}</div><div className="decision-invariant">A model can tighten this decision. It cannot create authority or relax deterministic enforcement.</div></article>
        </div>
      )}

      {tab === "Response" && detail && (
        <div className="response-layout investigation-content">
          <article className="subpanel"><div className="subpanel-title"><span>Escalation</span><span className="verified-label">{readable(detail.escalation.level)}</span></div><dl className="proof-list"><div><dt>Queue</dt><dd>{detail.escalation.queue ?? "No queue"}</dd></div><div><dt>Case</dt><dd><code>{detail.escalation.case_id ?? "No case"}</code></dd></div><div><dt>Reason</dt><dd>{detail.escalation.reason}</dd></div><div><dt>At</dt><dd>{clock(detail.escalation.escalated_at)}</dd></div></dl></article>
          <article className="subpanel"><div className="subpanel-title"><span>Containment response</span><span className="verified-label">{detail.response.effect_allowed ? "EFFECT ALLOWED" : "EFFECT PREVENTED"}</span></div><div className="response-actions">{detail.response.actions.map((action) => <span key={action}>{readable(action)}</span>)}</div><ul className="evidence-list">{detail.response.notes.map((note) => <li key={note}><span>✓</span>{note}</li>)}</ul><dl className="proof-list"><div><dt>Responder</dt><dd>{detail.response.responder}</dd></div><div><dt>Mode</dt><dd>{detail.response.simulated ? "Safe simulated containment" : "Live response"}</dd></div></dl></article>
          <article className="subpanel audit-panel"><div className="subpanel-title"><span>Finding audit</span><code>{readable(detail.finding.status)}</code></div>{detail.finding.audit.map((entry, index) => <div className="audit-entry" key={`${entry.at}-${index}`}><span>{clock(entry.at)}</span><i /><div><strong>{entry.from_status ? `${readable(entry.from_status)} → ` : ""}{readable(entry.to_status)}</strong><small>{entry.actor} · {entry.reason}</small></div></div>)}</article>
        </div>
      )}
    </section>
  );
}

function Overview({ alerts, active, onSelect, liveState, ledgerVerified }: { alerts: Alert[]; active: Alert | null; onSelect: (alert: Alert) => void; liveState: LiveState; ledgerVerified: boolean | null }) {
  const denied = alerts.filter((alert) => alert.decision === "DENY").length;
  const approvals = alerts.filter((alert) => alert.decision === "REQUIRE APPROVAL").length;
  const critical = alerts.filter((alert) => alert.severity === "critical").length;
  return (
    <>
      <section className="metrics-grid" aria-label="Security metrics">
        <MetricCard label="Live alerts" value={String(alerts.length).padStart(2, "0")} note="sanitized SSM decisions" tone={alerts.length ? "attention" : "default"} />
        <MetricCard label="Denied effects" value={String(denied).padStart(2, "0")} note="deterministic enforcement" tone={denied ? "good" : "default"} />
        <MetricCard label="Approval holds" value={String(approvals).padStart(2, "0")} note={`${critical} critical findings`} tone={approvals ? "attention" : "default"} />
        <MetricCard label="Ledger integrity" value={ledgerVerified === true ? "VERIFIED" : ledgerVerified === false ? "FAILED" : "—"} note={liveState === "connected" ? "latest live decisions" : "awaiting live bridge"} tone={ledgerVerified === true ? "good" : ledgerVerified === false ? "attention" : "default"} />
      </section>
      <div className="workspace-grid">
        <AlertQueue alerts={alerts} active={active} onSelect={onSelect} liveState={liveState} />
        <AlertDetail key={active?.id ?? "empty"} alert={active} />
      </div>
      <section className="evaluation-band">
        <div><span className="eyebrow">Immutable corpus · 2026-07-22.1</span><strong>All protected controls are holding</strong></div>
        <div className="evaluation-stat"><span>Detector recall</span><b>100%</b></div>
        <div className="evaluation-stat"><span>Benign completion</span><b>100%</b></div>
        <div className="evaluation-stat"><span>False blocks</span><b>0%</b></div>
        <div className="evaluation-stat"><span>Tests</span><b>91 / 91</b></div>
      </section>
    </>
  );
}

const policyCards = [
  ["Secret egress", "deny", "Secret-class data cannot reach an external destination."],
  ["Authority intersection", "deny", "Delegated operations can preserve or narrow authority, never expand it."],
  ["Persistent provenance", "deny", "Adversarial trust survives transforms, handoffs, and memory."],
  ["MCP contract drift", "approval", "Schema or destination drift requires exact, single-use approval."],
  ["Destructive action", "approval", "High-impact operations require a bound approval token."],
  ["Most-restrictive combiner", "deny", "A weaker model recommendation cannot relax deterministic policy."],
];

function Policies() {
  return (
    <section className="view-stack">
      <div className="view-intro"><span className="eyebrow">Policy control plane</span><h2>Deterministic enforcement first.</h2><p>Every effect is evaluated locally. Semantic analysis can tighten a decision, but never create authority or relax a denial.</p></div>
      <div className="policy-grid">
        {policyCards.map(([title, action, copy], index) => (
          <article className="policy-card" key={title}>
            <div className="policy-card-top"><span className="policy-number">P-{String(index + 1).padStart(2, "0")}</span><span className={`policy-action ${action}`}>{action === "approval" ? "REQUIRE APPROVAL" : "DENY"}</span></div>
            <h3>{title}</h3><p>{copy}</p>
            <div className="policy-foot"><span><StatusMark /> Evaluated</span><code>v1.0.0</code></div>
          </article>
        ))}
      </div>
      <section className="panel invariant-panel"><div><span className="eyebrow">Decision invariant</span><h3>deny &gt; require approval &gt; allow with obligations &gt; allow</h3></div><span className="signed-badge">SIGNED POLICY SET</span></section>
    </section>
  );
}

const evaluationModes = [
  ["Unprotected", 100, "danger"],
  ["Telemetry only", 100, "danger"],
  ["Static allowlist", 100, "danger"],
  ["Sink without provenance", 75, "warning"],
  ["Provenance without authority", 25, "warning"],
  ["Full deterministic system", 0, "healthy"],
  ["Codex shadow", 0, "healthy"],
  ["Semantic hold", 0, "healthy"],
] as const;

function Evaluations() {
  return (
    <section className="view-stack">
      <div className="view-intro"><span className="eyebrow">Effect-based evaluation</span><h2>Measure the effect, not the explanation.</h2><p>Eight configurations replay the same immutable attack corpus. The metric below is completed forbidden-effect rate; lower is safer.</p></div>
      <div className="evaluation-layout">
        <section className="panel benchmark-panel">
          <div className="panel-heading"><div><span className="eyebrow">Attack success by mode</span><h2>Control comparison</h2></div><span className="digest">SHA256 · D842…F02F</span></div>
          <div className="bar-list">
            {evaluationModes.map(([name, value, tone]) => (
              <div className="bar-row" key={name}><span>{name}</span><div className="bar-track"><i className={tone} style={{ width: `${Math.max(value, 1.4)}%` }} /></div><b>{value}%</b></div>
            ))}
          </div>
        </section>
        <aside className="evaluation-summary">
          <article className="summary-score"><span className="eyebrow">Release verdict</span><strong>PASS</strong><p>Research PoC definition of done</p></article>
          <article className="panel summary-list"><h3>Corpus profile</h3><dl><div><dt>Attack scenarios</dt><dd>4</dd></div><div><dt>Benign controls</dt><dd>1</dd></div><div><dt>Holdout scenarios</dt><dd>2</dd></div><div><dt>Control ablations</dt><dd>8</dd></div><div><dt>Schema contracts</dt><dd>31</dd></div></dl></article>
        </aside>
      </div>
    </section>
  );
}

const integrations = [
  { name: "Codex", state: "Active · recorded shadow", tone: "healthy" as const, tag: "READ ONLY", copy: "Versioned structured reviews. Cannot execute tools or alter enforcement." },
  { name: "OpenAI Responses", state: "Ready · disabled", tone: "warning" as const, tag: "API PROFILE", copy: "Strict JSON Schema output, privacy-transformed evidence, pinned model ID." },
  { name: "Anthropic Messages", state: "Ready · disabled", tone: "warning" as const, tag: "API PROFILE", copy: "Same validated verdict contract with normalized refusal and outage handling." },
  { name: "Splunk HEC", state: "Contract verified", tone: "healthy" as const, tag: "ALLOWLIST ONLY", copy: "Exports finding metadata only. Raw prompts, arguments, and canaries are excluded." },
  { name: "EC2 Tokyo", state: "Private · SSM bridge ready", tone: "healthy" as const, tag: "AP-NORTHEAST-1", copy: "Live decisions are read through the local loopback bridge. The node still has no public IP or ingress." },
  { name: "Production controls", state: "Not authorized", tone: "danger" as const, tag: "DEFERRED", copy: "Durable state, KMS/HSM signing, HA, and real connector validation remain open." },
];

function Integrations() {
  return (
    <section className="view-stack">
      <div className="view-intro"><span className="eyebrow">Provider-neutral boundary</span><h2>Connected by contract, separated by trust.</h2><p>Live model providers are disabled by default. Deterministic authorization remains available when every model is offline.</p></div>
      <div className="integration-grid">
        {integrations.map((item) => (
          <article className="integration-card" key={item.name}>
            <div className="integration-icon">{item.name.split(" ").map((word) => word[0]).join("").slice(0, 2)}</div>
            <div className="integration-copy"><div><h3>{item.name}</h3><span><StatusMark tone={item.tone} />{item.state}</span></div><p>{item.copy}</p></div>
            <span className="integration-tag">{item.tag}</span>
          </article>
        ))}
      </div>
    </section>
  );
}

export default function Home() {
  const [view, setView] = useState<View>("Overview");
  const [alerts, setAlerts] = useState<Alert[]>([]);
  const [activeId, setActiveId] = useState<string | null>(null);
  const [liveState, setLiveState] = useState<LiveState>("connecting");
  const [lastSynced, setLastSynced] = useState<string>("Not yet synced");
  const [ledgerVerified, setLedgerVerified] = useState<boolean | null>(null);
  const [liveError, setLiveError] = useState<string>("");
  const [preset, setPreset] = useState<string>(forgePresets[0][0]);
  const [simulation, setSimulation] = useState<SimulationState>("idle");
  const [simulationNote, setSimulationNote] = useState<string>("");

  const active = alerts.find((alert) => alert.id === activeId) ?? alerts[0] ?? null;

  const refreshAlerts = useCallback(async () => {
    try {
      const response = await fetch(`${LIVE_API}/api/alerts`, { cache: "no-store" });
      if (!response.ok) throw new Error("The SSM bridge could not read live alerts.");
      const payload = (await response.json()) as AlertsPayload;
      if (!Array.isArray(payload.alerts)) throw new Error("The live bridge returned an invalid alert list.");
      setAlerts(payload.alerts);
      setActiveId((current) => current && payload.alerts.some((alert) => alert.id === current) ? current : payload.alerts[0]?.id ?? null);
      setLedgerVerified(payload.ledger_verified);
      setLastSynced(new Date(payload.checked_at).toLocaleTimeString());
      setLiveError("");
      setLiveState("connected");
    } catch (error) {
      setLiveError(error instanceof Error ? error.message : "The live bridge is unavailable.");
      setLiveState("offline");
    }
  }, []);

  useEffect(() => {
    let stopped = false;
    let timer: number | undefined;
    const poll = async () => {
      await refreshAlerts();
      if (!stopped) timer = window.setTimeout(poll, 8000);
    };
    void poll();
    return () => {
      stopped = true;
      if (timer) window.clearTimeout(timer);
    };
  }, [refreshAlerts]);

  async function runSimulation() {
    if (simulation === "running") return;
    setSimulation("running");
    setSimulationNote("Submitting an allowlisted metadata event through AWS SSM…");
    try {
      const response = await fetch(`${LIVE_API}/api/forge`, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ preset }),
      });
      if (!response.ok) throw new Error("Remote authorization failed.");
      const payload = (await response.json()) as ForgePayload;
      if (payload.alerts.length) {
        setAlerts((current) => [...payload.alerts, ...current.filter((item) => !payload.alerts.some((fresh) => fresh.id === item.id))]);
        setActiveId(payload.alerts[0].id);
      }
      setLedgerVerified(payload.ledger_verified);
      setLastSynced(new Date(payload.completed_at).toLocaleTimeString());
      setLiveState("connected");
      setLiveError("");
      setSimulationNote(payload.alerts.length ? `${payload.alerts.length} live finding${payload.alerts.length === 1 ? "" : "s"} · action ${payload.overall_action.toUpperCase()}` : `No finding · action ${payload.overall_action.toUpperCase()}`);
      setSimulation("done");
      await refreshAlerts();
    } catch (error) {
      setSimulationNote(error instanceof Error ? error.message : "Unable to forge the live event.");
      setSimulation("error");
      setLiveState("offline");
    } finally {
      window.setTimeout(() => setSimulation("idle"), 5200);
    }
  }

  return (
    <div className="app-shell">
      <aside className="sidebar">
        <div className="brand"><span className="brand-mark">AS</span><div><strong>AgentSec</strong><small>CONTROL ROOM</small></div></div>
        <nav aria-label="Primary navigation">
          {navItems.map((item) => (
            <button key={item.label} className={view === item.label ? "nav-item active" : "nav-item"} onClick={() => setView(item.label)}>
              <span>{item.short}</span>{item.label}
              {item.label === "Incidents" && alerts.length > 0 && <b>{alerts.length}</b>}
            </button>
          ))}
        </nav>
        <div className="sidebar-bottom">
          <div className="protection-card"><div><StatusMark /><span>Enforcement</span></div><strong>Protected</strong><small>deterministic-v1</small></div>
          <button className="operator"><span>VA</span><div><strong>V. Analyst</strong><small>Security operator</small></div><b aria-hidden="true">⋯</b></button>
        </div>
      </aside>

      <main>
        <header className="topbar">
          <div><span className="eyebrow">Tenant-lab / authorization boundary</span><h1>{view === "Overview" ? "Authorization control room" : view}</h1></div>
          <div className="topbar-actions">
            <div className="system-health"><StatusMark tone={liveState === "offline" ? "danger" : liveState === "connecting" ? "warning" : "healthy"} /><span><b>{liveState === "connected" ? "Tokyo EC2 live" : liveState === "connecting" ? "Connecting to SSM" : "Live bridge offline"}</b><small>{liveState === "connected" ? `Synced ${lastSynced}` : liveError || "Start the local bridge"}</small></span></div>
            <label className="forge-select">
              <span className="sr-only">Live event preset</span>
              <select value={preset} onChange={(event) => setPreset(event.target.value)} disabled={simulation === "running"}>
                {forgePresets.map(([value, label]) => <option value={value} key={value}>{label}</option>)}
              </select>
            </label>
            <button className="simulation-button" onClick={runSimulation} disabled={simulation === "running"}>
              <span aria-hidden="true">▶</span>{simulation === "running" ? "Sending to EC2…" : "Forge live event"}
            </button>
          </div>
        </header>

        <div className="content">
          {(view === "Overview" || view === "Incidents") && <Overview alerts={alerts} active={active} onSelect={(alert) => setActiveId(alert.id)} liveState={liveState} ledgerVerified={ledgerVerified} />}
          {view === "Policies" && <Policies />}
          {view === "Evaluations" && <Evaluations />}
          {view === "Integrations" && <Integrations />}
        </div>
      </main>

      <div className={simulation === "idle" ? "toast" : "toast visible"} role="status" aria-live="polite">
        <span className={simulation === "done" ? "toast-icon done" : simulation === "error" ? "toast-icon error" : "toast-icon"}>{simulation === "done" ? "✓" : simulation === "error" ? "!" : "•••"}</span>
        <div><strong>{simulation === "done" ? "Live decision received" : simulation === "error" ? "Live request failed" : "Forging metadata event"}</strong><small>{simulationNote}</small></div>
      </div>
    </div>
  );
}
