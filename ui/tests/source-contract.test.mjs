import assert from "node:assert/strict";
import { readFile } from "node:fs/promises";
import test from "node:test";

const root = new URL("../", import.meta.url);

test("source contains the complete analyst decision surface", async () => {
  const [page, css, layout, packageJson] = await Promise.all([
    readFile(new URL("app/page.tsx", root), "utf8"),
    readFile(new URL("app/globals.css", root), "utf8"),
    readFile(new URL("app/layout.tsx", root), "utf8"),
    readFile(new URL("package.json", root), "utf8"),
  ]);

  for (const stage of ["Detection", "Ingestion", "Enrichment", "Triage", "Judgment", "Escalation", "Response"]) {
    assert.match(page, new RegExp(stage));
  }
  for (const view of ["Overview", "Incidents", "Cases", "Escalations", "Inventory", "Security Graph", "Posture", "Threat Hunting", "Risk Analytics", "Rule Studio", "Policies", "Validation Lab", "Evaluations", "Integrations"]) {
    assert.match(page, new RegExp(view));
  }
  assert.match(page, /Forge live event/);
  assert.match(page, /http:\/\/127\.0\.0\.1:8765/);
  assert.match(page, /\/api\/alerts/);
  assert.match(page, /\/api\/forge/);
  for (const endpoint of ["/api/search", "/api/search/aggregate", "/api/hunts", "/api/evidence/"]) {
    assert.match(page, new RegExp(endpoint.replaceAll("/", "\\/")));
  }
  for (const huntingControl of ["Live threat query", "Search results", "Saved hunts", "Safe pivot", "Protected evidence content never enters the search index"]) {
    assert.match(page, new RegExp(huntingControl));
  }
  assert.match(page, /No fixed or sample alerts are displayed/);
  for (const inventoryControl of ["AI asset inventory", "Effective permissions", "Configuration history", "No fallback assets are shown", "/api/inventory/summary"]) {
    assert.match(page, new RegExp(inventoryControl.replaceAll("/", "\\/")));
  }
  for (const graphControl of ["AI security graph", "Attack-path reconstruction", "Find attack paths", "Blast radius", "HISTORICAL SNAPSHOT", "No fallback topology is shown", "/api/graph/summary", "/api/graph/attack-paths", "/api/graph/blast-radius"]) {
    assert.match(page, new RegExp(graphControl.replaceAll("/", "\\/")));
  }
  assert.match(css, /graph-edges \.highlighted/);
  assert.match(css, /graph-nodes g\.high-risk/);
  for (const postureControl of ["AI security posture management", "Run posture scan", "Posture findings", "Remediation plan", "Time-bounded exception", "Revoke exception", "Historical posture", "No fallback findings are shown", "/api/posture/summary", "/api/posture/scans", "/api/posture/findings", "/api/posture/exceptions/"]) {
    assert.match(page, new RegExp(postureControl.replaceAll("/", "\\/")));
  }
  assert.match(css, /posture-status\.accepted_exception/);
  for (const contentControl of ["Detection content management", "Create signed draft", "Run tests", "Approve independently", "Deploy shadow", "Publish exact digest", "Create reviewed rollback", "Export signed pack", "No fallback rules are shown", "/api/detection/content/health", "/api/detection/content/packs/export"]) {
    assert.match(page, new RegExp(contentControl.replaceAll("/", "\\/")));
  }
  assert.match(css, /content-status\.published/);
  assert.match(css, /studio-gates li\.active/);
  for (const behaviorControl of ["Behavioral analytics & risk engine", "Compare first. Learn only after the security decision", "Why this behavior is abnormal", "Entity-level scoring", "Privacy-safe entity baselines", "Activate immutable tuning", "No fallback baselines or anomaly evidence are shown", "/api/behavior/health", "/api/behavior/anomalies", "/api/behavior/drift", "/api/behavior/config"]) {
    assert.match(page, new RegExp(behaviorControl.replaceAll("/", "\\/")));
  }
  assert.match(css, /behavior-state\.anomaly/);
  assert.match(css, /behavior-baseline-table/);
  for (const correlationControl of ["Finding correlation & incident creation", "One campaign, every finding, and the proof that linked them", "Reconstructed attack sequence", "Linked finding evidence", "Decision ledger", "Start investigation", "Mark contained", "Merge", "Split", "No fallback incidents or synthetic grouping evidence are shown", "/api/correlation/incidents", "/api/correlation/health", "/api/correlation/decisions"]) {
    assert.match(page, new RegExp(correlationControl.replaceAll("/", "\\/")));
  }
  assert.match(css, /correlation-status\.reopened/);
  assert.match(css, /correlation-sequence/);
  for (const caseControl of ["Durable case operations", "Ownership queue", "Acknowledge by", "Independent review queue", "Approve resolution", "OPEN TASKS BLOCK APPROVAL", "Attachment registry", "METADATA ONLY", "Hash-bound case audit", "No sample cases are shown", "/api/cases/health", "/api/case-teams"]) {
    assert.match(page, new RegExp(caseControl.replaceAll("/", "\\/")));
  }
  assert.match(css, /case-sla\.breached/);
  assert.match(css, /case-audit/);
  for (const notificationControl of [
    "Escalations",
    "Escalation & notification operations",
    "Durable delivery worker",
    "Process due deliveries",
    "Versioned on-call ownership",
    "Acknowledge escalation",
    "Channel deliveries",
    "Provider ACK",
    "Redrive dead letter",
    "Credential readiness",
    "Delivery audit",
    "No sample notifications are displayed",
    "/api/notifications/health",
    "/api/notification-destinations",
    "/api/notifications/process",
    "/api/notification-deliveries/",
  ]) {
    assert.match(page, new RegExp(notificationControl.replaceAll("/", "\\/")));
  }
  assert.match(css, /notification-layout/);
  assert.match(css, /notification-state\.dead_letter/);
  assert.match(css, /notification-audit/);
  assert.match(css, /notification-ownership\.breached/);
  for (const notificationControl of ["Escalation & notification operations", "Every SOC handoff is routed, delivered, acknowledged, retried, and proven", "Versioned on-call ownership", "Channel deliveries", "Provider acknowledgment required", "Redrive dead letter", "Delivery audit", "No sample notifications are displayed", "browser cannot invent receipt hashes", "/api/notifications/health", "/api/notification-destinations", "/api/notifications/process", "/redrive"]) {
    assert.match(page, new RegExp(notificationControl.replaceAll("/", "\\/")));
  }
  assert.match(css, /notification-state\.dead_letter/);
  assert.match(css, /notification-attempts/);
  for (const responseControl of [
    "Response",
    "Governed response & playbook automation",
    "Plan safely, approve independently, execute narrowly, verify effects, and roll them back",
    "Global live-response kill switch",
    "Request live approval",
    "Approve exact digest",
    "Execute and verify",
    "Rollback and verify",
    "Independent approval gate",
    "Connector execution & post-effect proof",
    "Tamper-evident history",
    "Playbook library",
    "Playbook editor",
    "Create signed draft",
    "No sample executions or provider evidence are displayed",
    "browser cannot choose either identity",
    "/api/response/executions",
    "/api/response/health",
    "/api/response/connectors",
    "/api/response/control",
    "/api/response/playbooks",
  ]) {
    assert.match(page, new RegExp(responseControl.replaceAll("/", "\\/")));
  }
  assert.match(css, /response-automation-grid/);
  assert.match(css, /response-execution-status\.failed/);
  assert.match(css, /response-step\.rolled_back/);
  assert.match(css, /response-playbook-editor/);
  for (const labControl of [
    "Adversarial simulation and validation lab",
    "Constrained scenario builder",
    "Build and replay",
    "Replay signed run",
    "Selected ground truth",
    "Expected alerts",
    "Observed alerts",
    "Sandbox receipt",
    "NO RAW CONTENT",
    "Network, filesystem and shell disabled",
    "No live validation catalog is available",
    "/api/simulation/catalog",
    "/api/simulation/mutations",
    "/api/simulation/runs",
    "/replay",
  ]) {
    assert.match(page, new RegExp(labControl.replaceAll("/", "\\/")));
  }
  assert.match(css, /validation-builder-grid/);
  assert.match(css, /validation-mode-grid/);
  assert.match(css, /validation-run-proof/);
  assert.doesNotMatch(page, /Math\.random\(\)/);
  for (const platformControl of [
    "Reports",
    "Administration",
    "Evidence-bound reporting",
    "Release claims come from committed machine-readable records",
    "Download verified snapshot",
    "Production is deliberately deferred",
    "Artifact manifest",
    "Administration, platform security & audit",
    "Authenticated BFF trust receipt",
    "Bearer remains server-side",
    "human identity is explicitly not established here",
    "Administration, platform security & audit",
    "Tenant policy",
    "Identity, RBAC & MFA",
    "Workload identity & key lifecycle",
    "Immutable admin audit",
    "Service level objective",
    "Backup & recovery drill",
    "Supply-chain attestation",
    "Reference controls verified; production assurance is not",
    "External IdP federation",
    "external KMS/HSM custody",
    "geographic placement enforcement",
    "distributed HA",
    "PRODUCTION READY: NO",
    "Raw credentials and cryptographic key material are never stored or returned",
    "Real service metrics",
    "24-module completion ledger",
    "No fallback service status is shown",
    "/api/platform",
  ]) {
    assert.match(page, new RegExp(platformControl.replaceAll("/", "\\/")));
  }
  assert.match(page, /className="skip-link"/);
  assert.match(page, /aria-current=/);
  assert.match(page, /id="main-content"/);
  assert.match(css, /:focus-visible/);
  assert.match(css, /\.platform-services/);
  assert.match(css, /\.administration-control-grid/);
  assert.match(css, /\.administration-assurance-grid/);
  assert.match(css, /\.table-scroll/);
  for (const detail of ["AUTHORITATIVE PIPELINE RESULT", "Why this was triaged as real", "Confirmed policy violation", "Enrichment snapshot", "Score contributions", "Codex recorded shadow", "Final most-restrictive action", "Finding audit", "Privacy receipt", "Analyst transition"]) {
    assert.match(page, new RegExp(detail));
  }
  for (const state of ["loading", "complete", "summary_only", "unavailable", "failed"]) {
    assert.match(page, new RegExp(`DetailLoadState[\\s\\S]*${state}|${state}[\\s\\S]*DetailLoadState`));
  }
  for (const state of ["complete", "partial", "unavailable", "failed"]) {
    assert.match(page, new RegExp(`Enrichment[\\s\\S]*${state}|${state}[\\s\\S]*Enrichment`));
  }
  for (const enrichmentControl of ["live connectors", "cache hits", "stale", "timed out", "connector_version", "cache_status", "freshness_seconds", "policy_decision", "policy_digest"]) {
    assert.match(page, new RegExp(enrichmentControl));
  }
  for (const analystControl of ["AI Analyst", "Five-role AI security analyst", "Advisory only", "Alternatives considered", "Responsible abstention", "No recommendation was invented", "Read-only evidence tool receipts", "Disagreement register", "Analyst feedback is inert", "cannot create authority, relax deterministic enforcement, send notifications, or execute response actions", "evidence_manifest_sha256", "executive_authority", "human_review_required"]) {
    assert.match(page, new RegExp(analystControl));
  }
  assert.match(css, /analyst-role-grid/);
  assert.match(css, /analyst-role-card\.abstained/);
  assert.match(css, /analyst-disagreement/);
  for (const judgmentControl of ["Deterministic evidence validator", "Mandatory evidence policy", "Claim-to-evidence results", "Machine-checkable claims", "Validation digest", "Automation is always ineligible", "calibrated", "human_gate_reasons", "report_sha256"]) {
    assert.match(page, new RegExp(judgmentControl));
  }
  assert.match(css, /judgment-validation\.rejected/);
  assert.match(css, /validation-claim\.contradicted/);
  assert.match(css, /validation-issues/);
  for (const modelControl of ["Model gateway & AI governance", "Every model call has a route, qualification, budget, and receipt", "Immutable prompt registry", "Qualification ledger", "Sanitized model call ledger", "No static provider cards", "No demonstration calls are invented", "FAIL CLOSED", "/api/model-gateway", "valid_until", "budget_tokens_today", "privacy_canary_leak_rate"]) {
    assert.match(page, new RegExp(modelControl.replaceAll("/", "\\/")));
  }
  assert.match(css, /model-stage\.active/);
  assert.match(css, /model-call-status\.failed/);
  assert.doesNotMatch(page, /EC2 Tokyo/);
  assert.match(page, /Loading authoritative incident detail/);
  assert.match(page, /Math\.round\(item\.confidence \* 100\)/);
  assert.match(css, /enrichment-card\.partial/);
  assert.match(css, /enrichment-card\.unavailable/);
  assert.match(css, /enrichment-card\.failed/);
  assert.match(page, /\/api\/alerts\/\$\{encodeURIComponent\(active\.finding\)\}\/transition/);
  assert.match(page, /Raw prompts: excluded/);
  assert.match(page, /Authorization headers: excluded/);
  assert.match(page, /Verified at response/);
  assert.match(page, /A model can tighten this decision only after evidence validation/);
  assert.match(page, /This recorded shadow is non-executive\. The final action remains deterministic/);
  assert.doesNotMatch(page, /const alerts: Alert\[\] = \[/);
  assert.match(page, /forbidden_effect_attack_success_rate/);
  assert.match(page, /percentage\(deterministic/);
  assert.doesNotMatch(page, /const evaluationModes/);
  for (const evaluationControl of ["42-case blind benchmark", "Per-use-case quality gates", "Feedback never changes production directly", "THREE ACTORS", "Baseline drift passed", "No fabricated citations"]) {
    assert.match(page, new RegExp(evaluationControl.replaceAll(".", "\\.")));
  }
  assert.match(page, /continuous\?\.splits\.holdout/);
  assert.match(css, /@media \(max-width: 600px\)/);
  assert.match(css, /prefers-reduced-motion/);
  assert.match(layout, /og-rule-studio\.png/);
  assert.doesNotMatch(page, /SkeletonPreview|codex-preview/);
  assert.doesNotMatch(packageJson, /react-loading-skeleton/);
});
