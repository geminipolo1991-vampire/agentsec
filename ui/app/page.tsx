"use client";

import { useCallback, useEffect, useMemo, useState } from "react";

type View = "Overview" | "Incidents" | "Cases" | "Escalations" | "Response" | "Inventory" | "Security Graph" | "Posture" | "Threat Hunting" | "Risk Analytics" | "Rule Studio" | "Policies" | "Validation Lab" | "Evaluations" | "Integrations" | "Reports" | "Administration";
type Severity = "critical" | "high" | "medium" | "low" | "info" | "unknown";
type DetailTab = "Summary" | "Timeline" | "Enrichment" | "Triage" | "Judgment" | "AI Analyst" | "Response & Audit";
type DetailLoadState = "loading" | "complete" | "summary_only" | "unavailable" | "failed";

type RiskContribution = {
  category: string;
  label: string;
  delta: number;
  evidence_refs: string[];
  rationale: string;
};

type IncidentDetail = {
  schema_version: string;
  trace_mode: "historical_summary" | "authoritative";
  detail_availability: "complete" | "summary_only";
  incident_id: string;
  alert_type: string;
  summary: {
    finding_id: string; event_id: string; flow_id: string; alert_type: string; title: string;
    agent_id: string; severity: string; priority: string; status: string; decision: string;
    effect_status: string; created_at: string; updated_at: string; detail_availability: string;
  };
  event_context?: {
    tenant_id: string; flow_id: string; agent_id: string; operation: string; source_type: string;
    source_trust: string; source_ref: string; resource_class: string; resource_ref: string;
    destination_class: string; destination_ref?: string | null; data_classes: string[];
    authority_operations: string[]; indicators: string[]; tool_name?: string | null; tool_schema_drift: boolean;
  } | null;
  detection?: {
    detector_id: string;
    rule_version: string;
    confidence: number;
    reason_codes: string[];
    evidence_refs: string[];
    recommended_action: string;
    detected_at: string;
  } | null;
  ingestion?: {
    duplicate: boolean;
    sequence: number;
    current_hash: string;
    ingested_at: string;
  } | null;
  enrichment?: {
    snapshot_id: string; status: "complete" | "partial" | "unavailable" | "failed"; observed_at: string;
    completed_sources: number; total_sources: number; mandatory_context_complete: boolean; warnings: string[];
    connector_sources: number; cache_hits: number; stale_fallbacks: number; timed_out_sources: number; policy_digest?: string | null;
    sources: {
      source: string; status: "complete" | "partial" | "unavailable" | "failed"; observed_at: string; confidence: number;
      facts: Record<string, string | number | boolean | string[]>; evidence_refs: string[]; latency_ms: number;
      affects_triage: boolean; failure_effect: string; connector_version?: string | null;
      cache_status: "not_applicable" | "miss" | "fresh" | "stale"; freshness_seconds?: number | null;
      expires_at?: string | null; policy_decision: string;
    }[];
  } | null;
  analyst_run?: {
    run_id: string; status: "completed" | "partial" | "abstained"; provider: string; model_id: string;
    recording_id?: string | null; policy_version: string; deterministic_action: string; advisory_action: string;
    executive_authority: false; human_review_required: boolean; evidence_manifest_sha256: string;
    started_at: string; completed_at: string; run_sha256: string;
    role_results: {
      role: "triage" | "investigation" | "judge" | "escalation" | "response_advisor";
      status: "completed" | "abstained" | "unavailable"; summary?: string | null; hypothesis?: string | null;
      recommended_action?: string | null; escalation_advice?: string | null; response_advice: string[];
      confidence?: number | null; evidence_ids: string[]; reason_codes: string[];
      claims: { claim_id: string; statement: string; subject: string; fact_key: string; operator: "equals" | "contains" | "exists"; expected_value?: string | number | boolean | string[] | null; evidence_ids: string[] }[];
      alternatives: { title: string; rationale: string; recommended_action?: string | null; evidence_ids: string[] }[];
      uncertainties: string[]; abstention_reason?: string | null; latency_ms: number;
    }[];
    tool_receipts: { receipt_id: string; role: string; tool: string; requested_kinds: string[]; returned_evidence_ids: string[]; result_count: number; receipt_sha256: string }[];
    disagreements: { disagreement_id: string; kind: string; left: string; right: string; left_action?: string | null; right_action?: string | null; rationale: string; evidence_ids: string[] }[];
    validation: {
      report_id: string; policy_version: string; status: "passed" | "human_review" | "rejected";
      deterministic_action: string; machine_action: string; automation_eligible: false; human_gate_required: boolean;
      human_gate_reasons: string[]; accepted_claims: number; rejected_claims: number; calibrated_confidence: number;
      validated_at: string; report_sha256: string;
      mandatory_evidence: { role: string; required_kinds: string[]; cited_kinds: string[]; missing_kinds: string[]; passed: boolean }[];
      claim_results: { claim_id: string; role: string; status: string; evidence_ids: string[]; matched_evidence_ids: string[]; conflicting_evidence_ids: string[]; independent_sources: number; claimed_confidence: number; calibrated_confidence: number; reason_codes: string[] }[];
      contradictions: { left_claim_id: string; right_claim_id: string; subject: string; fact_key: string; evidence_ids: string[]; reason_code: string }[];
      issues: { code: string; severity: "warning" | "error" | "critical"; role?: string | null; message: string; evidence_ids: string[] }[];
    };
  } | null;
  triage?: {
    risk_score: number;
    severity: string;
    priority: string;
    reasons: string[];
    assessed_at: string;
    score_version: string; contributions: RiskContribution[]; sla_minutes: number; route: string;
    missing_context_warnings: string[]; narrative: string; score_reproduced: boolean;
    behavior_assessment_id?: string | null; behavior_anomaly_score?: number | null;
    composite_risk_score?: number | null; behavior_drift_state?: string | null;
  } | null;
  risk_contributions: RiskContribution[];
  judgment?: {
    detector_recommendation: string;
    action: string;
    deterministic_action: string;
    final_action: string;
    combiner_result: string;
    reason_codes: string[];
    ai_mode: string;
    model_status: string;
    model_validation_status: string;
    model_calibrated_confidence?: number | null;
    model_human_gate_required: boolean;
    model_validation_codes: string[];
    policy_version: string;
    judged_at: string;
    model_verdict: null | {
      label: string;
      provider: string;
      model_id: string;
      action: string;
      confidence: number;
      reason_codes: string[];
      evidence_refs: string[];
      uncertainty?: string | null;
    };
  } | null;
  escalation?: {
    level: string;
    queue?: string | null;
    case_id?: string | null;
    reason: string;
    escalated_at: string;
  } | null;
  response?: {
    actions: string[];
    effect_allowed: boolean;
    effect_status: string;
    simulated: boolean;
    responder: string;
    notes: string[];
    responded_at: string;
  } | null;
  finding?: {
    status: string;
    created_at: string;
    updated_at: string;
    audit: { from_status?: string | null; to_status: string; actor: string; reason: string; at: string }[];
  } | null;
  timeline: { stage: string; outcome: string; at: string; evidence: Record<string, unknown> }[];
  validation?: {
    status: string;
    authoritative_pipeline_result: boolean;
    deterministic_match: boolean;
    ledger_committed: boolean;
    ledger_verified: boolean;
    response_simulated: boolean;
    basis: string[];
  };
  privacy: {
    redaction_policy_version: string;
    evidence_handling_policy: string;
    detail_availability: string;
    redaction_count: number;
    hashed_reference_count: number;
    raw_prompts_included: boolean;
    raw_tool_arguments_included: boolean;
    authorization_headers_included: boolean;
    ingest_tokens_included: boolean;
    credentials_included: boolean;
    full_sensitive_content_included: boolean;
  };
  recorded_at: string;
};

type Alert = {
  id: string;
  title: string;
  type: string;
  severity: Severity;
  decision: "DENY" | "REQUIRE APPROVAL" | "ALLOW" | "UNKNOWN";
  state: string;
  time: string;
  agent: string | null;
  operation: string | null;
  resource: string | null;
  source: string | null;
  sourceTrust: string | null;
  destination: string | null;
  reason: string | null;
  finding: string;
  policy: string | null;
  risk: number | null;
  priority?: string;
  effectStatus?: string;
  aiReview: string | null;
  evidence: string[];
  detailAvailability?: "complete" | "summary_only";
  detail?: IncidentDetail | null;
};

type CaseRecord = {
  case_id: string; tenant_id: string; title: string; summary: string; finding_ids: string[];
  correlation_incident_ids: string[]; status: "open" | "investigating" | "pending_review" | "resolved" | "closed";
  priority: "P0" | "P1" | "P2" | "P3"; severity: string; queue?: string | null;
  assigned_to?: string | null; team_id?: string | null; sla_minutes: number;
  acknowledgment_due_at: string; due_at: string; sla_state: "on_track" | "at_risk" | "breached" | "met";
  acknowledged_at?: string | null; resolution_requested_by?: string | null; resolution_requested_at?: string | null;
  approved_by?: string | null; approved_at?: string | null; closed_by?: string | null; closed_at?: string | null;
  version: number; policy_version: string; created_at: string; updated_at: string;
  audit_count: number; audit_head_sha256: string; record_sha256: string;
};

type CaseDetail = {
  case: CaseRecord;
  comments: { comment_id: string; actor_id: string; body: string; created_at: string; comment_sha256: string }[];
  tasks: { task_id: string; title: string; description: string; status: string; assigned_to?: string | null; due_at?: string | null; created_by: string; completed_by?: string | null; updated_at: string; task_sha256: string }[];
  attachments: { attachment_id: string; display_name: string; media_type: string; size_bytes: number; content_sha256: string; evidence_ref: string; scan_status: string; scanner_ref?: string | null; scanned_at?: string | null; uploaded_by: string; created_at: string; attachment_sha256: string }[];
  relationships: { relationship_id: string; kind: string; target_type: string; target_id: string; reason: string; created_by: string; created_at: string }[];
  reviews: { review_id: string; decision: string; reviewer_id: string; comment: string; created_at: string }[];
  audit: { audit_id: string; actor_id: string; action: string; from_status?: string | null; to_status?: string | null; occurred_at: string; sequence: number; previous_sha256: string; audit_sha256: string }[];
};

type CaseHealth = {
  total_cases: number; open_cases: number; pending_review: number; breached_sla: number;
  acknowledgment_breaches: number; resolution_breaches: number; unassigned_cases: number;
  closed_cases: number; open_tasks: number; calculated_at: string;
};

type CaseTeam = { team_id: string; name: string; description: string; member_ids: string[]; created_by: string; created_at: string; team_sha256: string };

type NotificationRecord = {
  notification_id: string; tenant_id: string; finding_id: string; alert_id: string; alert_type: string;
  severity: string; priority: string; decision: string; escalation_level: string; queue: string;
  case_id?: string | null; correlation_incident_id?: string | null; route_id: string;
  policy_version: string; policy_sha256: string; on_call_actor: string; schedule_id: string;
  schedule_version: number; delivery_state: "pending" | "partial" | "delivered" | "dead_letter";
  acknowledgment_state: "pending" | "acknowledged" | "breached"; acknowledgment_due_at: string;
  acknowledged_at?: string | null; acknowledged_by?: string | null; acknowledgment_note?: string | null;
  version: number; created_at: string; updated_at: string; audit_count: number;
  audit_head_sha256: string; record_sha256: string;
};

type NotificationDelivery = {
  delivery_id: string; destination_id: string; channel: "on_call" | "ticket" | "email" | "messaging";
  template_id: string; template_version: number; recipient: string; subject: string; body: string;
  idempotency_key: string; message_sha256: string; status: string; provider_ack_required: boolean;
  attempts: number; redrive_count: number; max_attempts: number; next_attempt_at: string;
  accepted_at?: string | null; acknowledged_at?: string | null; provider_reference_sha256?: string | null;
  provider_receipt_sha256?: string | null; last_error_code?: string | null; updated_at: string; delivery_sha256: string;
};

type NotificationDetail = {
  notification: NotificationRecord;
  deliveries: NotificationDelivery[];
  attempts: { attempt_id: string; delivery_id: string; attempt_number: number; redrive_count: number; outcome: string; error_code?: string | null; provider_receipt_sha256?: string | null; latency_ms: number; attempted_at: string; attempt_sha256: string }[];
  audit: { audit_id: string; sequence: number; actor_id: string; action: string; delivery_state_before?: string | null; delivery_state_after: string; detail_sha256: string; occurred_at: string; previous_sha256: string; audit_sha256: string }[];
};

type NotificationHealth = {
  total: number; pending_deliveries: number; retry_scheduled: number; provider_ack_pending: number;
  dead_letters: number; human_ack_breaches: number; configured_destinations: number; ready_destinations: number;
  oldest_pending_seconds?: number | null; policy_version: string; policy_sha256: string; observed_at: string;
};

type NotificationDestination = { destination_id: string; name: string; channel: string; provider_ack_required: boolean; enabled: boolean; ready: boolean };

type ResponseStep = {
  step_id: string; name: string; operation: string; connector_id: string; target_ref: string;
  expected_state: string; rollback_operation?: string | null; rollback_expected_state?: string | null;
  connector_ready: boolean; status: string; attempt_count: number; last_error_code?: string | null;
  provider_reference_sha256?: string | null; verification_evidence_sha256?: string | null;
  started_at?: string | null; completed_at?: string | null; step_sha256: string;
};
type ResponseExecution = {
  execution_id: string; tenant_id: string; finding_id: string; alert_id: string; case_id?: string | null;
  correlation_incident_id?: string | null; playbook_id: string; playbook_version: number; playbook_sha256: string;
  policy_version: string; policy_sha256: string; mode: "dry_run" | "live"; status: string;
  live_eligible: boolean; readiness_warnings: string[]; requested_by: string; live_requested_by?: string | null;
  rollback_requested_by?: string | null; approval_id?: string | null; rollback_approval_id?: string | null;
  kill_switch_version: number; steps: ResponseStep[]; version: number; created_at: string; updated_at: string;
  started_at?: string | null; completed_at?: string | null; audit_count: number; audit_head_sha256: string; record_sha256: string;
};
type ResponseApproval = {
  approval_id: string; scope: "execute" | "rollback"; plan_sha256: string; approver_id: string;
  reason: string; issued_at: string; expires_at: string; consumed_at?: string | null; approval_sha256: string;
};
type ResponseDetail = {
  execution: ResponseExecution; approval?: ResponseApproval | null; rollback_approval?: ResponseApproval | null;
  attempts: { attempt_id: string; step_id: string; phase: string; attempt_number: number; outcome: string;
    error_code?: string | null; latency_ms: number; provider_reference_sha256?: string | null;
    evidence_sha256?: string | null; attempted_at: string; attempt_sha256: string }[];
  audit: { audit_id: string; sequence: number; actor_id: string; action: string; status_before?: string | null;
    status_after: string; detail_sha256: string; occurred_at: string; previous_sha256: string; audit_sha256: string }[];
};
type ResponseHealth = {
  total_executions: number; dry_runs: number; awaiting_approval: number; running: number; succeeded: number;
  failed: number; rollback_pending: number; rolled_back: number; verification_failures: number; active_playbooks: number;
  configured_connectors: number; ready_connectors: number; kill_switch_active: boolean; kill_switch_version: number;
  average_execution_ms: number; policy_version: string; policy_sha256: string; observed_at: string;
};
type ResponseConnector = { connector_id: string; name: string; operations: string[]; enabled: boolean; ready: boolean };
type ResponseControl = { kill_switch_active: boolean; version: number; changed_by: string; reason: string; changed_at: string; control_sha256: string };
type ResponsePlaybook = {
  status: "draft" | "in_review" | "approved" | "rejected" | "active" | "retired";
  author_id: string; reviewer_id?: string | null; review_comment?: string | null; revision: number;
  created_at: string; updated_at: string; record_sha256: string;
  definition: { playbook_id: string; version: number; name: string; description: string; priority: number; definition_sha256: string;
    trigger: { priorities: string[]; escalation_levels: string[]; alert_types: string[]; decisions: string[] };
    steps: { step_id: string; name: string; operation: string; connector_id: string; target_selector: string;
      expected_state: string; rollback_operation?: string | null; rollback_expected_state?: string | null;
      timeout_seconds: number; requires_approval: boolean }[] };
};

type PlatformService = {
  service_id: string; name: string; state: "available" | "unavailable";
  metrics: Record<string, string | number | boolean | null>; error_code?: string;
};
type PlatformEvaluationMode = {
  mode: string; attack_scenarios: number; benign_scenarios: number;
  benign_task_completion_rate: number; detector_recall: number; false_block_rate: number;
  forbidden_effect_attack_success_rate: number; record_digest: string; sha256: string;
};
type PlatformContinuousTrack = {
  dataset_version: string; dataset_sha256: string; case_count: number; use_case_count: number;
  splits: Record<string, number>;
  blind_execution: boolean; candidate_id: string; candidate_kind: string; provider: string;
  exact_model_id: string; qualified: boolean; live_provider_calls: boolean; route_sha256: string;
  gate_state: "pass" | "block" | "hold"; failed_checks: number; drift_passed?: boolean | null;
  metrics: { cases: number; attack_cases: number; benign_cases: number; alert_precision: number;
    detector_recall: number; forbidden_effect_attack_success_rate: number; benign_task_completion_rate: number;
    severity_exact_agreement_rate: number; evidence_validity_rate: number; safe_action_agreement_rate: number;
    abstention_rate: number; brier_score: number; expected_calibration_error: number; schema_validity_rate: number };
  use_cases: { use_case: string; cases: number; detector_recall: number; safe_action_agreement_rate: number;
    evidence_validity_rate: number; severity_exact_agreement_rate: number }[];
  record_digest: string; sha256: string;
};
type PlatformSnapshot = {
  schema_version: string; source: string; checked_at: string; module_scope: string;
  bff: {
    upstream_authenticated: true; upstream_authentication: string;
    browser_service_auth_exposed: false; network_scope: string;
    human_identity_verified: false; human_identity_boundary: string;
  };
  administration: { state: "unavailable" } | {
    state: "available";
    tenant: { tenant_id: string; display_name: string; status: string; residency_region: string;
      allowed_processing_regions: string[]; retention_days: number; evidence_retention_days: number;
      legal_hold: boolean; encryption_required: boolean; policy_version: number; record_sha256: string };
    identity: { configured: number; enabled: number; role_counts: Record<string, number>;
      access_reviews: number; local_adapter: boolean; external_idp_federated: boolean };
    workload_identity: { configured: number; revoked: number };
    keys: { configured: number; active: number; external_custody_verified: boolean };
    assurance: { audit_entries: number; audit_valid: boolean; latest_slos_passed: boolean;
      latest_recovery_drill_passed: boolean; latest_supply_chain_attestation_passed: boolean;
      geographic_residency_verified: boolean; distributed_ha_verified: boolean;
      production_ready: boolean; boundaries: string[] };
    latest_slo: null | { name: string; observed: number; passed: boolean; error_budget_remaining: number };
    latest_recovery: null | { passed: boolean; observed_rpo_minutes: number; observed_rto_minutes: number;
      integrity_verified: boolean; record_sha256: string };
    latest_supply_chain: null | { release_id: string; passed: boolean; signature_verified: boolean;
      artifact_sha256: string; sbom_sha256: string; provenance_sha256: string };
    audit_checkpoint: null | { sequence: number; current_sha256: string; signature_algorithm: string };
  };
  services: PlatformService[];
  reports: {
    release: { state: "available" | "unavailable"; sha256?: string; schema_version?: string; scope?: string;
      dataset_version?: string; all_passed?: boolean; production_ready?: boolean; discovered_tests?: number;
      criteria?: { id: string; passed: boolean }[]; production_deferred?: string[] };
    evaluation: { state: "available" | "unavailable"; sha256?: string; schema_version?: string;
      dataset_version?: string; manifest_digest?: string;
      artifacts?: { path: string; record_digest: string; sha256: string }[];
      modes?: PlatformEvaluationMode[];
      ablation?: { full_system_attack_success_rate: number; record_digest: string; sha256: string;
        results: { component: string; attack_scenarios: number; forbidden_effect_attack_success_rate: number; affected_scenarios_count: number }[] };
      continuous?: { baseline?: PlatformContinuousTrack; candidate?: PlatformContinuousTrack } };
  };
  modules: { id: string; name: string; status: "not_started" | "in_progress" | "implemented" | "verified"; acceptance_record?: string | null }[];
};

type SimulationVariantProfile = {
  variant: string; locale: string; transformations: string[];
  normalized_signal_required: boolean; raw_content_retained: boolean;
  qualification_boundary: string;
};
type SimulationScenario = {
  scenario_id: string; version: string; name: string; description: string;
  attack: boolean; dataset_split: string; framework_mappings: string[]; tags: string[];
  variant: string; source: string; trusted_ground_truth: boolean; record_sha256: string;
  steps: {
    step_id: string; sequence: number; title: string; attack_stage: string; stimulus_sha256: string;
    event: { event_id: string; flow_id: string; agent_id: string; operation: string; source_type: string; resource: string; destination?: string | null; indicators: string[]; data_classes: string[] };
    ground_truth: { expected_alert_types: string[]; expected_protected_action: string; forbidden_completed_operations: string[]; required_completed_operations: string[] };
  }[];
};
type SimulationCatalog = {
  schema_version: string;
  health: { status: string; scenarios: number; trusted_scenarios: number; imported_unreviewed: number; runs: number; passed_runs: number; failed_runs: number; audit_valid: boolean; sandbox: string; network_enabled: boolean; raw_content_retained: boolean };
  variants: SimulationVariantProfile[];
  scenarios: { scenarios: SimulationScenario[]; count: number; total: number };
  safety_invariants: string[];
};
type SimulationRun = {
  run_id: string; request_id: string; scenario_id: string; scenario_version: string;
  scenario_sha256: string; variant: string; mode: string; replay_of?: string | null;
  trusted_ground_truth: boolean; passed: boolean; started_at: string; completed_at: string;
  record_sha256: string;
  sandbox: { engine: string; local_only: boolean; network_enabled: boolean; filesystem_enabled: boolean; shell_enabled: boolean; completed_modes: number; completed_steps: number; observed_effects: number; receipt_sha256: string };
  results: {
    protected: boolean; expectation_met: boolean; forbidden_effect_count: number; detected_alert_count: number;
    steps: { step_id: string; sequence: number; expected_alert_types: string[]; observed_alert_types: string[]; expected_action: string; observed_action: string; effect_completed: boolean; completed_operations: string[]; forbidden_effects_completed: string[]; required_effects_missing: string[]; alert_ids: string[]; finding_ids: string[]; ground_truth_passed: boolean; expectation_met: boolean; reasons: string[] }[];
  }[];
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

type IncidentPayload = {
  detail_availability: "complete" | "summary_only";
  finding_id?: string;
  incident: IncidentDetail | null;
};

type SearchHit = {
  record_type: string;
  record_id: string;
  created_at: string;
  severity?: string | null;
  risk_score?: number | null;
  confidence?: number | null;
  title?: string | null;
  projection: Record<string, unknown>;
};

type SearchPage = {
  query: string;
  hits: SearchHit[];
  total: number;
  next_cursor?: string | null;
  elapsed_ms: number;
};

type SearchAggregation = {
  field: string;
  buckets: { value: string; count: number }[];
};

type SavedHunt = {
  hunt_id: string;
  name: string;
  description: string;
  query: string;
  updated_at: string;
};

type EvidencePivot = {
  evidence_id: string;
  evidence: Record<string, unknown>;
  related_records: SearchHit[];
  protected_content_included: false;
};

type InventoryPermission = {
  operation: string;
  resource_scope: string;
  effect: string;
  approved: boolean;
  source_ref: string;
};

type InventoryComponent = {
  component_id: string;
  kind: "application" | "agent" | "model" | "tool" | "data_store";
  name: string;
  external_ref: string;
  application_id?: string | null;
  owner_ref?: string | null;
  criticality: string;
  status: string;
  source: string;
  permissions: InventoryPermission[];
  configuration: Record<string, string | number | boolean | null>;
  configuration_version: number;
  risk_score: number;
  risk_reasons: string[];
  last_seen_at: string;
};

type InventorySummary = {
  total_components: number;
  by_kind: Record<string, number>;
  active_components: number;
  unmanaged_components: number;
  unowned_components: number;
  high_risk_components: number;
  maximum_risk_score: number;
};

type InventoryDetail = {
  component: InventoryComponent;
  configuration_history: { version: number; changed_fields: string[]; observed_at: string; configuration_digest: string }[];
  relationships: { source_component_id: string; relationship: string; target_component_id: string }[];
  risk_rollup: { score: number; component_count: number; high_risk_components: number; unowned_components: number; unapproved_permissions: number; reasons: string[] };
};

type SecurityGraphNode = {
  node_id: string;
  node_type: "application" | "agent" | "model" | "tool" | "data_store" | "source" | "resource" | "destination" | "decision" | "finding";
  name: string;
  risk_score: number;
  criticality: string;
  labels: Record<string, string>;
  source_ref: string;
  valid_from: string;
};

type SecurityGraphEdge = {
  edge_id: string;
  source_node_id: string;
  target_node_id: string;
  edge_type: string;
  weight: number;
  risk_factors: string[];
  evidence_refs: string[];
  valid_from: string;
};

type SecurityGraphSnapshot = {
  tenant_id: string;
  as_of: string;
  nodes: SecurityGraphNode[];
  edges: SecurityGraphEdge[];
  truncated: boolean;
};

type SecurityGraphSummary = {
  as_of: string;
  node_count: number;
  edge_count: number;
  by_node_type: Record<string, number>;
  high_risk_nodes: number;
  external_destinations: number;
};

type AttackPathResult = {
  paths: { node_ids: string[]; edge_ids: string[]; total_weight: number; exposure_score: number; risk_factors: string[] }[];
  explored_states: number;
  truncated: boolean;
};

type BlastRadiusResult = {
  origin_node_id: string;
  impacted_nodes: { node_id: string; depth: number; risk_score: number; via_edge_id?: string | null }[];
  impacted_count: number;
  high_risk_count: number;
  maximum_risk_score: number;
};

type PostureFinding = {
  finding_id: string; check_id: string; check_version: string; component_id: string;
  component_kind: string; component_name: string; title: string; severity: string;
  risk_score: number; status: "open" | "accepted_exception" | "resolved";
  observed: Record<string, string>; remediation: string[]; framework_mappings: string[];
  first_seen_at: string; last_seen_at: string; resolved_at?: string | null;
};
type PostureSummary = { enabled_checks: number; total_findings: number; open_findings: number; accepted_exceptions: number; resolved_findings: number; critical_open_findings: number; posture_score: number; latest_scan_at?: string | null };
type PostureCheck = { check_id: string; version: string; title: string; severity: string; applicable_kinds: string[]; framework_mappings: string[]; enabled: boolean };
type PostureTrend = { scan_id: string; completed_at: string; posture_score: number; failing: number; passing: number; open_findings: number; accepted_exceptions: number };
type PostureDetail = { finding: PostureFinding; exception?: { exception_id: string; owner_ref: string; approved_by: string; reason: string; status: string; expires_at: string } | null; check: PostureCheck & { description: string; remediation: string[] } };
type RuleResult = {
  definition_sha256: string; event_count: number; alert_count?: number; passed?: boolean;
  false_positive_event_ids?: string[]; false_negative_event_ids?: string[]; errors: string[];
  match_rate?: number; duration_ms: number; completed_at: string;
};
type RuleContent = {
  content_id: string; revision: number; status: string; author_id: string; reviewer_id?: string | null;
  review_comment?: string | null; created_at: string; updated_at: string; record_sha256: string;
  definition: Record<string, unknown> & { rule_id: string; version: string; name: string; kind: string; severity: string; enabled: boolean };
  validation?: RuleResult | null; backtest?: RuleResult | null; shadow_result?: RuleResult | null;
};
type ContentHealth = {
  total_content: number; draft: number; in_review: number; approved: number; shadow: number;
  published: number; rejected: number; retired: number; validation_failures: number;
  rule_health: { rule_id: string; active_version: string; evaluation_count: number; match_count: number; error_count: number }[];
};

type BehaviorRiskFactor = {
  factor: string; entity_ref: string; observed: string; expected: string;
  probability: number; contribution: number; evidence_refs: string[]; rationale: string;
};
type BehaviorEntityScore = {
  entity_ref: string; entity_type: string; baseline_revision: number; observation_count: number;
  baseline_state: "learning" | "active"; anomaly_score: number; confidence: number;
  factors: BehaviorRiskFactor[]; evaluated_at: string;
};
type BehaviorAssessment = {
  assessment_id: string; event_id: string; feature_sha256: string; config_id: string; config_version: string;
  entity_scores: BehaviorEntityScore[]; anomaly_score: number; composite_risk_score: number;
  is_anomaly: boolean; cold_start: boolean; drift_state: string; factors: BehaviorRiskFactor[];
  learning_status: "pending" | "learned" | "rejected"; learning_reason?: string | null; evaluated_at: string;
};
type BehaviorBaseline = {
  entity_ref: string; entity_type: string; revision: number; state: "learning" | "active";
  observation_count: number; operation_counts: Record<string, number>; destination_counts: Record<string, number>;
  source_trust_counts: Record<string, number>; hour_counts: Record<string, number>;
  authority_gap_count: number; sensitive_data_count: number; schema_drift_count: number; effectful_count: number;
  first_observed_at: string; last_observed_at: string; config_version: string; baseline_sha256: string;
};
type BehaviorTuningInput = {
  config_id: string; version: string; minimum_observations: number; maximum_observations: number;
  rare_probability: number; anomaly_threshold: number; operation_weight: number; destination_weight: number;
  source_trust_weight: number; time_weight: number; authority_weight: number; sensitive_weight: number;
  schema_drift_weight: number; drift_window_size: number; drift_warning_rate: number;
  drift_critical_rate: number; retention_days: number;
};
type BehaviorTuningConfig = BehaviorTuningInput & {
  tenant_id: string; active: boolean; created_by: string; reason: string;
  created_at: string; config_sha256: string;
};
type BehaviorDrift = {
  entity_ref?: string | null; window_size: number; anomaly_count: number; anomaly_rate: number;
  average_score: number; drift_score: number; state: string; reasons: string[];
  config_version: string; calculated_at: string;
};
type BehaviorHealth = {
  total_baselines: number; learning_baselines: number; active_baselines: number;
  total_assessments: number; anomalies: number; learned: number; rejected_learning: number;
  drift: BehaviorDrift; active_config: BehaviorTuningConfig; calculated_at: string;
};
type CorrelationFindingLink = {
  finding_id: string; alert_id: string; event_id: string; alert_type: string; title: string;
  severity: string; risk_score: number; priority: string; decision: string; attack_stage: string;
  flow_ref: string; agent_ref: string; entity_refs: string[]; evidence_refs: string[];
  correlation_reasons: string[]; correlation_score: number; sequence_order: number;
  occurred_at: string; linked_at: string;
};
type CorrelatedIncident = {
  incident_id: string; title: string; status: string; severity: string; priority: string;
  risk_score: number; finding_count: number; finding_links: CorrelationFindingLink[];
  attack_sequence: { order: number; stage: string; finding_id: string; event_id: string; occurred_at: string; evidence_refs: string[] }[];
  entity_refs: string[]; evidence_refs: string[]; correlation_policy_version: string;
  reopened_count: number; parent_incident_id?: string | null; superseded_by?: string | null;
  revision: number; audit: { action: string; actor_id: string; reason: string; at: string }[];
  created_at: string; updated_at: string; closed_at?: string | null; incident_sha256: string;
};
type CorrelationDecision = {
  decision_id: string; finding_id: string; outcome: string; incident_id?: string | null;
  suppression_id?: string | null; selected_score: number; reasons: string[]; policy_version: string;
  decided_at: string; decision_sha256: string;
};
type CorrelationHealth = {
  total_incidents: number; open_incidents: number; closed_incidents: number; merged_incidents: number;
  total_findings: number; multi_finding_incidents: number; suppressed_findings: number;
  active_suppressions: number; calculated_at: string;
};
type ModelGatewayProviderHealth = {
  route_id: string; route_revision: number; provider: "openai" | "anthropic";
  stage: "candidate" | "shadow" | "active" | "retired"; circuit_state: "closed" | "open";
  consecutive_failures: number; successful_calls: number; failed_calls: number;
  last_latency_ms?: number | null; last_error_code?: string | null; circuit_open_until?: string | null;
  qualification_id?: string | null; secret_ready: boolean; budget_requests_last_minute: number;
  budget_tokens_today: number; in_flight: number; calculated_at: string;
};
type ModelGatewayRoute = {
  route_id: string; revision: number; provider: "openai" | "anthropic"; exact_model_id: string;
  workload: string; allowed_modes: string[]; allowed_data_classes: string[]; region: string;
  priority: number; fallback_route_id?: string | null; max_requests_per_minute: number;
  max_tokens_per_day: number; max_concurrency: number; max_output_tokens: number;
  stage: "candidate" | "shadow" | "active" | "retired"; prompt_id: string; prompt_version: number;
  secret_id: string; secret_version: number; route_sha256: string; created_at: string;
};
type ModelGatewayPrompt = {
  prompt_id: string; version: number; workload: string; output_schema_sha256: string;
  author_id: string; created_at: string; prompt_sha256: string;
};
type ModelGatewayQualification = {
  qualification_id: string; route_id: string; route_revision: number; exact_model_id: string;
  test_suite_version: string; evidence_sha256: string; passed: boolean; executed_by: string;
  reviewed_by: string; qualified_at: string; valid_until: string;
  metrics: { fixture_count: number; schema_valid_rate: number; citation_valid_rate: number; forbidden_effect_rate: number; privacy_canary_leak_rate: number; fallback_test_passed: boolean; deterministic_relaxation_rate: number };
};
type ModelGatewayCall = {
  call_id: string; route_id: string; route_revision: number; provider: string; exact_model_id: string;
  prompt_id: string; prompt_version: number; workload: string; mode: string; data_classes: string[];
  status: "reserved" | "completed" | "failed" | "denied"; reserved_tokens: number;
  input_tokens: number; output_tokens: number; total_tokens: number; latency_ms: number;
  provider_request_id?: string | null; output_sha256?: string | null; error_code?: string | null;
  created_at: string; completed_at?: string | null;
};
type ModelGatewayPayload = {
  health: {
    tenant_id: string; policy_version: string; prompts: number; routes: number; active_routes: number;
    qualified_routes: number; open_circuits: number; providers: ModelGatewayProviderHealth[];
    calculated_at: string;
  };
  routes: ModelGatewayRoute[]; prompts: ModelGatewayPrompt[];
  qualifications: ModelGatewayQualification[]; calls: ModelGatewayCall[]; checked_at: string;
};

const LIVE_API = "http://127.0.0.1:8765";

type PlatformLoadState = "loading" | "ready" | "offline";

function usePlatformSnapshot() {
  const [snapshot, setSnapshot] = useState<PlatformSnapshot | null>(null);
  const [state, setState] = useState<PlatformLoadState>("loading");
  const [message, setMessage] = useState("Loading live service and committed release evidence…");

  const refresh = useCallback(async (signal?: AbortSignal) => {
    setState("loading");
    try {
      const response = await fetch(`${LIVE_API}/api/platform`, { cache: "no-store", signal });
      if (!response.ok) throw new Error(`Platform snapshot is unavailable (${response.status}).`);
      const next = await response.json() as PlatformSnapshot;
      if (!Array.isArray(next.services) || !Array.isArray(next.modules) || !next.bff || !next.reports) {
        throw new Error("Platform snapshot returned an invalid contract.");
      }
      if (signal?.aborted) return;
      setSnapshot(next);
      setState("ready");
      setMessage(`Live product health and committed reports synchronized at ${new Date(next.checked_at).toLocaleString()}.`);
    } catch (error) {
      if (signal?.aborted) return;
      setSnapshot(null);
      setState("offline");
      setMessage(error instanceof Error ? error.message : "Platform snapshot is unavailable.");
    }
  }, []);

  useEffect(() => {
    const controller = new AbortController();
    const timer = window.setTimeout(() => { void refresh(controller.signal); }, 0);
    return () => { window.clearTimeout(timer); controller.abort(); };
  }, [refresh]);

  return { snapshot, state, message, refresh };
}

function percentage(value?: number) {
  return value == null ? "—" : `${Math.round(value * 100)}%`;
}

function evaluationModeLabel(mode: string) {
  const labels: Record<string, string> = {
    unprotected: "Unprotected",
    telemetry_only: "Telemetry only",
    static_allowlist: "Static allowlist",
    sink_without_provenance: "Sink without provenance",
    provenance_without_authority: "Provenance without authority",
    deterministic: "Full deterministic system",
    codex_shadow: "Codex shadow",
    semantic_hold: "Semantic hold",
  };
  return labels[mode] ?? readable(mode);
}

const forgePresets = [
  ["indirect_injection_secret_egress", "Prompt injection + secret egress"],
  ["confused_deputy_authority_expansion", "Authority expansion + destructive action"],
  ["persistent_memory_poisoning", "Persistent memory poisoning"],
  ["mcp_schema_drift", "MCP tool contract drift"],
  ["benign_inventory_read", "Benign inventory read"],
] as const;

const stages = ["Detection", "Ingestion", "Enrichment", "Triage", "Judgment", "Escalation", "Response"];

const navItems: { label: View; short: string }[] = [
  { label: "Overview", short: "OV" },
  { label: "Incidents", short: "IN" },
  { label: "Cases", short: "CA" },
  { label: "Escalations", short: "ES" },
  { label: "Response", short: "RX" },
  { label: "Inventory", short: "IV" },
  { label: "Security Graph", short: "SG" },
  { label: "Posture", short: "PM" },
  { label: "Threat Hunting", short: "TH" },
  { label: "Risk Analytics", short: "RA" },
  { label: "Rule Studio", short: "RS" },
  { label: "Policies", short: "PO" },
  { label: "Validation Lab", short: "VL" },
  { label: "Evaluations", short: "EV" },
  { label: "Integrations", short: "CN" },
  { label: "Reports", short: "RP" },
  { label: "Administration", short: "AD" },
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
              <span className="alert-meta"><code>{alert.operation}</code> · {alert.agent}<em>{alert.detailAvailability === "complete" ? "COMPLETE" : "SUMMARY ONLY"}</em></span>
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

function display(value: unknown) {
  if (value === null || value === undefined || value === "") return "—";
  if (Array.isArray(value)) return value.join(", ") || "—";
  if (typeof value === "object") return JSON.stringify(value);
  return String(value);
}

function AiAnalystView({ run }: { run: NonNullable<IncidentDetail["analyst_run"]> }) {
  const validation = run.validation;
  return (
    <div className="analyst-view investigation-content">
      <article className={`analyst-run-summary ${run.status}`}>
        <div><span className="eyebrow">Five-role AI security analyst</span><strong>{readable(run.status)}</strong><small>{run.provider} · {run.model_id} · {run.recording_id ?? "live governed run"}</small></div>
        <dl><div><dt>Authority</dt><dd>{run.executive_authority ? "Executive" : "Advisory only"}</dd></div><div><dt>Deterministic</dt><dd>{readable(run.deterministic_action)}</dd></div><div><dt>Advisory</dt><dd>{readable(run.advisory_action)}</dd></div><div><dt>Human review</dt><dd>{run.human_review_required ? "Required" : "Standard review"}</dd></div><div><dt>Policy</dt><dd><code>{run.policy_version}</code></dd></div><div><dt>Run</dt><dd><code>{run.run_id}</code></dd></div></dl>
        <p>This analysis is non-executive. It cannot create authority, relax deterministic enforcement, send notifications, or execute response actions.</p>
      </article>
      <section className={`judgment-validation ${validation.status}`}>
        <header><div><span className="eyebrow">Deterministic evidence validator</span><h3>{readable(validation.status)}</h3></div><strong>{Math.round(validation.calibrated_confidence * 100)}% calibrated</strong></header>
        <div className="validation-metrics"><div><span>Machine action</span><b>{readable(validation.machine_action)}</b><small>Deterministic only</small></div><div><span>Claims</span><b>{validation.accepted_claims} accepted</b><small>{validation.rejected_claims} rejected</small></div><div><span>Human gate</span><b>{validation.human_gate_required ? "Required" : "Policy passed"}</b><small>Automation is always ineligible</small></div><div><span>Policy</span><code>{validation.policy_version}</code><small>{clock(validation.validated_at)}</small></div></div>
        {validation.human_gate_reasons.length > 0 && <div className="validation-gates"><span>Gate reasons</span>{validation.human_gate_reasons.map((reason) => <code key={reason}>{reason}</code>)}</div>}
        <div className="validation-grid"><article><strong>Mandatory evidence policy</strong>{validation.mandatory_evidence.map((check) => <div className={`validation-check ${check.passed ? "passed" : "failed"}`} key={check.role}><span>{readable(check.role)}</span><b>{check.passed ? "Complete" : "Missing evidence"}</b><small>Required: {check.required_kinds.map(readable).join(" · ")}</small>{check.missing_kinds.length > 0 && <code>{check.missing_kinds.join(", ")}</code>}</div>)}</article><article><strong>Claim-to-evidence results</strong>{validation.claim_results.length ? validation.claim_results.map((claim) => <div className={`validation-claim ${claim.status}`} key={claim.claim_id}><span>{readable(claim.role)} · {readable(claim.status)}</span><b>{Math.round(claim.claimed_confidence * 100)}% model → {Math.round(claim.calibrated_confidence * 100)}% calibrated</b><small>{claim.matched_evidence_ids.length} matched · {claim.independent_sources} independent source(s)</small><code>{claim.reason_codes.join(" · ")}</code></div>) : <div className="validation-check failed"><span>No structured claims</span><b>Human review required</b></div>}</article></div>
        {validation.issues.length > 0 && <div className="validation-issues">{validation.issues.map((issue, index) => <div className={issue.severity} key={`${issue.code}:${index}`}><strong>{issue.code}</strong><span>{issue.role ? `${readable(issue.role)} · ` : ""}{issue.message}</span></div>)}</div>}
        {validation.contradictions.length > 0 && <div className="validation-contradictions"><strong>Contradictions</strong>{validation.contradictions.map((item) => <div key={`${item.left_claim_id}:${item.right_claim_id}`}><span>{item.subject} · {readable(item.fact_key)}</span><code>{item.left_claim_id} ↔ {item.right_claim_id}</code></div>)}</div>}
        <div className="validation-proof"><span>Validation digest</span><code>{validation.report_sha256}</code></div>
      </section>
      <div className="analyst-role-grid">{run.role_results.map((role, index) => <article className={`analyst-role-card ${role.status}`} key={role.role}><header><span>{String(index + 1).padStart(2, "0")}</span><strong>{readable(role.role)}</strong><b>{readable(role.status)}</b></header>{role.status === "completed" ? <><p>{role.summary}</p>{role.hypothesis && <div className="analyst-hypothesis"><span>Hypothesis</span>{role.hypothesis}</div>}<dl><div><dt>Confidence</dt><dd>{role.confidence != null ? `${Math.round(role.confidence * 100)}%` : "—"}</dd></div><div><dt>Recommendation</dt><dd>{role.recommended_action ? readable(role.recommended_action) : "Context only"}</dd></div><div><dt>Latency</dt><dd>{role.latency_ms} ms</dd></div><div><dt>Evidence</dt><dd>{role.evidence_ids.length} cited</dd></div></dl>{role.escalation_advice && <div className="analyst-advice"><span>Escalation advice</span>{role.escalation_advice}</div>}{role.response_advice.map((advice) => <div className="analyst-advice" key={advice}><span>Response advice</span>{advice}</div>)}<div className="analyst-citations"><span>Claim evidence citations</span>{role.evidence_ids.map((evidenceId) => <code key={evidenceId}>{evidenceId}</code>)}</div>{role.claims.length > 0 && <div className="analyst-claims"><span>Machine-checkable claims</span>{role.claims.map((claim) => <div key={claim.claim_id}><strong>{claim.statement}</strong><small>{claim.fact_key} {claim.operator} {display(claim.expected_value)}</small><code>{claim.evidence_ids.join(", ")}</code></div>)}</div>}<div className="analyst-reason-codes"><span>Reason codes</span>{role.reason_codes.map((reasonCode) => <code key={reasonCode}>{reasonCode}</code>)}</div><div className="analyst-alternatives"><span>Alternatives considered</span>{role.alternatives.map((alternative) => <div key={alternative.title}><strong>{alternative.title}</strong><p>{alternative.rationale}</p><small>{alternative.recommended_action ? `Advisory: ${readable(alternative.recommended_action)}` : "No action proposed"}</small><code>{alternative.evidence_ids.join(", ")}</code></div>)}</div>{role.uncertainties.length > 0 && <div className="analyst-uncertainty"><span>Uncertainty</span>{role.uncertainties.join(" · ")}</div>}</> : <div className="analyst-abstention"><strong>{role.status === "abstained" ? "Responsible abstention" : "Role unavailable"}</strong><p>{role.abstention_reason}</p><span>No recommendation was invented.</span></div>}</article>)}</div>
      <div className="analyst-proof-grid"><article className="subpanel"><div className="subpanel-title"><span>Read-only evidence tool receipts</span><code>{run.evidence_manifest_sha256.slice(0, 16)}</code></div>{run.tool_receipts.map((receipt) => <div className="analyst-receipt" key={receipt.receipt_id}><strong>{readable(receipt.role)}</strong><span>{receipt.tool} · {receipt.result_count} returned</span><small>Requested: {receipt.requested_kinds.map(readable).join(" · ")}</small><div>{receipt.returned_evidence_ids.map((evidenceId) => <code key={evidenceId}>{evidenceId}</code>)}</div><code>{receipt.receipt_sha256}</code></div>)}</article><article className="subpanel"><div className="subpanel-title"><span>Disagreement register</span><code>{run.disagreements.length}</code></div>{run.disagreements.length ? run.disagreements.map((item) => <div className="analyst-disagreement" key={item.disagreement_id}><strong>{readable(item.kind)}</strong><span>{item.left} ↔ {item.right}</span><p>{item.rationale}</p><small>{item.left_action ? readable(item.left_action) : "no action"}{item.right_action ? ` → ${readable(item.right_action)}` : ""}</small>{item.evidence_ids.map((evidenceId) => <code key={evidenceId}>{evidenceId}</code>)}</div>) : <div className="analyst-no-disagreement"><StatusMark /><span>All completed recommendations preserve the deterministic action.</span></div>}<div className="analyst-feedback-note"><strong>Analyst feedback is inert</strong><span>Authenticated feedback is audit evidence only and is never applied to a model or policy automatically.</span></div></article></div>
      <div className="analyst-run-proof"><span>Run digest</span><code>{run.run_sha256}</code><span>{clock(run.started_at)} → {clock(run.completed_at)}</span></div>
    </div>
  );
}

function AlertDetail({
  alert,
  detail,
  loadState,
  onTransition,
}: {
  alert: Alert | null;
  detail: IncidentDetail | null;
  loadState: DetailLoadState;
  onTransition: (action: string, reason: string) => Promise<void>;
}) {
  const [tab, setTab] = useState<DetailTab>("Summary");
  const [reason, setReason] = useState("Analyst reviewed the recorded incident evidence");
  const [transitioning, setTransitioning] = useState("");

  if (!alert) {
    return (
      <section className="panel detail-panel empty-detail" aria-label="Live alert details">
        <div>
          <span className="eyebrow">Live authorization trace</span>
          <h2>Waiting for a sanitized decision</h2>
          <p>Forge an event or connect the loopback bridge. The browser receives allowlisted incident records—never AWS credentials, ingest tokens, raw prompts, or tool arguments.</p>
        </div>
        <ol className="lifecycle pending-lifecycle">
          {stages.map((stage, index) => <li key={stage}><span className="stage-index">{String(index + 1).padStart(2, "0")}</span><span className="stage-dot" /><span className="stage-name">{stage}</span><span className="stage-result">pending</span></li>)}
        </ol>
      </section>
    );
  }

  const complete = detail?.detail_availability === "complete";
  const detection = complete ? detail.detection : null;
  const ingestion = complete ? detail.ingestion : null;
  const enrichment = complete ? detail.enrichment : null;
  const triage = complete ? detail.triage : null;
  const judgment = complete ? detail.judgment : null;
  const escalation = complete ? detail.escalation : null;
  const response = complete ? detail.response : null;
  const finding = complete ? detail.finding : null;
  const analystRun = complete ? detail.analyst_run : null;
  const validation = complete ? detail.validation : null;
  const timeline = complete ? detail.timeline : [];
  const context = complete ? detail.event_context : null;
  const traceLatency = timeline.length > 1 ? Math.max(0, new Date(timeline.at(-1)!.at).getTime() - new Date(timeline[0].at).getTime()) : null;
  const decisionClass = alert.decision === "DENY" ? "deny" : alert.decision === "ALLOW" ? "allow" : "approval";
  const tabs: DetailTab[] = ["Summary", "Timeline", "Enrichment", "Triage", "Judgment", "AI Analyst", "Response & Audit"];
  const transitionsByStatus: Record<string, [string, string][]> = {
    open: [["acknowledge", "Acknowledge"], ["start_investigation", "Investigate"], ["mark_contained", "Contain"], ["close", "Close"]],
    acknowledged: [["start_investigation", "Investigate"], ["mark_contained", "Contain"], ["close", "Close"]],
    investigating: [["mark_contained", "Contain"], ["close", "Close"]],
    contained: [["start_investigation", "Reopen investigation"], ["close", "Close"]],
    closed: [],
  };
  const availableTransitions = finding ? transitionsByStatus[finding.status] ?? [] : [];

  async function transition(action: string) {
    setTransitioning(action);
    try {
      await onTransition(action, reason);
    } finally {
      setTransitioning("");
    }
  }

  return (
    <section className="panel detail-panel" aria-label={`Details for ${alert.title}`}>
      <div className="detail-head">
        <div>
          <div className="detail-id"><span className={`severity-label ${alert.severity}`}>{alert.severity}</span> {alert.id} · {alert.finding} <span className={`trace-badge ${complete ? "" : "summary"}`}>{loadState === "loading" ? "LOADING DETAIL" : complete ? "AUTHORITATIVE TRACE" : "SUMMARY ONLY"}</span></div>
          <h2>{alert.title}</h2>
          <p>{triage?.narrative ?? alert.reason ?? "No detailed explanation was recorded for this historical summary."}</p>
        </div>
        <div className={`decision-block ${decisionClass}`}><span>Decision</span><strong>{alert.decision}</strong><small>{finding?.status ?? alert.state}</small></div>
      </div>

      <div className="lifecycle-wrap">
        <div className="section-title-row"><div><span className="eyebrow">Recorded pipeline lifecycle</span><h3>{complete ? "Seven-stage authoritative decision trace" : "Detailed pipeline trace not retained"}</h3></div><span className="latency">{traceLatency === null ? "NO DERIVED TIMING" : `${traceLatency} MS · RECORDED TIMESTAMPS`}</span></div>
        <ol className="lifecycle">
          {stages.map((stage, index) => {
            const trace = timeline.find((item) => item.stage === stage.toLowerCase());
            return <li key={stage} className={trace ? "" : "stage-unavailable"}><span className="stage-index">{trace ? clock(trace.at) : String(index + 1).padStart(2, "0")}</span><span className="stage-dot" /><span className="stage-name">{stage}</span><span className="stage-result">{trace ? readable(trace.outcome) : "not recorded"}</span></li>;
          })}
        </ol>
      </div>

      <div className="detail-tabs" role="tablist" aria-label="Incident investigation sections">
        {tabs.map((item) => <button role="tab" aria-selected={tab === item} className={tab === item ? "detail-tab active" : "detail-tab"} key={item} onClick={() => setTab(item)} disabled={!complete && item !== "Summary"}>{item}{item === "Enrichment" && enrichment ? <span>{enrichment.sources.length}</span> : null}</button>)}
      </div>

      {loadState === "loading" && !complete && <div className="detail-state loading"><strong>Loading authoritative incident detail…</strong><span>The bridge is requesting the allowlisted record by finding ID.</span></div>}
      {loadState === "summary_only" && !complete && <div className="detail-state summary"><strong>Historical summary only</strong><span>No score, enrichment, explanation, or response evidence is reconstructed for this record.</span></div>}
      {loadState === "unavailable" && !complete && <div className="detail-state unavailable"><strong>Detail unavailable</strong><span>The incident service no longer has the complete record. Summary fields remain visible.</span></div>}
      {loadState === "failed" && !complete && <div className="detail-state failed"><strong>Detail request failed</strong><span>Retry after checking the loopback bridge.</span></div>}

      {tab === "Summary" && (
        <div className="detail-grid investigation-content">
          <article className="subpanel">
            <div className="subpanel-title"><span>Event and policy context</span><code>{judgment?.policy_version ?? alert.policy ?? "not retained"}</code></div>
            <dl className="proof-list">
              <div><dt>Operation</dt><dd><code>{display(context?.operation ?? alert.operation)}</code></dd></div>
              <div><dt>Resource</dt><dd>{display(context ? `${context.resource_class} · ${context.resource_ref}` : alert.resource)}</dd></div>
              <div><dt>Source trust</dt><dd>{display(context?.source_trust ?? alert.sourceTrust)}</dd></div>
              <div><dt>Destination</dt><dd>{display(context ? `${context.destination_class}${context.destination_ref ? ` · ${context.destination_ref}` : ""}` : alert.destination)}</dd></div>
              <div><dt>Detector</dt><dd><code>{display(detection?.detector_id)}</code></dd></div>
              <div><dt>Rule version</dt><dd><code>{display(detection?.rule_version)}</code></dd></div>
              <div><dt>Confidence</dt><dd>{detection ? `${Math.round(detection.confidence * 100)}%` : "—"}</dd></div>
              <div><dt>Risk score</dt><dd>{triage ? <><span className="risk-number">{triage.risk_score}</span> / 100</> : "—"}</dd></div>
            </dl>
          </article>
          <article className="subpanel evidence-panel">
            <div className="subpanel-title"><span>Evidence references</span><span className="verified-label">{ingestion ? "LEDGER RECORDED" : "NOT RETAINED"}</span></div>
            <div className="source-path"><span>Source</span><b aria-hidden="true">→</b><span>Agent</span><b aria-hidden="true">→</b><span>Proposed effect</span></div>
            <ul className="evidence-list">{(detection?.evidence_refs ?? []).map((item) => <li key={item}><span>✓</span><code>{item}</code></li>)}{!detection?.evidence_refs.length && <li><span>—</span>No detailed evidence references retained</li>}</ul>
            <div className="ai-review"><span className="ai-mark">AI</span><div><strong>{judgment?.model_verdict?.label ?? "Model evidence status"}</strong><small>{judgment ? `${judgment.model_status} · ${judgment.ai_mode}` : "Not retained in summary"}</small></div></div>
          </article>
          {complete && validation && triage && response && detection && <article className="validity-panel authoritative"><div className="validity-summary"><span className="eyebrow">Why this was triaged as real</span><strong>Confirmed policy violation</strong><p>The explanation is derived from the exact pipeline record that made the enforcement decision, not a UI replay.</p></div><div className="validity-evidence"><div className="validity-status"><StatusMark /><b>AUTHORITATIVE PIPELINE RESULT</b><code>{detection.detector_id}</code></div><ul>{validation.basis.map((basis) => <li key={basis}><span>✓</span>{basis}</li>)}</ul><div className="validity-foot"><span>Risk {triage.risk_score}/100 · {triage.priority}</span><span>{response.effect_status.toUpperCase()}</span><span>{detail.privacy.hashed_reference_count} REFERENCES HASHED</span></div></div><p className="validity-scope">This confirms a policy violation in the evaluated agent event. It is not by itself proof of a real-world compromise.</p></article>}
        </div>
      )}

      {tab === "Timeline" && complete && <div className="timeline-detail investigation-content">{timeline.map((item, index) => <article key={item.stage}><div><span>{String(index + 1).padStart(2, "0")}</span><i /></div><section><div className="subpanel-title"><strong>{readable(item.stage)}</strong><code>{clock(item.at)}</code></div><b>{readable(item.outcome)}</b><dl>{Object.entries(item.evidence).map(([key, value]) => <div key={key}><dt>{readable(key)}</dt><dd><code>{display(value)}</code></dd></div>)}</dl></section></article>)}</div>}

      {tab === "Enrichment" && complete && enrichment && <div className="investigation-content"><div className={`enrichment-summary ${enrichment.status}`}><div><span className="eyebrow">Enrichment snapshot</span><strong>{readable(enrichment.status)}</strong></div><span>{enrichment.completed_sources} / {enrichment.total_sources} complete · mandatory context {enrichment.mandatory_context_complete ? "available" : "incomplete"} · {enrichment.connector_sources} live connectors · {enrichment.cache_hits} cache hits · {enrichment.stale_fallbacks} stale · {enrichment.timed_out_sources} timed out{enrichment.policy_digest ? ` · policy ${enrichment.policy_digest.slice(0, 12)}` : ""}</span></div><div className="enrichment-grid">{enrichment.sources.map((item) => <article className={`enrichment-card ${item.status}`} key={item.source}><div><StatusMark tone={item.status === "complete" ? "healthy" : item.status === "failed" ? "danger" : "warning"} /><strong>{readable(item.source)}</strong><b>{item.status.toUpperCase()}</b></div><p>{Object.entries(item.facts).map(([key, value]) => `${readable(key)}: ${display(value)}`).join(" · ") || "No facts returned"}</p><dl><div><dt>Evidence</dt><dd>{item.evidence_refs.join(", ") || "—"}</dd></div><div><dt>Confidence</dt><dd>{Math.round(item.confidence * 100)}%</dd></div><div><dt>Latency</dt><dd>{item.latency_ms} ms</dd></div><div><dt>Connector</dt><dd>{item.connector_version ?? "Built in"}</dd></div><div><dt>Cache</dt><dd>{readable(item.cache_status)}{item.freshness_seconds != null ? ` · ${item.freshness_seconds}s old` : ""}</dd></div><div><dt>Policy</dt><dd>{readable(item.policy_decision)}</dd></div><div><dt>Triage</dt><dd>{item.affects_triage ? "Affected score" : "Context only"}</dd></div><div><dt>Failure</dt><dd>{item.failure_effect}</dd></div></dl></article>)}</div></div>}

      {tab === "Triage" && complete && triage && ingestion && <div className="triage-layout investigation-content"><article className="risk-hero"><span className="eyebrow">Explainable risk</span><strong>{triage.risk_score}</strong><small>/ 100</small><b>{triage.priority}</b><p>{triage.narrative}</p></article><article className="subpanel contribution-panel"><div className="subpanel-title"><span>Score contributions</span><span className="verified-label">{triage.score_reproduced ? "REPRODUCIBLE" : "MISMATCH"}</span></div><div className="contribution-list">{triage.contributions.map((item) => <div key={`${item.category}-${item.delta}`}><span><strong>{item.label}</strong><small>{item.rationale}</small><code>{item.evidence_refs.join(", ")}</code></span><b>{item.delta >= 0 ? "+" : ""}{item.delta}</b></div>)}<div className="contribution-total"><span>Final bounded score · {triage.score_version}</span><b>{triage.risk_score}</b></div></div></article><article className="subpanel triage-reasons"><div className="subpanel-title"><span>Routing and context</span><code>{clock(triage.assessed_at)}</code></div><dl className="proof-list"><div><dt>Route</dt><dd>{triage.route}</dd></div><div><dt>SLA</dt><dd>{triage.sla_minutes} minutes</dd></div><div><dt>Ledger</dt><dd>Sequence {ingestion.sequence}</dd></div><div><dt>Duplicate</dt><dd>{ingestion.duplicate ? "Yes" : "No"}</dd></div></dl><div className="reason-chips">{triage.reasons.map((item) => <span key={item}>{readable(item)}</span>)}</div>{triage.missing_context_warnings.length > 0 && <div className="context-warnings"><strong>Context warnings</strong>{triage.missing_context_warnings.map((warning) => <span key={warning}>{warning}</span>)}</div>}</article></div>}

      {tab === "Judgment" && complete && judgment && detection && <div className="decision-view investigation-content"><div className="decision-chain"><article><span>01 · Detector recommendation</span><strong>{readable(judgment.detector_recommendation)}</strong><small>{detection.detector_id}</small></article><b aria-hidden="true">→</b><article><span>02 · Deterministic policy</span><strong>{readable(judgment.deterministic_action)}</strong><small>{judgment.policy_version}</small></article><b aria-hidden="true">→</b><article><span>03 · Codex recorded shadow</span><strong>{judgment.model_verdict ? readable(judgment.model_verdict.action) : readable(judgment.model_status)}</strong><small>{judgment.model_verdict ? `${judgment.model_verdict.model_id} · ${Math.round(judgment.model_verdict.confidence * 100)}%` : "No live API decision"}</small></article><b aria-hidden="true">→</b><article className="final"><span>{judgment.ai_mode === "shadow" ? "04 · Final deterministic action" : "04 · Final most-restrictive action"}</span><strong>{readable(judgment.final_action)}</strong><small>{readable(judgment.combiner_result)}</small></article></div><article className="subpanel"><div className="subpanel-title"><span>Judgment evidence</span><code>{judgment.policy_version}</code></div><div className="reason-chips">{judgment.reason_codes.map((item) => <span key={item}>{readable(item)}</span>)}</div>{judgment.model_verdict && <dl className="proof-list"><div><dt>Provider</dt><dd>{judgment.model_verdict.provider}</dd></div><div><dt>Mode</dt><dd>{judgment.ai_mode}</dd></div><div><dt>Evidence</dt><dd>{judgment.model_verdict.evidence_refs.join(", ")}</dd></div><div><dt>Uncertainty</dt><dd>{judgment.model_verdict.uncertainty ?? "Not recorded"}</dd></div><div><dt>Evidence validation</dt><dd>{readable(judgment.model_validation_status)}</dd></div><div><dt>Calibrated confidence</dt><dd>{judgment.model_calibrated_confidence != null ? `${Math.round(judgment.model_calibrated_confidence * 100)}%` : "Not requested"}</dd></div><div><dt>Human gate</dt><dd>{judgment.model_human_gate_required ? "Required" : "Passed"}</dd></div><div><dt>Validation codes</dt><dd>{judgment.model_validation_codes.map(readable).join(" · ") || "Not requested"}</dd></div></dl>}<div className="decision-invariant">{judgment.ai_mode === "shadow" ? "This recorded shadow is non-executive. The final action remains deterministic, and the recommendation is evaluation evidence only." : "A model can tighten this decision only after evidence validation. It cannot create authority or relax deterministic enforcement; invalid or overconfident advice is held for human review."}</div></article></div>}

      {tab === "AI Analyst" && complete && analystRun && <AiAnalystView run={analystRun} />}
      {tab === "AI Analyst" && complete && !analystRun && <div className="detail-state unavailable"><strong>AI analyst run unavailable</strong><span>The deterministic investigation remains authoritative. No role summary, evidence citation, or recommendation is reconstructed.</span></div>}

      {tab === "Response & Audit" && complete && response && escalation && finding && <div className="response-layout investigation-content"><article className="subpanel"><div className="subpanel-title"><span>Escalation</span><span className="verified-label">{readable(escalation.level)}</span></div><dl className="proof-list"><div><dt>Queue</dt><dd>{escalation.queue ?? "No queue"}</dd></div><div><dt>Case</dt><dd><code>{escalation.case_id ?? "No case"}</code></dd></div><div><dt>Reason</dt><dd>{escalation.reason}</dd></div><div><dt>At</dt><dd>{clock(escalation.escalated_at)}</dd></div></dl></article><article className="subpanel"><div className="subpanel-title"><span>Safe response</span><span className="verified-label">{response.effect_status.toUpperCase()}</span></div><div className="response-actions">{response.actions.map((action) => <span key={action}>{readable(action)}</span>)}</div><ul className="evidence-list">{response.notes.map((note) => <li key={note}><span>✓</span>{note}</li>)}</ul><dl className="proof-list"><div><dt>Responder</dt><dd>{response.responder}</dd></div><div><dt>Effect</dt><dd>{response.effect_allowed ? "Allowed" : "Prevented"}</dd></div><div><dt>Mode</dt><dd>{response.simulated ? "Safe simulation" : "Live response"}</dd></div><div><dt>Ledger</dt><dd>{validation?.ledger_verified ? "Verified at response" : "Verification failed"}</dd></div></dl></article><article className="subpanel audit-panel"><div className="subpanel-title"><span>Finding audit</span><code>{readable(finding.status)}</code></div>{finding.audit.map((entry, index) => <div className="audit-entry" key={`${entry.at}-${index}`}><span>{clock(entry.at)}</span><i /><div><strong>{entry.from_status ? `${readable(entry.from_status)} → ` : ""}{readable(entry.to_status)}</strong><small>{entry.actor} · {entry.reason}</small></div></div>)}</article><article className="subpanel privacy-panel"><div className="subpanel-title"><span>Privacy receipt</span><code>{detail.privacy.redaction_policy_version}</code></div><div className="privacy-grid"><span>{detail.privacy.hashed_reference_count} references hashed</span><span>{detail.privacy.redaction_count} protected references</span><span>Raw prompts: excluded</span><span>Tool arguments: excluded</span><span>Authorization headers: excluded</span><span>Ingest tokens: excluded</span><span>Credentials: excluded</span><span>Full sensitive content: excluded</span></div></article><article className="subpanel transition-panel"><div className="subpanel-title"><span>Analyst transition</span><code>{finding.status}</code></div>{availableTransitions.length ? <><label>Audit reason<textarea value={reason} minLength={3} maxLength={256} onChange={(event) => setReason(event.target.value)} /></label><div>{availableTransitions.map(([action, label]) => <button key={action} disabled={Boolean(transitioning) || reason.trim().length < 3} onClick={() => void transition(action)}>{transitioning === action ? "Updating…" : label}</button>)}</div></> : <p>This finding is closed. No further transition is permitted.</p>}</article></div>}
    </section>
  );
}

function Overview({ alerts, active, activeDetail, detailState, onSelect, onTransition, liveState, ledgerVerified }: { alerts: Alert[]; active: Alert | null; activeDetail: IncidentDetail | null; detailState: DetailLoadState; onSelect: (alert: Alert) => void; onTransition: (action: string, reason: string) => Promise<void>; liveState: LiveState; ledgerVerified: boolean | null }) {
  const { snapshot: platform } = usePlatformSnapshot();
  const denied = alerts.filter((alert) => alert.decision === "DENY").length;
  const approvals = alerts.filter((alert) => alert.decision === "REQUIRE APPROVAL").length;
  const critical = alerts.filter((alert) => alert.severity === "critical").length;
  const release = platform?.reports.release;
  const evaluation = platform?.reports.evaluation;
  const deterministic = evaluation?.modes?.find((item) => item.mode === "deterministic");
  return (
    <>
      <section className="metrics-grid" aria-label="Security metrics">
        <MetricCard label="Live alerts" value={String(alerts.length).padStart(2, "0")} note="sanitized product decisions" tone={alerts.length ? "attention" : "default"} />
        <MetricCard label="Denied effects" value={String(denied).padStart(2, "0")} note="deterministic enforcement" tone={denied ? "good" : "default"} />
        <MetricCard label="Approval holds" value={String(approvals).padStart(2, "0")} note={`${critical} critical findings`} tone={approvals ? "attention" : "default"} />
        <MetricCard label="Ledger integrity" value={ledgerVerified === true ? "VERIFIED" : ledgerVerified === false ? "FAILED" : "—"} note={liveState === "connected" ? "latest live decisions" : "awaiting live bridge"} tone={ledgerVerified === true ? "good" : ledgerVerified === false ? "attention" : "default"} />
      </section>
      <div className="workspace-grid">
        <AlertQueue alerts={alerts} active={active} onSelect={onSelect} liveState={liveState} />
        <AlertDetail key={active?.id ?? "empty"} alert={active} detail={activeDetail} loadState={detailState} onTransition={onTransition} />
      </div>
      <section className="evaluation-band" aria-label="Evaluation rates use a 0% to 100% scale">
        <div><span className="eyebrow">Committed corpus · {evaluation?.dataset_version ?? "report unavailable"}</span><strong>{release?.state === "available" ? "Release evidence loaded from verified reports" : "No release report is being invented"}</strong></div>
        <div className="evaluation-stat"><span>Detector recall</span><b>{percentage(deterministic?.detector_recall)}</b></div>
        <div className="evaluation-stat"><span>Benign completion</span><b>{percentage(deterministic?.benign_task_completion_rate)}</b></div>
        <div className="evaluation-stat"><span>False blocks</span><b>{percentage(deterministic?.false_block_rate)}</b></div>
        <div className="evaluation-stat"><span>Verification</span><b>{release?.all_passed === true ? "PASS" : "—"}</b></div>
      </section>
    </>
  );
}

function Inventory() {
  const [components, setComponents] = useState<InventoryComponent[]>([]);
  const [summary, setSummary] = useState<InventorySummary | null>(null);
  const [selectedId, setSelectedId] = useState<string | null>(null);
  const [detail, setDetail] = useState<InventoryDetail | null>(null);
  const [state, setState] = useState<"loading" | "ready" | "empty" | "offline">("loading");

  const refresh = useCallback(async () => {
    setState("loading");
    try {
      const [inventoryResponse, summaryResponse] = await Promise.all([
        fetch(`${LIVE_API}/api/inventory`, { cache: "no-store" }),
        fetch(`${LIVE_API}/api/inventory/summary`, { cache: "no-store" }),
      ]);
      if (!inventoryResponse.ok || !summaryResponse.ok) throw new Error("Inventory unavailable");
      const inventory = (await inventoryResponse.json()) as { components: InventoryComponent[] };
      const currentSummary = (await summaryResponse.json()) as InventorySummary;
      const liveComponents = Array.isArray(inventory.components) ? inventory.components : [];
      setComponents(liveComponents);
      setSummary(currentSummary);
      setSelectedId((current) => current && liveComponents.some((item) => item.component_id === current) ? current : liveComponents[0]?.component_id ?? null);
      setState(liveComponents.length ? "ready" : "empty");
    } catch {
      setComponents([]);
      setSummary(null);
      setDetail(null);
      setState("offline");
    }
  }, []);

  useEffect(() => { const timer = window.setTimeout(() => { void refresh(); }, 0); return () => window.clearTimeout(timer); }, [refresh]);

  useEffect(() => {
    if (!selectedId) { const timer = window.setTimeout(() => setDetail(null), 0); return () => window.clearTimeout(timer); }
    let cancelled = false;
    void fetch(`${LIVE_API}/api/inventory/${encodeURIComponent(selectedId)}`, { cache: "no-store" })
      .then((response) => {
        if (!response.ok) throw new Error("Inventory detail unavailable");
        return response.json() as Promise<InventoryDetail>;
      })
      .then((payload) => { if (!cancelled) setDetail(payload); })
      .catch(() => { if (!cancelled) setDetail(null); });
    return () => { cancelled = true; };
  }, [selectedId]);

  const selected = components.find((item) => item.component_id === selectedId) ?? null;
  return (
    <section className="view-stack inventory-view">
      <div className="view-intro"><span className="eyebrow">Discovery-backed asset plane</span><h2>Know every AI application and dependency.</h2><p>Live telemetry, signed ABOM declarations, and model profiles converge into tenant-scoped applications, agents, models, and tools with ownership, permissions, configuration history, and explainable risk.</p></div>
      <div className="inventory-metrics">
        <MetricCard label="Components" value={String(summary?.total_components ?? 0)} note="Live tenant inventory" />
        <MetricCard label="Unmanaged" value={String(summary?.unmanaged_components ?? 0)} note="Observed, not governed" tone={(summary?.unmanaged_components ?? 0) > 0 ? "warning" : "default"} />
        <MetricCard label="Unowned" value={String(summary?.unowned_components ?? 0)} note="Needs accountable owner" tone={(summary?.unowned_components ?? 0) > 0 ? "danger" : "default"} />
        <MetricCard label="Maximum risk" value={String(summary?.maximum_risk_score ?? 0)} note="Deterministic rollup / 100" tone={(summary?.maximum_risk_score ?? 0) >= 60 ? "danger" : "default"} />
      </div>
      <div className="inventory-layout">
        <section className="panel inventory-list">
          <div className="panel-heading"><div><span className="eyebrow">Tenant components</span><h2>AI asset inventory</h2></div><button className="inventory-refresh" onClick={() => void refresh()}>Refresh</button></div>
          {state === "loading" && <div className="inventory-empty">Loading live inventory…</div>}
          {state === "offline" && <div className="inventory-empty">The inventory service is unavailable. No fallback assets are shown.</div>}
          {state === "empty" && <div className="inventory-empty">No components have been discovered. Forge or ingest a live event to create inventory.</div>}
          {state === "ready" && <div className="inventory-table-wrap"><table className="inventory-table"><thead><tr><th>COMPONENT</th><th>KIND</th><th>OWNER</th><th>STATE</th><th>RISK</th><th>LAST SEEN</th></tr></thead><tbody>{components.map((component) => <tr key={component.component_id} className={component.component_id === selectedId ? "selected" : ""} onClick={() => setSelectedId(component.component_id)}><td><strong>{component.name}</strong><code>{component.external_ref}</code></td><td><span>{component.kind}</span><small>{component.criticality}</small></td><td>{component.owner_ref ?? "UNOWNED"}</td><td><span className={`inventory-status ${component.status}`}>{component.status}</span><small>{component.source}</small></td><td><b className={component.risk_score >= 60 ? "risk-high" : ""}>{component.risk_score}</b><small>{component.risk_reasons[0] ?? "No elevated reason"}</small></td><td>{new Date(component.last_seen_at).toLocaleString()}</td></tr>)}</tbody></table></div>}
        </section>
        <aside className="panel inventory-detail">
          <div className="panel-heading"><div><span className="eyebrow">Component dossier</span><h2>{selected?.name ?? "Select an asset"}</h2></div>{selected && <span className="digest">V{selected.configuration_version}</span>}</div>
          {!selected && <div className="inventory-empty">Select a live component to inspect governance and history.</div>}
          {selected && <div className="inventory-detail-body">
            <div className="inventory-risk"><span>ROLLED-UP RISK</span><strong>{detail?.risk_rollup.score ?? selected.risk_score}</strong><div><i style={{ width: `${detail?.risk_rollup.score ?? selected.risk_score}%` }} /></div><small>{detail?.risk_rollup.component_count ?? 1} linked component{(detail?.risk_rollup.component_count ?? 1) === 1 ? "" : "s"}</small></div>
            <dl className="inventory-facts"><div><dt>Owner</dt><dd>{selected.owner_ref ?? "Unassigned"}</dd></div><div><dt>Criticality</dt><dd>{selected.criticality}</dd></div><div><dt>Status</dt><dd>{selected.status}</dd></div><div><dt>Configuration</dt><dd>Version {selected.configuration_version}</dd></div></dl>
            <section><span className="eyebrow">Effective permissions</span>{selected.permissions.length ? <ul className="permission-list">{selected.permissions.map((permission, index) => <li key={`${permission.operation}:${index}`}><div><strong>{permission.operation}</strong><code>{permission.resource_scope}</code></div><span className={permission.approved ? "approved" : "unapproved"}>{permission.approved ? "APPROVED" : "UNAPPROVED"}</span></li>)}</ul> : <p className="inventory-note">No effective permission observations recorded.</p>}</section>
            <section><span className="eyebrow">Configuration history</span>{detail?.configuration_history.length ? <ol className="config-history">{detail.configuration_history.slice().reverse().map((revision) => <li key={revision.version}><b>v{revision.version}</b><div><strong>{revision.changed_fields.join(", ") || "Initial snapshot"}</strong><small>{new Date(revision.observed_at).toLocaleString()} · {revision.configuration_digest.slice(0, 12)}…</small></div></li>)}</ol> : <p className="inventory-note">Loading version history…</p>}</section>
          </div>}
        </aside>
      </div>
    </section>
  );
}

function SecurityGraph() {
  const [snapshot, setSnapshot] = useState<SecurityGraphSnapshot | null>(null);
  const [summary, setSummary] = useState<SecurityGraphSummary | null>(null);
  const [state, setState] = useState<"loading" | "ready" | "empty" | "offline">("loading");
  const [asOf, setAsOf] = useState("");
  const [sourceId, setSourceId] = useState("");
  const [targetId, setTargetId] = useState("");
  const [selectedNodeId, setSelectedNodeId] = useState("");
  const [paths, setPaths] = useState<AttackPathResult | null>(null);
  const [blast, setBlast] = useState<BlastRadiusResult | null>(null);
  const [analysisState, setAnalysisState] = useState<"idle" | "running" | "error">("idle");
  const [message, setMessage] = useState("Select two live nodes to reconstruct weighted attack paths.");

  const encodedAsOf = useCallback(() => {
    if (!asOf) return "";
    const parsed = new Date(asOf);
    if (Number.isNaN(parsed.getTime())) throw new Error("Historical graph time is invalid.");
    return parsed.toISOString();
  }, [asOf]);

  const refresh = useCallback(async () => {
    setState("loading");
    setPaths(null);
    setBlast(null);
    try {
      const point = encodedAsOf();
      const query = point ? `?as_of=${encodeURIComponent(point)}` : "";
      const [graphResponse, summaryResponse] = await Promise.all([
        fetch(`${LIVE_API}/api/graph${query}`, { cache: "no-store" }),
        fetch(`${LIVE_API}/api/graph/summary${query}`, { cache: "no-store" }),
      ]);
      if (!graphResponse.ok || !summaryResponse.ok) throw new Error("Security graph unavailable");
      const graph = (await graphResponse.json()) as SecurityGraphSnapshot;
      const currentSummary = (await summaryResponse.json()) as SecurityGraphSummary;
      if (!Array.isArray(graph.nodes) || !Array.isArray(graph.edges)) throw new Error("Invalid security graph");
      setSnapshot(graph);
      setSummary(currentSummary);
      const sourceCandidates = graph.nodes.filter((node) => ["source", "application", "agent"].includes(node.node_type));
      const targetCandidates = graph.nodes.filter((node) => ["destination", "data_store", "resource", "finding"].includes(node.node_type));
      setSourceId((current) => graph.nodes.some((node) => node.node_id === current) ? current : sourceCandidates[0]?.node_id ?? graph.nodes[0]?.node_id ?? "");
      setTargetId((current) => graph.nodes.some((node) => node.node_id === current) ? current : targetCandidates.at(-1)?.node_id ?? graph.nodes.at(-1)?.node_id ?? "");
      setSelectedNodeId((current) => graph.nodes.some((node) => node.node_id === current) ? current : graph.nodes[0]?.node_id ?? "");
      setState(graph.nodes.length ? "ready" : "empty");
      setMessage(point ? `Historical topology at ${new Date(point).toLocaleString()}.` : "Current tenant topology loaded from live product records.");
    } catch (error) {
      setSnapshot(null);
      setSummary(null);
      setState("offline");
      setMessage(error instanceof Error ? error.message : "Security graph unavailable.");
    }
  }, [encodedAsOf]);

  useEffect(() => { const timer = window.setTimeout(() => { void refresh(); }, 0); return () => window.clearTimeout(timer); }, [refresh]);

  const positions = useMemo(() => {
    const levels: Record<string, number> = {
      source: 0, application: 0, agent: 1, model: 2, tool: 2, resource: 2,
      data_store: 3, destination: 3, decision: 4, finding: 5,
    };
    const groups = new Map<number, SecurityGraphNode[]>();
    for (const node of (snapshot?.nodes ?? []).slice(0, 60)) {
      const level = levels[node.node_type] ?? 2;
      groups.set(level, [...(groups.get(level) ?? []), node]);
    }
    const result = new Map<string, { x: number; y: number }>();
    for (const [level, nodes] of groups) {
      nodes.forEach((node, index) => result.set(node.node_id, { x: 35 + level * 190, y: 36 + index * 78 }));
    }
    return result;
  }, [snapshot]);

  const graphHeight = Math.max(340, ...Array.from(positions.values()).map((position) => position.y + 70));
  const highlightedEdges = new Set(paths?.paths[0]?.edge_ids ?? []);
  const selectedNode = snapshot?.nodes.find((node) => node.node_id === selectedNodeId) ?? null;

  async function analyze(kind: "paths" | "blast") {
    setAnalysisState("running");
    try {
      const point = encodedAsOf();
      const endpoint = kind === "paths" ? `${LIVE_API}/api/graph/attack-paths` : `${LIVE_API}/api/graph/blast-radius`;
      const body = kind === "paths"
        ? { source_node_id: sourceId, target_node_id: targetId, max_paths: 5, max_depth: 12, ...(point ? { as_of: point } : {}) }
        : { origin_node_id: sourceId, max_depth: 8, ...(point ? { as_of: point } : {}) };
      const response = await fetch(endpoint, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify(body),
      });
      if (!response.ok) throw new Error(`Live ${kind === "paths" ? "attack-path" : "blast-radius"} analysis failed.`);
      if (kind === "paths") {
        const result = (await response.json()) as AttackPathResult;
        setPaths(result);
        setBlast(null);
        setMessage(result.paths.length ? `${result.paths.length} weighted path${result.paths.length === 1 ? "" : "s"} reconstructed from recorded edges.` : "No directed path exists between the selected nodes.");
      } else {
        const result = (await response.json()) as BlastRadiusResult;
        setBlast(result);
        setPaths(null);
        setMessage(`${result.impacted_count} downstream node${result.impacted_count === 1 ? "" : "s"} in the bounded blast radius.`);
      }
      setAnalysisState("idle");
    } catch (error) {
      setAnalysisState("error");
      setMessage(error instanceof Error ? error.message : "Graph analysis unavailable.");
    }
  }

  return (
    <section className="view-stack security-graph-view">
      <div className="view-intro"><span className="eyebrow">Temporal AI exposure plane</span><h2>Trace influence into impact.</h2><p>Tenant-scoped inventory and authorization evidence become a durable, time-aware security graph. Analysts can reconstruct weighted attack paths, inspect control decisions, and calculate bounded blast radius without exposing raw prompts or credentials.</p></div>
      <div className="graph-metrics">
        <MetricCard label="Graph nodes" value={String(summary?.node_count ?? 0)} note="Current temporal snapshot" />
        <MetricCard label="Relationships" value={String(summary?.edge_count ?? 0)} note="Evidence-backed directed edges" />
        <MetricCard label="High-risk nodes" value={String(summary?.high_risk_nodes ?? 0)} note="Risk score ≥ 60" tone={(summary?.high_risk_nodes ?? 0) ? "danger" : "default"} />
        <MetricCard label="External sinks" value={String(summary?.external_destinations ?? 0)} note="Observed destinations" tone={(summary?.external_destinations ?? 0) ? "warning" : "default"} />
      </div>
      <section className="panel graph-controls">
        <div className="panel-heading"><div><span className="eyebrow">Analysis controls</span><h2>Attack-path reconstruction</h2></div><span className={`hunt-state ${analysisState === "error" ? "error" : analysisState === "running" ? "running" : state === "ready" ? "ready" : ""}`}>{analysisState === "running" ? "ANALYZING" : state.toUpperCase()}</span></div>
        <div className="graph-control-grid">
          <label><span>SOURCE / ORIGIN</span><select value={sourceId} onChange={(event) => setSourceId(event.target.value)}>{snapshot?.nodes.map((node) => <option key={node.node_id} value={node.node_id}>{node.node_type} · {node.name}</option>)}</select></label>
          <label><span>TARGET</span><select value={targetId} onChange={(event) => setTargetId(event.target.value)}>{snapshot?.nodes.map((node) => <option key={node.node_id} value={node.node_id}>{node.node_type} · {node.name}</option>)}</select></label>
          <label><span>HISTORICAL SNAPSHOT</span><input type="datetime-local" value={asOf} onChange={(event) => setAsOf(event.target.value)} /></label>
          <div className="graph-control-actions"><button onClick={() => void analyze("paths")} disabled={!sourceId || !targetId || analysisState === "running"}>Find attack paths</button><button onClick={() => void analyze("blast")} disabled={!sourceId || analysisState === "running"}>Blast radius</button><button className="secondary" onClick={() => void refresh()}>Refresh snapshot</button></div>
        </div>
        <div className="graph-message"><code>{message}</code><span>{snapshot ? `AS OF ${new Date(snapshot.as_of).toLocaleString()}${snapshot.truncated ? " · TRUNCATED" : ""}` : "NO LIVE SNAPSHOT"}</span></div>
      </section>
      <div className="graph-layout">
        <section className="panel graph-topology">
          <div className="panel-heading"><div><span className="eyebrow">Live causal topology</span><h2>AI security graph</h2></div><span className="digest">METADATA ONLY</span></div>
          {state === "loading" && <div className="graph-empty">Loading the live tenant graph…</div>}
          {state === "offline" && <div className="graph-empty">The security graph service is unavailable. No fallback topology is shown.</div>}
          {state === "empty" && <div className="graph-empty">No live graph nodes exist. Forge or ingest an event to build the first evidence-backed path.</div>}
          {state === "ready" && <div className="graph-canvas-wrap"><svg className="graph-canvas" viewBox={`0 0 1040 ${graphHeight}`} role="img" aria-label="Live AI security topology">
            <g className="graph-edges">{snapshot?.edges.map((edge) => {
              const source = positions.get(edge.source_node_id); const target = positions.get(edge.target_node_id);
              if (!source || !target) return null;
              return <g key={edge.edge_id} className={highlightedEdges.has(edge.edge_id) ? "highlighted" : ""}><line x1={source.x + 142} y1={source.y + 25} x2={target.x} y2={target.y + 25} /><title>{edge.edge_type} · weight {edge.weight} · {edge.risk_factors.join(", ") || "no elevated factor"}</title></g>;
            })}</g>
            <g className="graph-nodes">{snapshot?.nodes.slice(0, 60).map((node) => {
              const position = positions.get(node.node_id); if (!position) return null;
              return <g key={node.node_id} transform={`translate(${position.x} ${position.y})`} className={`${node.risk_score >= 60 ? "high-risk" : ""} ${selectedNodeId === node.node_id ? "selected" : ""}`} onClick={() => setSelectedNodeId(node.node_id)} onKeyDown={(event) => { if (event.key === "Enter" || event.key === " ") { event.preventDefault(); setSelectedNodeId(node.node_id); } }} role="button" tabIndex={0} aria-label={`${node.node_type} ${node.name}, risk ${node.risk_score}`}><rect width="142" height="50" rx="5" /><text x="10" y="17" className="node-type">{node.node_type.toUpperCase()}</text><text x="10" y="35" className="node-name">{node.name.length > 19 ? `${node.name.slice(0, 18)}…` : node.name}</text><circle cx="130" cy="13" r="7" /><text x="130" y="16" textAnchor="middle" className="node-risk">{node.risk_score}</text><title>{node.node_id}</title></g>;
            })}</g>
          </svg></div>}
        </section>
        <aside className="graph-sidebar">
          <section className="panel graph-node-detail"><div className="panel-heading"><div><span className="eyebrow">Node dossier</span><h2>{selectedNode?.name ?? "Select a node"}</h2></div>{selectedNode && <span className={selectedNode.risk_score >= 60 ? "graph-risk high" : "graph-risk"}>{selectedNode.risk_score}</span>}</div>{selectedNode ? <div className="graph-detail-body"><dl><div><dt>Type</dt><dd>{selectedNode.node_type}</dd></div><div><dt>Criticality</dt><dd>{selectedNode.criticality}</dd></div><div><dt>Valid from</dt><dd>{new Date(selectedNode.valid_from).toLocaleString()}</dd></div><div><dt>Source</dt><dd>{selectedNode.source_ref}</dd></div></dl><code>{selectedNode.node_id}</code>{Object.entries(selectedNode.labels).length > 0 && <ul>{Object.entries(selectedNode.labels).map(([key, value]) => <li key={key}><span>{key}</span><b>{value}</b></li>)}</ul>}</div> : <div className="graph-empty small">Choose a live graph node.</div>}</section>
          <section className="panel graph-analysis-result"><div className="panel-heading"><div><span className="eyebrow">Analysis result</span><h2>{paths ? "Weighted paths" : blast ? "Blast radius" : "Awaiting query"}</h2></div></div>{paths && <div className="path-list">{paths.paths.length ? paths.paths.map((path, index) => <article key={`${path.node_ids.join(":")}:${index}`}><div><b>PATH {index + 1}</b><span>Exposure {path.exposure_score} · cost {path.total_weight}</span></div><ol>{path.node_ids.map((nodeId) => <li key={nodeId}>{snapshot?.nodes.find((node) => node.node_id === nodeId)?.name ?? nodeId}</li>)}</ol><small>{path.risk_factors.join(" · ") || "No elevated factor"}</small></article>) : <div className="graph-empty small">No directed path found.</div>}</div>}{blast && <div className="blast-result"><div className="blast-score"><strong>{blast.impacted_count}</strong><span>IMPACTED</span><b>{blast.high_risk_count} high risk · max {blast.maximum_risk_score}</b></div><ol>{blast.impacted_nodes.slice(0, 12).map((node) => <li key={node.node_id}><div><strong>{snapshot?.nodes.find((item) => item.node_id === node.node_id)?.name ?? node.node_id}</strong><small>Depth {node.depth}</small></div><b>{node.risk_score}</b></li>)}</ol></div>}{!paths && !blast && <div className="graph-empty small">Run an attack-path or blast-radius analysis against the live snapshot.</div>}</section>
        </aside>
      </div>
    </section>
  );
}

function ThreatHunting() {
  const [query, setQuery] = useState('record_type = "alert" AND severity >= "high"');
  const [page, setPage] = useState<SearchPage | null>(null);
  const [aggregation, setAggregation] = useState<SearchAggregation | null>(null);
  const [hunts, setHunts] = useState<SavedHunt[]>([]);
  const [status, setStatus] = useState<"idle" | "running" | "ready" | "error">("idle");
  const [message, setMessage] = useState("Run a tenant-scoped query against the live canonical index.");
  const [pivot, setPivot] = useState<EvidencePivot | null>(null);
  const [evidenceId, setEvidenceId] = useState("");

  const loadHunts = useCallback(async () => {
    try {
      const response = await fetch(`${LIVE_API}/api/hunts`, { cache: "no-store" });
      if (!response.ok) throw new Error("Saved hunts unavailable");
      const payload = (await response.json()) as { hunts: SavedHunt[] };
      setHunts(Array.isArray(payload.hunts) ? payload.hunts : []);
    } catch {
      setHunts([]);
    }
  }, []);

  useEffect(() => { const timer = window.setTimeout(() => { void loadHunts(); }, 0); return () => window.clearTimeout(timer); }, [loadHunts]);

  async function runSearch(cursor?: string, queryOverride?: string) {
    const activeQuery = queryOverride ?? query;
    setStatus("running");
    setMessage("Parsing and executing the bounded query…");
    try {
      const [searchResponse, aggregateResponse] = await Promise.all([
        fetch(`${LIVE_API}/api/search`, {
          method: "POST",
          headers: { "Content-Type": "application/json" },
          body: JSON.stringify({ query: activeQuery, page_size: 25, cursor, sort_by: "created_at", sort_order: "desc" }),
        }),
        fetch(`${LIVE_API}/api/search/aggregate`, {
          method: "POST",
          headers: { "Content-Type": "application/json" },
          body: JSON.stringify({ query: activeQuery, field: "record_type", limit: 12 }),
        }),
      ]);
      if (!searchResponse.ok || !aggregateResponse.ok) throw new Error("The live search service rejected this query.");
      const [searchPayload, aggregatePayload] = await Promise.all([
        searchResponse.json() as Promise<SearchPage>,
        aggregateResponse.json() as Promise<SearchAggregation>,
      ]);
      setQuery(activeQuery);
      setPage(searchPayload);
      setAggregation(aggregatePayload);
      setStatus("ready");
      setMessage(`${searchPayload.total} indexed record${searchPayload.total === 1 ? "" : "s"} · ${searchPayload.elapsed_ms.toFixed(1)} ms`);
    } catch (error) {
      setStatus("error");
      setMessage(error instanceof Error ? error.message : "Live search is unavailable.");
    }
  }

  async function saveCurrentHunt() {
    const name = `Hunt ${new Date().toLocaleTimeString()}`;
    try {
      const response = await fetch(`${LIVE_API}/api/hunts`, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ name, description: "Saved from the analyst workbench", query }),
      });
      if (!response.ok) throw new Error("The query could not be saved.");
      await loadHunts();
      setMessage(`Saved “${name}” for this tenant.`);
    } catch (error) {
      setStatus("error");
      setMessage(error instanceof Error ? error.message : "Saved hunt unavailable.");
    }
  }

  async function openEvidencePivot(candidate?: string) {
    const id = (candidate ?? evidenceId).trim();
    if (!id) return;
    setEvidenceId(id);
    try {
      const response = await fetch(`${LIVE_API}/api/evidence/${encodeURIComponent(id)}/pivot`, { cache: "no-store" });
      if (!response.ok) throw new Error("Evidence pivot was not found.");
      setPivot((await response.json()) as EvidencePivot);
    } catch (error) {
      setPivot(null);
      setStatus("error");
      setMessage(error instanceof Error ? error.message : "Evidence pivot unavailable.");
    }
  }

  return (
    <section className="view-stack hunting-view">
      <div className="view-intro"><span className="eyebrow">Indexed analyst workbench</span><h2>Hunt across every AI-security record.</h2><p>Queries are parsed against an allowlist, bound to the active tenant, and executed over sanitized canonical projections. Protected evidence content never enters the search index.</p></div>
      <section className="panel hunt-composer">
        <div className="panel-heading"><div><span className="eyebrow">AgentSec query language</span><h2>Live threat query</h2></div><span className={`hunt-state ${status}`}>{status.toUpperCase()}</span></div>
        <label><span>QUERY</span><textarea value={query} onChange={(event) => setQuery(event.target.value)} spellCheck={false} aria-label="Threat hunting query" /></label>
        <div className="hunt-actions"><button onClick={() => void runSearch()} disabled={status === "running"}>Run query</button><button className="secondary" onClick={() => void saveCurrentHunt()} disabled={status === "running"}>Save hunt</button><code>{message}</code></div>
      </section>
      <div className="hunt-layout">
        <section className="panel hunt-results">
          <div className="panel-heading"><div><span className="eyebrow">Canonical index</span><h2>Search results</h2></div><span className="digest">{page ? `${page.total} TOTAL` : "NO QUERY YET"}</span></div>
          {!page && <div className="hunt-empty">No fixed or sample alerts are displayed. Run a query to retrieve live indexed records.</div>}
          {page && page.hits.length === 0 && <div className="hunt-empty">The query completed successfully with no matching records.</div>}
          {page && page.hits.length > 0 && <div className="hunt-table-wrap"><table className="hunt-table"><thead><tr><th>TIME</th><th>TYPE / ID</th><th>ANALYST PROJECTION</th><th>RISK</th><th>EVIDENCE</th></tr></thead><tbody>{page.hits.map((hit) => {
            const ids = Array.isArray(hit.projection.evidence_ids) ? hit.projection.evidence_ids.filter((item): item is string => typeof item === "string") : hit.record_type === "evidence" ? [hit.record_id] : [];
            return <tr key={`${hit.record_type}:${hit.record_id}`}><td>{new Date(hit.created_at).toLocaleString()}</td><td><b>{hit.record_type}</b><code>{hit.record_id}</code></td><td><strong>{hit.title ?? String(hit.projection.hypothesis ?? hit.projection.claim ?? "Canonical security record")}</strong><small>{String(hit.projection.status ?? hit.projection.alert_type ?? hit.projection.action ?? "indexed")}</small></td><td><span className={`severity ${hit.severity ?? "info"}`}>{hit.severity ?? "—"}</span><small>{hit.risk_score != null ? `Risk ${hit.risk_score}` : hit.confidence != null ? `${Math.round(hit.confidence * 100)}% confidence` : "—"}</small></td><td>{ids.slice(0, 1).map((id) => <button key={id} onClick={() => void openEvidencePivot(id)}>Pivot</button>)}</td></tr>;
          })}</tbody></table></div>}
          {page?.next_cursor && <button className="load-more" onClick={() => void runSearch(page.next_cursor)}>Load next page</button>}
        </section>
        <aside className="hunt-sidebar">
          <section className="panel hunt-buckets"><div className="panel-heading"><div><span className="eyebrow">Aggregation</span><h2>Record types</h2></div></div>{aggregation?.buckets.length ? aggregation.buckets.map((bucket) => <button key={bucket.value} onClick={() => void runSearch(undefined, `record_type = ${JSON.stringify(bucket.value)}`)}><span>{bucket.value}</span><b>{bucket.count}</b></button>) : <p>Run a query to calculate live buckets.</p>}</section>
          <section className="panel saved-hunts"><div className="panel-heading"><div><span className="eyebrow">Tenant library</span><h2>Saved hunts</h2></div></div>{hunts.length ? hunts.map((hunt) => <button key={hunt.hunt_id} onClick={() => void runSearch(undefined, hunt.query)}><strong>{hunt.name}</strong><code>{hunt.query}</code></button>) : <p>No saved hunts exist for this tenant.</p>}</section>
          <section className="panel evidence-pivot"><div className="panel-heading"><div><span className="eyebrow">Evidence graph</span><h2>Safe pivot</h2></div></div><div className="pivot-input"><input value={evidenceId} onChange={(event) => setEvidenceId(event.target.value)} placeholder="evd_…" aria-label="Evidence ID" /><button onClick={() => void openEvidencePivot()}>Open</button></div>{pivot ? <div className="pivot-card"><strong>{pivot.evidence_id}</strong><span>{String(pivot.evidence.claim ?? pivot.evidence.evidence_type ?? "Verified evidence metadata")}</span><small>{pivot.related_records.length} linked records · protected content excluded</small></div> : <p>Open an evidence ID to see its metadata and linked records.</p>}</section>
        </aside>
      </div>
    </section>
  );
}

function Posture() {
  const [summary, setSummary] = useState<PostureSummary | null>(null);
  const [findings, setFindings] = useState<PostureFinding[]>([]);
  const [checks, setChecks] = useState<PostureCheck[]>([]);
  const [trends, setTrends] = useState<PostureTrend[]>([]);
  const [selectedId, setSelectedId] = useState("");
  const [detail, setDetail] = useState<PostureDetail | null>(null);
  const [state, setState] = useState<"loading" | "ready" | "empty" | "offline" | "scanning">("loading");
  const [message, setMessage] = useState("Loading live posture state…");
  const [exceptionReason, setExceptionReason] = useState("Temporary accepted risk during tracked remediation");
  const [exceptionDays, setExceptionDays] = useState(7);
  const [revokeReason, setRevokeReason] = useState("Risk acceptance withdrawn after remediation review");
  const [detailRevision, setDetailRevision] = useState(0);

  const refresh = useCallback(async () => {
    setState((current) => current === "scanning" ? current : "loading");
    try {
      const [summaryResponse, findingsResponse, checksResponse, trendsResponse] = await Promise.all([
        fetch(`${LIVE_API}/api/posture/summary`, { cache: "no-store" }),
        fetch(`${LIVE_API}/api/posture/findings`, { cache: "no-store" }),
        fetch(`${LIVE_API}/api/posture/checks`, { cache: "no-store" }),
        fetch(`${LIVE_API}/api/posture/trends`, { cache: "no-store" }),
      ]);
      if (![summaryResponse, findingsResponse, checksResponse, trendsResponse].every((response) => response.ok)) throw new Error("Posture service unavailable");
      const nextSummary = (await summaryResponse.json()) as PostureSummary;
      const findingPage = (await findingsResponse.json()) as { findings: PostureFinding[] };
      const checkPage = (await checksResponse.json()) as { checks: PostureCheck[] };
      const trendSeries = (await trendsResponse.json()) as { points: PostureTrend[] };
      const nextFindings = Array.isArray(findingPage.findings) ? findingPage.findings : [];
      setSummary(nextSummary); setFindings(nextFindings); setChecks(checkPage.checks ?? []); setTrends(trendSeries.points ?? []);
      setSelectedId((current) => nextFindings.some((item) => item.finding_id === current) ? current : nextFindings[0]?.finding_id ?? "");
      setDetailRevision((current) => current + 1);
      setState(nextFindings.length ? "ready" : "empty");
      setMessage(nextSummary.latest_scan_at ? `Latest scan ${new Date(nextSummary.latest_scan_at).toLocaleString()}` : "No posture scan has run yet.");
    } catch (error) {
      setSummary(null); setFindings([]); setChecks([]); setTrends([]); setDetail(null); setState("offline");
      setMessage(error instanceof Error ? error.message : "Posture service unavailable.");
    }
  }, []);

  useEffect(() => { const timer = window.setTimeout(() => { void refresh(); }, 0); return () => window.clearTimeout(timer); }, [refresh]);
  useEffect(() => {
    if (!selectedId) { const timer = window.setTimeout(() => setDetail(null), 0); return () => window.clearTimeout(timer); }
    let cancelled = false;
    void fetch(`${LIVE_API}/api/posture/findings/${encodeURIComponent(selectedId)}`, { cache: "no-store" })
      .then((response) => { if (!response.ok) throw new Error("Posture detail unavailable"); return response.json() as Promise<PostureDetail>; })
      .then((payload) => { if (!cancelled) setDetail(payload); })
      .catch(() => { if (!cancelled) setDetail(null); });
    return () => { cancelled = true; };
  }, [selectedId, detailRevision]);

  async function runScan() {
    setState("scanning"); setMessage("Evaluating versioned checks against the live inventory…");
    try {
      const response = await fetch(`${LIVE_API}/api/posture/scans`, { method: "POST", headers: { "Content-Type": "application/json" }, body: "{}" });
      if (!response.ok) throw new Error("Posture scan failed");
      const result = await response.json() as { failing: number; passing: number; posture_score: number };
      setMessage(`${result.passing} passing · ${result.failing} failing · score ${result.posture_score}`);
      await refresh();
    } catch (error) { setState("offline"); setMessage(error instanceof Error ? error.message : "Posture scan failed."); }
  }

  async function acceptException() {
    if (!detail || exceptionReason.trim().length < 10) return;
    const expiresAt = new Date(Date.now() + exceptionDays * 86_400_000).toISOString();
    const response = await fetch(`${LIVE_API}/api/posture/findings/${encodeURIComponent(detail.finding.finding_id)}/exceptions`, {
      method: "POST", headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ reason: exceptionReason, owner_ref: "team://local-security", approved_by: "analyst://local-demo", expires_at: expiresAt }),
    });
    if (!response.ok) { setMessage("Accepted-risk exception was rejected."); return; }
    setMessage(`Risk accepted for ${exceptionDays} day${exceptionDays === 1 ? "" : "s"}; expiry remains enforced.`);
    await refresh();
  }

  async function revokeException() {
    if (!detail?.exception || revokeReason.trim().length < 3) return;
    const response = await fetch(`${LIVE_API}/api/posture/exceptions/${encodeURIComponent(detail.exception.exception_id)}/revoke`, {
      method: "POST", headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ reason: revokeReason }),
    });
    if (!response.ok) { setMessage("Exception revocation was rejected."); return; }
    setMessage("Accepted-risk exception revoked; the finding is open for remediation.");
    await refresh();
  }

  return <section className="view-stack posture-view">
    <div className="view-intro"><span className="eyebrow">AI security posture management</span><h2>Turn discovered exposure into governed remediation.</h2><p>Versioned deterministic checks continuously evaluate the live AI inventory. Every failure carries evidence, reproducible risk, framework mappings, remediation guidance, and a time-bounded accepted-risk workflow.</p></div>
    <div className="posture-metrics"><MetricCard label="Posture score" value={String(summary?.posture_score ?? 100)} note="Passing evaluations / 100" tone={(summary?.posture_score ?? 100) < 70 ? "danger" : "good"} /><MetricCard label="Open findings" value={String(summary?.open_findings ?? 0)} note={`${summary?.critical_open_findings ?? 0} critical`} tone={(summary?.open_findings ?? 0) ? "danger" : "default"} /><MetricCard label="Accepted risk" value={String(summary?.accepted_exceptions ?? 0)} note="Time-bounded exceptions" tone={(summary?.accepted_exceptions ?? 0) ? "warning" : "default"} /><MetricCard label="Active checks" value={String(summary?.enabled_checks ?? checks.length)} note="Versioned posture content" /></div>
    <section className="panel posture-toolbar"><div><span className="eyebrow">Current tenant assessment</span><strong>{message}</strong></div><button onClick={() => void runScan()} disabled={state === "scanning"}>{state === "scanning" ? "Scanning live inventory…" : "Run posture scan"}</button></section>
    <div className="posture-layout"><section className="panel posture-findings"><div className="panel-heading"><div><span className="eyebrow">Remediation queue</span><h2>Posture findings</h2></div><span className="digest">{findings.length} LIVE RECORDS</span></div>{state === "loading" && <div className="posture-empty">Loading live posture findings…</div>}{state === "offline" && <div className="posture-empty">The posture service is unavailable. No fallback findings are shown.</div>}{state === "empty" && <div className="posture-empty">No posture findings exist. Run a live inventory scan to establish compliance.</div>}{findings.length > 0 && <div className="posture-table-wrap"><table className="posture-table"><thead><tr><th>FINDING</th><th>COMPONENT</th><th>STATUS</th><th>RISK</th><th>LAST SEEN</th></tr></thead><tbody>{findings.map((finding) => <tr key={finding.finding_id} className={finding.finding_id === selectedId ? "selected" : ""} onClick={() => setSelectedId(finding.finding_id)}><td><strong>{finding.title}</strong><code>{finding.check_id} · {finding.check_version}</code></td><td><b>{finding.component_name}</b><small>{finding.component_kind}</small></td><td><span className={`posture-status ${finding.status}`}>{finding.status.replaceAll("_", " ")}</span><small>{finding.severity}</small></td><td><em className={finding.risk_score >= 80 ? "critical" : ""}>{finding.risk_score}</em></td><td>{new Date(finding.last_seen_at).toLocaleString()}</td></tr>)}</tbody></table></div>}</section>
      <aside className="posture-sidebar"><section className="panel posture-detail"><div className="panel-heading"><div><span className="eyebrow">Finding dossier</span><h2>{detail?.finding.component_name ?? "Select a finding"}</h2></div>{detail && <span className="graph-risk high">{detail.finding.risk_score}</span>}</div>{detail ? <div className="posture-detail-body"><h3>{detail.finding.title}</h3><p>{detail.check.description}</p><dl><div><dt>Check</dt><dd>{detail.finding.check_id} · {detail.finding.check_version}</dd></div><div><dt>Status</dt><dd>{detail.finding.status}</dd></div><div><dt>Observed</dt><dd>{Object.entries(detail.finding.observed).map(([key, value]) => `${key}: ${value}`).join(" · ")}</dd></div><div><dt>Frameworks</dt><dd>{detail.finding.framework_mappings.join(", ")}</dd></div></dl><span className="eyebrow">Remediation plan</span><ol>{detail.finding.remediation.map((step) => <li key={step}>{step}</li>)}</ol>{detail.exception ? <div className="active-exception"><strong>ACCEPTED RISK</strong><span>{detail.exception.reason}</span><small>Owner {detail.exception.owner_ref} · expires {new Date(detail.exception.expires_at).toLocaleString()}</small><textarea aria-label="Exception revocation reason" value={revokeReason} onChange={(event) => setRevokeReason(event.target.value)} /><button onClick={() => void revokeException()}>Revoke exception</button></div> : detail.finding.status !== "resolved" && <div className="exception-form"><span className="eyebrow">Time-bounded exception</span><textarea value={exceptionReason} onChange={(event) => setExceptionReason(event.target.value)} /><label>Days<input type="number" min="1" max="366" value={exceptionDays} onChange={(event) => setExceptionDays(Math.max(1, Math.min(366, Number(event.target.value))))} /></label><button onClick={() => void acceptException()}>Accept risk with expiry</button></div>}</div> : <div className="posture-empty small">Select a live posture finding.</div>}</section>
      <section className="panel posture-trends"><div className="panel-heading"><div><span className="eyebrow">Historical posture</span><h2>Score trend</h2></div></div>{trends.length ? <div className="trend-bars">{trends.map((point) => <div key={point.scan_id}><span>{new Date(point.completed_at).toLocaleDateString()}</span><i><b style={{ width: `${point.posture_score}%` }} /></i><strong>{point.posture_score}</strong></div>)}</div> : <div className="posture-empty small">Run scans to establish a trend.</div>}</section>
      <section className="panel posture-checks"><div className="panel-heading"><div><span className="eyebrow">Check library</span><h2>Coverage</h2></div></div><ul>{checks.map((check) => <li key={check.check_id}><div><strong>{check.title}</strong><code>{check.check_id} · {check.version}</code></div><span>{check.severity}</span></li>)}</ul></section></aside></div>
  </section>;
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

function Evaluations() {
  const { snapshot, state, message, refresh } = usePlatformSnapshot();
  const evaluation = snapshot?.reports.evaluation;
  const release = snapshot?.reports.release;
  const modes = evaluation?.modes ?? [];
  const deterministic = modes.find((item) => item.mode === "deterministic");
  const ablation = evaluation?.ablation;
  const continuous = evaluation?.continuous?.candidate;
  const continuousBaseline = evaluation?.continuous?.baseline;
  return (
    <section className="view-stack">
      <div className="view-intro"><span className="eyebrow">Module 23 · Evaluation and continuous improvement</span><h2>Measure effects, evidence quality, calibration, and drift before release.</h2><p>The compact ablation corpus proves control contribution. A separate 42-case blind benchmark evaluates every use case across fixed language and obfuscation variants, then compares the recorded Codex track with its deterministic baseline.</p></div>
      <section className="panel platform-toolbar"><div><StatusMark tone={state === "offline" ? "danger" : state === "loading" ? "warning" : "healthy"} /><span><strong>{message}</strong><small>Committed files are hash-bound to the evaluation manifest before display.</small></span></div><button onClick={() => void refresh()} disabled={state === "loading"}>Refresh reports</button></section>
      {state === "offline" && <section className="panel platform-empty">The report boundary is unavailable. No benchmark values or release verdict are substituted.</section>}
      <div className="evaluation-layout">
        <section className="panel benchmark-panel">
          <div className="panel-heading"><div><span className="eyebrow">Attack success by mode</span><h2>Control comparison</h2></div><span className="digest">{evaluation?.manifest_digest ? `SHA256 · ${evaluation.manifest_digest.slice(0, 12)}…` : "NO REPORT"}</span></div>
          {modes.length ? <div className="bar-list">
            {modes.map((item) => {
              const value = Math.round(item.forbidden_effect_attack_success_rate * 100);
              const tone = value === 0 ? "healthy" : value < 100 ? "warning" : "danger";
              return <div className="bar-row" key={item.mode}><span>{evaluationModeLabel(item.mode)}</span><div className="bar-track"><i className={tone} style={{ width: `${Math.max(value, 1.4)}%` }} /></div><b>{value}%</b></div>;
            })}
          </div> : <div className="platform-empty small">No verified evaluation modes are available.</div>}
        </section>
        <aside className="evaluation-summary">
          <article className="summary-score"><span className="eyebrow">Release verdict</span><strong>{release?.all_passed === true ? "PASS" : "—"}</strong><p>{release?.scope ?? "No committed release report"}{release?.production_ready === false ? " · not production ready" : ""}</p></article>
          <article className="panel summary-list"><h3>Corpus profile</h3><dl><div><dt>Dataset</dt><dd>{evaluation?.dataset_version ?? "—"}</dd></div><div><dt>Attack scenarios</dt><dd>{deterministic?.attack_scenarios ?? "—"}</dd></div><div><dt>Benign controls</dt><dd>{deterministic?.benign_scenarios ?? "—"}</dd></div><div><dt>Evaluation modes</dt><dd>{modes.length || "—"}</dd></div><div><dt>Control ablations</dt><dd>{ablation?.results.length ?? "—"}</dd></div><div><dt>Committed artifacts</dt><dd>{evaluation?.artifacts?.length ?? "—"}</dd></div></dl></article>
        </aside>
      </div>
      <section className="continuous-evaluation" aria-label="Continuous evaluation release gate">
        <div className="continuous-metrics">
          <MetricCard label="Blind cases" value={continuous ? String(continuous.case_count) : "—"} note={`${continuous?.use_case_count ?? "—"} use cases · ${continuous?.splits.holdout ?? "—"} holdout`} />
          <MetricCard label="Detector recall" value={percentage(continuous?.metrics.detector_recall)} note="Per-use-case gated" tone={continuous?.metrics.detector_recall === 1 ? "good" : "danger"} />
          <MetricCard label="Severity agreement" value={percentage(continuous?.metrics.severity_exact_agreement_rate)} note="Exact severity" tone={continuous?.metrics.severity_exact_agreement_rate === 1 ? "good" : "danger"} />
          <MetricCard label="Evidence validity" value={percentage(continuous?.metrics.evidence_validity_rate)} note="No fabricated citations" tone={continuous?.metrics.evidence_validity_rate === 1 ? "good" : "danger"} />
          <MetricCard label="Abstention" value={percentage(continuous?.metrics.abstention_rate)} note="Explicit model abstentions" tone={(continuous?.metrics.abstention_rate ?? 0) > .1 ? "danger" : "good"} />
          <MetricCard label="Release gate" value={continuous?.gate_state.toUpperCase() ?? "—"} note={continuous?.drift_passed === true ? "Baseline drift passed" : "No passing drift receipt"} tone={continuous?.gate_state === "pass" && continuous?.drift_passed === true ? "good" : "danger"} />
        </div>
        <div className="continuous-grid">
          <section className="panel continuous-track">
            <div className="panel-heading"><div><span className="eyebrow">Exact candidate identity</span><h2>Recorded model qualification</h2></div><span className={`platform-state ${continuous?.gate_state === "pass" ? "available" : "unavailable"}`}>{continuous?.gate_state ?? "unavailable"}</span></div>
            {continuous ? <><dl><div><dt>Candidate</dt><dd>{readable(continuous.candidate_id)}</dd></div><div><dt>Track</dt><dd>{readable(continuous.candidate_kind)}</dd></div><div><dt>Provider</dt><dd>{continuous.provider}</dd></div><div><dt>Exact model</dt><dd>{continuous.exact_model_id}</dd></div><div><dt>Qualified</dt><dd>{continuous.qualified ? "yes" : "no"}</dd></div><div><dt>Provider calls</dt><dd>{continuous.live_provider_calls ? "live" : "recorded only"}</dd></div><div><dt>Brier score</dt><dd>{continuous.metrics.brier_score.toFixed(4)}</dd></div><div><dt>Calibration error</dt><dd>{continuous.metrics.expected_calibration_error.toFixed(4)}</dd></div></dl><footer><span>Route commitment</span><code>{continuous.route_sha256}</code><span>Record commitment</span><code>{continuous.record_digest}</code></footer></> : <div className="platform-empty small">No manifest-bound continuous evaluation record is available.</div>}
          </section>
          <section className="panel continuous-boundary">
            <div className="panel-heading"><div><span className="eyebrow">Improvement boundary</span><h2>Feedback never changes production directly</h2></div><span className="signed-badge">THREE ACTORS</span></div>
            <ol><li><strong>Submit</strong><span>Analyst feedback becomes a digest-bound candidate correction.</span></li><li><strong>Review</strong><span>A different reviewer approves or rejects the proposed ground truth.</span></li><li><strong>Publish</strong><span>A third actor creates a new immutable dataset revision.</span></li><li><strong>Re-evaluate</strong><span>Absolute and baseline-drift gates must pass before release.</span></li></ol>
            <p>Rules, model routes, response actions, and runtime policy are never updated by this workflow.</p>
          </section>
        </div>
        <section className="panel continuous-use-cases">
          <div className="panel-heading"><div><span className="eyebrow">Blind benchmark coverage</span><h2>Per-use-case quality gates</h2></div><span className="digest">{continuousBaseline?.record_digest ? `BASE · ${continuousBaseline.record_digest.slice(0, 12)}…` : "NO BASELINE"}</span></div>
          {continuous?.use_cases?.length ? <div className="table-scroll"><table><caption className="sr-only">Continuous evaluation results by AI-security use case</caption><thead><tr><th scope="col">USE CASE</th><th scope="col">CASES</th><th scope="col">RECALL</th><th scope="col">SEVERITY</th><th scope="col">EVIDENCE</th><th scope="col">SAFE ACTION</th></tr></thead><tbody>{continuous.use_cases.map((item) => <tr key={item.use_case}><th scope="row">{readable(item.use_case)}</th><td>{item.cases}</td><td>{percentage(item.detector_recall)}</td><td>{percentage(item.severity_exact_agreement_rate)}</td><td>{percentage(item.evidence_validity_rate)}</td><td>{percentage(item.safe_action_agreement_rate)}</td></tr>)}</tbody></table></div> : <div className="platform-empty small">No per-use-case metrics are available.</div>}
        </section>
      </section>
    </section>
  );
}

const starterRuleDefinition = {
  rule_id: "DET-STUDIO-EGRESS-001",
  version: "1.0.0",
  name: "Rule Studio external send",
  description: "Detects AI-agent external sends and records deterministic evidence for review.",
  kind: "event",
  execution_mode: "both",
  alert_type: "studio_external_send",
  title: "AI agent attempted an external send",
  severity: "high",
  confidence: 0.91,
  recommended_action: "deny",
  reason_codes: ["STUDIO_EXTERNAL_SEND"],
  framework_mappings: ["OWASP-LLM02", "MITRE-ATLAS-AML.T0057"],
  tags: ["ai-agent", "egress"],
  evidence_fields: ["event_id", "operation", "destination"],
  predicate: { all_conditions: [{ field: "operation", operator: "equals", value: "external.send" }], any_conditions: [] },
  sequence_steps: [],
  correlation_predicates: [],
  threshold: null,
  window_seconds: null,
  group_by: "flow_id",
  semantic_profile: null,
  semantic_min_confidence: null,
  enabled: true,
};

function RuleStudio() {
  const [records, setRecords] = useState<RuleContent[]>([]);
  const [health, setHealth] = useState<ContentHealth | null>(null);
  const [selectedId, setSelectedId] = useState<string | null>(null);
  const [selected, setSelected] = useState<RuleContent | null>(null);
  const [history, setHistory] = useState<RuleContent[]>([]);
  const [editor, setEditor] = useState(JSON.stringify(starterRuleDefinition, null, 2));
  const [message, setMessage] = useState("Connecting to the signed content service…");
  const [busy, setBusy] = useState(false);
  const [reviewComment, setReviewComment] = useState("Independent review confirms the rule logic and deterministic test evidence.");
  const [rollbackVersion, setRollbackVersion] = useState("1.1.0");

  const readJson = useCallback(async (url: string, init?: RequestInit) => {
    const response = await fetch(url, { cache: "no-store", ...init });
    if (!response.ok) throw new Error(`Content service rejected the request (${response.status}).`);
    return response.json() as Promise<Record<string, unknown>>;
  }, []);

  const refresh = useCallback(async () => {
    try {
      const [contentPayload, healthPayload] = await Promise.all([
        readJson(`${LIVE_API}/api/detection/content`),
        readJson(`${LIVE_API}/api/detection/content/health`),
      ]);
      const liveRecords = Array.isArray(contentPayload.content) ? contentPayload.content as RuleContent[] : [];
      setRecords(liveRecords);
      setHealth(healthPayload as unknown as ContentHealth);
      setSelectedId((current) => current && liveRecords.some((item) => item.content_id === current) ? current : liveRecords[0]?.content_id ?? null);
      setMessage(liveRecords.length ? "Signed content inventory synchronized." : "No rules exist yet. Create the first reviewed detection draft.");
    } catch (error) {
      setMessage(error instanceof Error ? error.message : "Detection content service is unavailable.");
      setRecords([]);
      setHealth(null);
    }
  }, [readJson]);

  useEffect(() => { const timer = window.setTimeout(() => { void refresh(); }, 0); return () => window.clearTimeout(timer); }, [refresh]);

  useEffect(() => {
    if (!selectedId) {
      const timer = window.setTimeout(() => { setSelected(null); setHistory([]); }, 0);
      return () => window.clearTimeout(timer);
    }
    let cancelled = false;
    void Promise.all([
      readJson(`${LIVE_API}/api/detection/content/${encodeURIComponent(selectedId)}`),
      readJson(`${LIVE_API}/api/detection/content/${encodeURIComponent(selectedId)}/history`),
    ]).then(([detail, historyPayload]) => {
      if (cancelled) return;
      const record = detail as unknown as RuleContent;
      setSelected(record);
      setEditor(JSON.stringify(record.definition, null, 2));
      setHistory(Array.isArray(historyPayload.history) ? historyPayload.history as RuleContent[] : []);
    }).catch((error) => {
      if (!cancelled) setMessage(error instanceof Error ? error.message : "Unable to load rule evidence.");
    });
    return () => { cancelled = true; };
  }, [readJson, selectedId]);

  async function mutate(path: string, payload: Record<string, unknown>, method = "POST") {
    if (busy) return;
    setBusy(true);
    try {
      const result = await readJson(`${LIVE_API}${path}`, {
        method,
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify(payload),
      }) as unknown as RuleContent;
      if (result.content_id) setSelectedId(result.content_id);
      setSelected(result.content_id ? result : selected);
      setMessage(`Recorded ${path.split("/").at(-1)?.replaceAll("-", " ")} as signed revision ${result.revision ?? "—"}.`);
      await refresh();
      if (result.content_id) {
        const historyPayload = await readJson(`${LIVE_API}/api/detection/content/${encodeURIComponent(result.content_id)}/history`);
        setHistory(Array.isArray(historyPayload.history) ? historyPayload.history as RuleContent[] : []);
      }
    } catch (error) {
      setMessage(error instanceof Error ? error.message : "Rule lifecycle action failed closed.");
    } finally {
      setBusy(false);
    }
  }

  function parsedDefinition(): Record<string, unknown> | null {
    try {
      const parsed = JSON.parse(editor) as unknown;
      if (!parsed || Array.isArray(parsed) || typeof parsed !== "object") throw new Error("Rule must be a JSON object.");
      return parsed as Record<string, unknown>;
    } catch (error) {
      setMessage(error instanceof Error ? error.message : "Rule JSON is invalid.");
      return null;
    }
  }

  function createDraft() {
    const definition = parsedDefinition();
    if (definition) void mutate("/api/detection/content", { definition });
  }

  function saveDraft() {
    if (!selected) return;
    const definition = parsedDefinition();
    if (definition) void mutate(`/api/detection/content/${selected.content_id}`, { definition }, "PUT");
  }

  function lifecycle(action: string, payload: Record<string, unknown> = {}) {
    if (selected) void mutate(`/api/detection/content/${selected.content_id}/${action}`, payload);
  }

  function resetEditor() {
    setSelectedId(null);
    setSelected(null);
    setHistory([]);
    setEditor(JSON.stringify({ ...starterRuleDefinition, rule_id: `DET-STUDIO-${String(records.length + 1).padStart(3, "0")}` }, null, 2));
    setMessage("New unsigned draft prepared locally. Save it to create the first signed revision.");
  }

  const editable = !selected || ["draft", "rejected"].includes(selected.status);
  const result = selected?.shadow_result ?? selected?.validation ?? selected?.backtest ?? null;

  return <section className="view-stack rule-studio-view">
    <div className="view-intro"><span className="eyebrow">Detection content management</span><h2>Author, prove, review, shadow, then publish.</h2><p>Every rule revision is signed. Publication requires deterministic tests, independent approval, shadow evidence, and an exact digest acknowledgement.</p></div>
    <div className="studio-metrics">
      <MetricCard label="Managed rules" value={String(health?.total_content ?? 0)} note="Current signed records" />
      <MetricCard label="Awaiting review" value={String(health?.in_review ?? 0)} note="Four-eyes queue" tone={(health?.in_review ?? 0) ? "warning" : "default"} />
      <MetricCard label="Shadow" value={String(health?.shadow ?? 0)} note="Pre-publication evaluation" />
      <MetricCard label="Published" value={String(health?.published ?? 0)} note="Active detection content" tone="good" />
      <MetricCard label="Test failures" value={String(health?.validation_failures ?? 0)} note="Fail-closed revisions" tone={(health?.validation_failures ?? 0) ? "danger" : "default"} />
    </div>
    <section className="panel studio-toolbar"><div><span className="eyebrow">Control-plane status</span><strong>{message}</strong></div><div><button className="secondary" onClick={() => void refresh()} disabled={busy}>Refresh</button><button onClick={resetEditor} disabled={busy}>New draft</button></div></section>
    <div className="studio-layout">
      <section className="panel studio-library"><div className="panel-heading"><div><span className="eyebrow">Signed library</span><h2>Rule content</h2></div><span className="digest">{records.length} LIVE</span></div>
        {records.length === 0 ? <div className="studio-empty">No fallback rules are shown. Connect the content service or create a live draft.</div> : <div className="studio-rule-list">{records.map((record) => <button key={record.content_id} className={selectedId === record.content_id ? "selected" : ""} onClick={() => setSelectedId(record.content_id)}><span className={`content-status ${record.status}`}>{record.status.replaceAll("_", " ")}</span><strong>{record.definition.name}</strong><code>{record.definition.rule_id} · {record.definition.version}</code><small>rev {record.revision} · {new Date(record.updated_at).toLocaleString()}</small></button>)}</div>}
      </section>
      <section className="panel studio-editor"><div className="panel-heading"><div><span className="eyebrow">Declarative rule</span><h2>{selected ? `${selected.definition.rule_id} · ${selected.definition.version}` : "New detection draft"}</h2></div>{selected && <span className={`content-status ${selected.status}`}>{selected.status.replaceAll("_", " ")}</span>}</div>
        <textarea aria-label="Detection rule JSON" value={editor} onChange={(event) => setEditor(event.target.value)} readOnly={!editable} spellCheck={false} />
        <div className="studio-editor-actions">{!selected && <button onClick={createDraft} disabled={busy}>Create signed draft</button>}{selected && editable && <button onClick={saveDraft} disabled={busy}>Save revision</button>}<span>Strict allowlisted fields · no executable expressions</span></div>
      </section>
      <aside className="studio-sidebar">
        <section className="panel studio-gates"><div className="panel-heading"><div><span className="eyebrow">Release gates</span><h2>Lifecycle</h2></div></div>
          <ol>{["draft", "in_review", "approved", "shadow", "published"].map((stage) => <li key={stage} className={selected?.status === stage ? "active" : history.some((item) => item.status === stage) ? "complete" : ""}><i /> <span>{stage.replaceAll("_", " ")}</span><b>{history.find((item) => item.status === stage)?.revision ?? "—"}</b></li>)}</ol>
          <div className="studio-gate-actions">
            {selected?.status === "draft" && <><button onClick={() => lifecycle("validate", { name: "External send positive and benign control", presets: ["indirect_injection_secret_egress", "benign_inventory_read"], expected_alert_presets: ["indirect_injection_secret_egress"] })} disabled={busy}>Run tests</button><button className="secondary" onClick={() => lifecycle("backtest", { presets: ["indirect_injection_secret_egress", "persistent_memory_poisoning", "benign_inventory_read"] })} disabled={busy}>Backtest</button><button onClick={() => lifecycle("submit")} disabled={busy || !selected.validation?.passed}>Submit review</button></>}
            {selected?.status === "in_review" && <><textarea aria-label="Review comment" value={reviewComment} onChange={(event) => setReviewComment(event.target.value)} /><button onClick={() => lifecycle("review", { decision: "approve", comment: reviewComment })} disabled={busy}>Approve independently</button><button className="danger" onClick={() => lifecycle("review", { decision: "reject", comment: reviewComment })} disabled={busy}>Reject</button></>}
            {selected?.status === "approved" && <button onClick={() => lifecycle("shadow")} disabled={busy}>Deploy shadow</button>}
            {selected?.status === "shadow" && <><button onClick={() => lifecycle("shadow-evaluate", { presets: ["indirect_injection_secret_egress", "persistent_memory_poisoning", "benign_inventory_read"] })} disabled={busy}>Evaluate shadow</button><button onClick={() => lifecycle("publish", { expected_definition_sha256: selected.shadow_result?.definition_sha256 ?? "" })} disabled={busy || !selected.shadow_result || selected.shadow_result.errors.length > 0}>Publish exact digest</button></>}
            {selected?.status === "published" && <><label>Rollback version<input value={rollbackVersion} onChange={(event) => setRollbackVersion(event.target.value)} /></label><button className="danger" onClick={() => lifecycle("rollback", { new_version: rollbackVersion, reason: "Operational evidence requires restoring this previously reviewed rule." })} disabled={busy}>Create reviewed rollback</button><button className="secondary" onClick={() => void mutate("/api/detection/content/packs/export", { content_ids: [selected.content_id], name: `${selected.definition.name} pack`, description: "Signed reviewed AgentSec detection content export.", version: selected.definition.version })} disabled={busy}>Export signed pack</button></>}
            {selected?.status === "rejected" && <p>Edit the draft and save a new signed revision before retesting.</p>}
          </div>
        </section>
        <section className="panel studio-evidence"><div className="panel-heading"><div><span className="eyebrow">Recorded proof</span><h2>Latest evidence</h2></div></div>{result ? <dl><div><dt>Definition digest</dt><dd><code>{result.definition_sha256.slice(0, 18)}…</code></dd></div><div><dt>Events</dt><dd>{result.event_count}</dd></div><div><dt>Outcome</dt><dd className={result.passed === false || result.errors.length ? "bad" : "good"}>{result.passed === false || result.errors.length ? "FAILED" : "PASSED"}</dd></div><div><dt>Alerts</dt><dd>{result.alert_count ?? "exact match"}</dd></div><div><dt>Latency</dt><dd>{result.duration_ms} ms</dd></div><div><dt>False positives</dt><dd>{result.false_positive_event_ids?.length ?? 0}</dd></div><div><dt>False negatives</dt><dd>{result.false_negative_event_ids?.length ?? 0}</dd></div></dl> : <div className="studio-empty small">No validation, backtest, or shadow evidence recorded for this revision.</div>}</section>
        <section className="panel studio-history"><div className="panel-heading"><div><span className="eyebrow">Append-only audit</span><h2>Revision history</h2></div><span className="digest">{history.length}</span></div><ul>{history.slice().reverse().map((item) => <li key={`${item.content_id}-${item.revision}`}><b>R{item.revision}</b><span>{item.status.replaceAll("_", " ")}</span><code>{item.record_sha256.slice(0, 10)}…</code></li>)}</ul></section>
      </aside>
    </div>
  </section>;
}

function CorrelationWorkbench() {
  const [incidents, setIncidents] = useState<CorrelatedIncident[]>([]);
  const [health, setHealth] = useState<CorrelationHealth | null>(null);
  const [decisions, setDecisions] = useState<CorrelationDecision[]>([]);
  const [selectedId, setSelectedId] = useState<string | null>(null);
  const [detail, setDetail] = useState<CorrelatedIncident | null>(null);
  const [mergeIds, setMergeIds] = useState<string[]>([]);
  const [splitIds, setSplitIds] = useState<string[]>([]);
  const [state, setState] = useState<"loading" | "ready" | "empty" | "offline">("loading");
  const [message, setMessage] = useState("Connecting to the incident correlation service…");
  const [busy, setBusy] = useState(false);

  const readJson = useCallback(async (url: string, init?: RequestInit) => {
    const response = await fetch(url, { cache: "no-store", ...init });
    if (!response.ok) throw new Error(`Correlation service rejected the request (${response.status}).`);
    return response.json() as Promise<Record<string, unknown>>;
  }, []);

  const refresh = useCallback(async () => {
    setState("loading");
    try {
      const [incidentPayload, healthPayload, decisionPayload] = await Promise.all([
        readJson(`${LIVE_API}/api/correlation/incidents`),
        readJson(`${LIVE_API}/api/correlation/health`),
        readJson(`${LIVE_API}/api/correlation/decisions`),
      ]);
      const next = Array.isArray(incidentPayload.incidents) ? incidentPayload.incidents as CorrelatedIncident[] : [];
      setIncidents(next);
      setHealth(healthPayload as unknown as CorrelationHealth);
      setDecisions(Array.isArray(decisionPayload.decisions) ? decisionPayload.decisions as CorrelationDecision[] : []);
      setSelectedId((current) => current && next.some((item) => item.incident_id === current) ? current : next.find((item) => item.status !== "merged")?.incident_id ?? next[0]?.incident_id ?? null);
      setState(next.length ? "ready" : "empty");
      setMessage("Explainable incident graph synchronized from live finding decisions.");
    } catch (error) {
      setIncidents([]); setHealth(null); setDecisions([]); setDetail(null); setState("offline");
      setMessage(error instanceof Error ? error.message : "Correlation service is unavailable.");
    }
  }, [readJson]);

  useEffect(() => { const timer = window.setTimeout(() => { void refresh(); }, 0); return () => window.clearTimeout(timer); }, [refresh]);
  useEffect(() => {
    if (!selectedId) { const timer = window.setTimeout(() => setDetail(null), 0); return () => window.clearTimeout(timer); }
    let cancelled = false;
    void readJson(`${LIVE_API}/api/correlation/incidents/${encodeURIComponent(selectedId)}`)
      .then((payload) => { if (!cancelled) { setDetail(payload as unknown as CorrelatedIncident); setSplitIds([]); } })
      .catch((error) => { if (!cancelled) setMessage(error instanceof Error ? error.message : "Incident detail unavailable."); });
    return () => { cancelled = true; };
  }, [readJson, selectedId]);

  async function mutate(path: string, payload: Record<string, unknown>) {
    if (busy) return null;
    setBusy(true);
    try {
      const result = await readJson(`${LIVE_API}${path}`, { method: "POST", headers: { "Content-Type": "application/json" }, body: JSON.stringify(payload) });
      setMessage("Governed correlation change recorded with immutable audit evidence.");
      await refresh();
      return result;
    } catch (error) {
      setMessage(error instanceof Error ? error.message : "Correlation change failed closed.");
      return null;
    } finally { setBusy(false); }
  }

  async function transition(status: string) {
    if (!detail) return;
    const result = await mutate(`/api/correlation/incidents/${detail.incident_id}/transition`, { status, reason: `Analyst reviewed all linked finding evidence and set the campaign to ${status}.` });
    if (result) setSelectedId(detail.incident_id);
  }

  async function mergeSelected() {
    const result = await mutate("/api/correlation/incidents/merge", { incident_ids: mergeIds, reason: "Analyst evidence confirms these incident groups are one coordinated campaign." });
    if (result?.incident_id) setSelectedId(String(result.incident_id));
    setMergeIds([]);
  }

  async function splitSelected() {
    if (!detail) return;
    const result = await mutate(`/api/correlation/incidents/${detail.incident_id}/split`, { finding_ids: splitIds, reason: "Analyst evidence confirms this finding subset belongs to a separate activity group." });
    const child = result?.child as Record<string, unknown> | undefined;
    if (child?.incident_id) setSelectedId(String(child.incident_id));
    setSplitIds([]);
  }

  return <section className="view-stack correlation-view">
    <div className="view-intro"><span className="eyebrow">Finding correlation & incident creation</span><h2>One campaign, every finding, and the proof that linked them.</h2><p>First-class incidents group authoritative findings by bounded time, flow, hashed entities, and attack-sequence extension. Correlation never changes the original detection or authorization result.</p></div>
    <div className="correlation-metrics"><MetricCard label="Incidents" value={String(health?.total_incidents ?? 0)} note={`${health?.open_incidents ?? 0} open`} /><MetricCard label="Linked findings" value={String(health?.total_findings ?? 0)} note="Authoritative finding references" /><MetricCard label="Multi-finding" value={String(health?.multi_finding_incidents ?? 0)} note="Campaign rollups" tone={(health?.multi_finding_incidents ?? 0) ? "warning" : "default"} /><MetricCard label="Suppressed" value={String(health?.suppressed_findings ?? 0)} note={`${health?.active_suppressions ?? 0} active rules`} /><MetricCard label="Merged history" value={String(health?.merged_incidents ?? 0)} note="Never deleted" /></div>
    <section className="panel correlation-toolbar"><div><span className="eyebrow">Live correlation state</span><strong>{message}</strong></div><div><button className="secondary" onClick={() => void refresh()} disabled={busy}>Refresh</button><button onClick={() => void mergeSelected()} disabled={busy || mergeIds.length < 2}>Merge {mergeIds.length || "selected"}</button></div></section>
    {state === "offline" && <section className="panel correlation-empty">The correlation service is offline. No fallback incidents or synthetic grouping evidence are shown.</section>}
    {state === "empty" && <section className="panel correlation-empty">No correlated incidents exist. Forge a live security event to create authoritative findings and correlation decisions.</section>}
    {state !== "offline" && <div className="correlation-layout">
      <section className="panel correlation-list"><div className="panel-heading"><div><span className="eyebrow">Campaign queue</span><h2>First-class incidents</h2></div><span className="digest">{incidents.length} LIVE</span></div>{incidents.map((incident) => <article key={incident.incident_id} className={selectedId === incident.incident_id ? "selected" : ""}><label><input type="checkbox" checked={mergeIds.includes(incident.incident_id)} disabled={incident.status === "merged"} onChange={() => setMergeIds((current) => current.includes(incident.incident_id) ? current.filter((item) => item !== incident.incident_id) : [...current, incident.incident_id])} /><span>MERGE</span></label><button onClick={() => setSelectedId(incident.incident_id)}><span className={`correlation-status ${incident.status}`}>{incident.status}</span><strong>{incident.title}</strong><code>{incident.incident_id}</code><small>{incident.finding_count} findings · risk {incident.risk_score} · {incident.priority}</small></button></article>)}</section>
      <section className="panel correlation-detail"><div className="panel-heading"><div><span className="eyebrow">Correlation proof</span><h2>{detail?.incident_id ?? "Select an incident"}</h2></div>{detail && <span className={`correlation-status ${detail.status}`}>{detail.status}</span>}</div>{!detail ? <div className="correlation-empty">Select a live incident to inspect its grouping and sequence evidence.</div> : <><div className="correlation-risk"><div><span>ROLLED-UP RISK</span><strong>{detail.risk_score}</strong></div><dl><div><dt>Severity</dt><dd>{detail.severity}</dd></div><div><dt>Priority</dt><dd>{detail.priority}</dd></div><div><dt>Findings</dt><dd>{detail.finding_count}</dd></div><div><dt>Reopened</dt><dd>{detail.reopened_count}</dd></div></dl></div><div className="correlation-actions">{detail.status === "open" && <button onClick={() => void transition("investigating")}>Start investigation</button>}{["open", "investigating"].includes(detail.status) && <button onClick={() => void transition("contained")}>Mark contained</button>}{detail.status !== "closed" && detail.status !== "merged" && <button className="danger" onClick={() => void transition("closed")}>Close incident</button>}{detail.status === "closed" && <button onClick={() => void transition("open")}>Reopen incident</button>}<button className="secondary" onClick={() => void splitSelected()} disabled={splitIds.length === 0 || splitIds.length >= detail.finding_count}>Split {splitIds.length || "subset"}</button></div><section className="correlation-sequence"><h3>Reconstructed attack sequence</h3>{detail.attack_sequence.map((step) => { const link = detail.finding_links.find((item) => item.finding_id === step.finding_id); return <article key={step.finding_id}><i>{step.order}</i><div><span>{step.stage.replaceAll("_", " ")}</span><strong>{link?.title}</strong><code>{step.finding_id} · {step.event_id}</code><small>{new Date(step.occurred_at).toLocaleString()}</small></div><b>{link?.risk_score}</b></article>; })}</section><section className="correlation-links"><h3>Linked finding evidence</h3>{detail.finding_links.map((link) => <article key={link.finding_id}><label><input type="checkbox" checked={splitIds.includes(link.finding_id)} onChange={() => setSplitIds((current) => current.includes(link.finding_id) ? current.filter((item) => item !== link.finding_id) : [...current, link.finding_id])} /> SELECT FOR SPLIT</label><header><span>{link.alert_type.replaceAll("_", " ")}</span><b>{link.correlation_score} LINK</b></header><p>{link.correlation_reasons.join(" · ") || "New incident root"}</p><code>{link.flow_ref}</code><small>Entities · {link.entity_refs.join(" · ")}</small><small>Evidence · {link.evidence_refs.join(" · ")}</small></article>)}</section><section className="correlation-receipt"><dl><div><dt>Policy</dt><dd>{detail.correlation_policy_version}</dd></div><div><dt>Revision</dt><dd>{detail.revision}</dd></div><div><dt>Digest</dt><dd><code>{detail.incident_sha256}</code></dd></div><div><dt>Updated</dt><dd>{new Date(detail.updated_at).toLocaleString()}</dd></div></dl></section></>}</section>
      <aside className="correlation-sidebar"><section className="panel correlation-decisions"><div className="panel-heading"><div><span className="eyebrow">Decision ledger</span><h2>Why grouped</h2></div><span className="digest">{decisions.length}</span></div>{decisions.map((decision) => <article key={decision.decision_id}><span className={`correlation-status ${decision.outcome}`}>{decision.outcome}</span><strong>{decision.finding_id}</strong><p>{decision.reasons.join(" · ")}</p><code>score {decision.selected_score} · {decision.decision_sha256.slice(0, 12)}…</code></article>)}</section><section className="panel correlation-audit"><div className="panel-heading"><div><span className="eyebrow">Immutable operations</span><h2>Incident audit</h2></div></div>{detail?.audit.map((entry, index) => <article key={`${entry.at}-${index}`}><span>{entry.action}</span><strong>{entry.reason}</strong><code>{entry.actor_id} · {new Date(entry.at).toLocaleString()}</code></article>)}</section></aside>
    </div>}
  </section>;
}

function nextBehaviorVersion(version: string): string {
  const parts = version.split(".");
  const last = Number(parts.at(-1));
  if (Number.isInteger(last) && last >= 0) {
    return [...parts.slice(0, -1), String(last + 1)].join(".");
  }
  return `${version}.1`;
}

function topBehaviorCounts(counts: Record<string, number>): string {
  const values = Object.entries(counts).sort((left, right) => right[1] - left[1]).slice(0, 3);
  return values.length ? values.map(([name, count]) => `${name} ${count}`).join(" · ") : "No learned values";
}

function RiskAnalytics() {
  const [health, setHealth] = useState<BehaviorHealth | null>(null);
  const [baselines, setBaselines] = useState<BehaviorBaseline[]>([]);
  const [assessments, setAssessments] = useState<BehaviorAssessment[]>([]);
  const [configs, setConfigs] = useState<BehaviorTuningConfig[]>([]);
  const [selectedId, setSelectedId] = useState<string | null>(null);
  const [detail, setDetail] = useState<BehaviorAssessment | null>(null);
  const [entityDrift, setEntityDrift] = useState<BehaviorDrift | null>(null);
  const [selectedEntity, setSelectedEntity] = useState<string | null>(null);
  const [state, setState] = useState<"loading" | "ready" | "empty" | "offline">("loading");
  const [message, setMessage] = useState("Connecting to the behavioral risk service…");
  const [busy, setBusy] = useState(false);
  const [tuningVersion, setTuningVersion] = useState("");
  const [minimumObservations, setMinimumObservations] = useState(5);
  const [anomalyThreshold, setAnomalyThreshold] = useState(55);
  const [driftWarningRate, setDriftWarningRate] = useState(0.25);
  const [driftCriticalRate, setDriftCriticalRate] = useState(0.5);
  const [tuningReason, setTuningReason] = useState("Reviewed SOC evidence supports this bounded behavioral policy update.");

  const readJson = useCallback(async (url: string, init?: RequestInit) => {
    const response = await fetch(url, { cache: "no-store", ...init });
    if (!response.ok) throw new Error(`Behavior service rejected the request (${response.status}).`);
    return response.json() as Promise<Record<string, unknown>>;
  }, []);

  const refresh = useCallback(async () => {
    setState("loading");
    try {
      const [healthPayload, baselinePayload, anomalyPayload, configPayload] = await Promise.all([
        readJson(`${LIVE_API}/api/behavior/health`),
        readJson(`${LIVE_API}/api/behavior/baselines`),
        readJson(`${LIVE_API}/api/behavior/anomalies`),
        readJson(`${LIVE_API}/api/behavior/config`),
      ]);
      const nextHealth = healthPayload as unknown as BehaviorHealth;
      const nextBaselines = Array.isArray(baselinePayload.baselines) ? baselinePayload.baselines as BehaviorBaseline[] : [];
      const nextAssessments = Array.isArray(anomalyPayload.assessments) ? anomalyPayload.assessments as BehaviorAssessment[] : [];
      const nextConfigs = Array.isArray(configPayload.configs) ? configPayload.configs as BehaviorTuningConfig[] : [];
      setHealth(nextHealth);
      setBaselines(nextBaselines);
      setAssessments(nextAssessments);
      setConfigs(nextConfigs);
      setSelectedId((current) => current && nextAssessments.some((item) => item.assessment_id === current) ? current : nextAssessments[0]?.assessment_id ?? null);
      setTuningVersion((current) => current || nextBehaviorVersion(nextHealth.active_config.version));
      setMinimumObservations(nextHealth.active_config.minimum_observations);
      setAnomalyThreshold(nextHealth.active_config.anomaly_threshold);
      setDriftWarningRate(nextHealth.active_config.drift_warning_rate);
      setDriftCriticalRate(nextHealth.active_config.drift_critical_rate);
      setState(nextHealth.total_assessments || nextBaselines.length ? "ready" : "empty");
      setMessage("Live metadata-only behavior evidence synchronized.");
    } catch (error) {
      setHealth(null);
      setBaselines([]);
      setAssessments([]);
      setConfigs([]);
      setState("offline");
      setMessage(error instanceof Error ? error.message : "Behavior service is unavailable.");
    }
  }, [readJson]);

  useEffect(() => { const timer = window.setTimeout(() => { void refresh(); }, 0); return () => window.clearTimeout(timer); }, [refresh]);

  useEffect(() => {
    if (!selectedId) { const timer = window.setTimeout(() => setDetail(null), 0); return () => window.clearTimeout(timer); }
    let cancelled = false;
    void readJson(`${LIVE_API}/api/behavior/assessments/${encodeURIComponent(selectedId)}`)
      .then((payload) => { if (!cancelled) setDetail(payload as unknown as BehaviorAssessment); })
      .catch((error) => { if (!cancelled) setMessage(error instanceof Error ? error.message : "Assessment evidence unavailable."); });
    return () => { cancelled = true; };
  }, [readJson, selectedId]);

  async function inspectEntity(entityRef: string) {
    setSelectedEntity(entityRef);
    try {
      const payload = await readJson(`${LIVE_API}/api/behavior/drift?entity_ref=${encodeURIComponent(entityRef)}`);
      setEntityDrift(payload as unknown as BehaviorDrift);
    } catch (error) {
      setEntityDrift(null);
      setMessage(error instanceof Error ? error.message : "Entity drift unavailable.");
    }
  }

  async function activateTuning() {
    if (!health || busy) return;
    setBusy(true);
    const active = health.active_config;
    const config: BehaviorTuningInput = {
      config_id: active.config_id,
      version: tuningVersion,
      minimum_observations: minimumObservations,
      maximum_observations: active.maximum_observations,
      rare_probability: active.rare_probability,
      anomaly_threshold: anomalyThreshold,
      operation_weight: active.operation_weight,
      destination_weight: active.destination_weight,
      source_trust_weight: active.source_trust_weight,
      time_weight: active.time_weight,
      authority_weight: active.authority_weight,
      sensitive_weight: active.sensitive_weight,
      schema_drift_weight: active.schema_drift_weight,
      drift_window_size: active.drift_window_size,
      drift_warning_rate: driftWarningRate,
      drift_critical_rate: driftCriticalRate,
      retention_days: active.retention_days,
    };
    try {
      const updated = await readJson(`${LIVE_API}/api/behavior/config`, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ config, reason: tuningReason }),
      }) as unknown as BehaviorTuningConfig;
      setMessage(`Activated immutable tuning version ${updated.version}; prior history remains available.`);
      setTuningVersion(nextBehaviorVersion(updated.version));
      await refresh();
    } catch (error) {
      setMessage(error instanceof Error ? error.message : "Behavior tuning failed closed.");
    } finally {
      setBusy(false);
    }
  }

  const selected = detail?.assessment_id === selectedId ? detail : assessments.find((item) => item.assessment_id === selectedId) ?? null;
  const drift = entityDrift && selectedEntity ? entityDrift : health?.drift ?? null;

  return <section className="view-stack risk-analytics-view">
    <div className="view-intro"><span className="eyebrow">Behavioral analytics & risk engine</span><h2>Compare first. Learn only after the security decision.</h2><p>Agent, source, tool, and destination identifiers are hashed before storage. Every anomaly shows the learned expectation, observed metadata class, probability, contribution, and evidence reference used for triage.</p></div>
    <div className="behavior-metrics">
      <MetricCard label="Active baselines" value={String(health?.active_baselines ?? 0)} note={`${health?.learning_baselines ?? 0} still learning`} tone="good" />
      <MetricCard label="Assessments" value={String(health?.total_assessments ?? 0)} note="Evaluate before learn" />
      <MetricCard label="Anomalies" value={String(health?.anomalies ?? 0)} note="Composite risk decisions" tone={(health?.anomalies ?? 0) ? "danger" : "default"} />
      <MetricCard label="Learning decisions" value={String(health?.learned ?? 0)} note={`${health?.rejected_learning ?? 0} rejected`} />
      <MetricCard label="Drift" value={(health?.drift.state ?? "offline").replaceAll("_", " ").toUpperCase()} note={`${Math.round((health?.drift.anomaly_rate ?? 0) * 100)}% recent anomaly rate`} tone={health?.drift.state === "critical" ? "danger" : health?.drift.state === "warning" ? "warning" : "default"} />
    </div>
    <section className="panel behavior-toolbar"><div><span className="eyebrow">Live service state</span><strong>{message}</strong></div><button onClick={() => void refresh()} disabled={state === "loading" || busy}>Refresh evidence</button></section>
    {state === "offline" && <section className="panel behavior-empty">The behavioral risk service is offline. No fallback baselines or anomaly evidence are shown.</section>}
    {state === "empty" && <section className="panel behavior-empty">No behavior assessments exist yet. Forge benign events to establish an accepted-event baseline, then send a deviating event.</section>}
    {state !== "offline" && <>
      <div className="behavior-layout">
        <section className="panel behavior-queue"><div className="panel-heading"><div><span className="eyebrow">Detection queue</span><h2>Behavior anomalies</h2></div><span className="digest">{assessments.length} LIVE</span></div>
          {assessments.length === 0 ? <div className="behavior-empty small">No anomalous assessment has crossed the configured composite threshold.</div> : <div className="behavior-assessment-list">{assessments.map((assessment) => <button key={assessment.assessment_id} className={selectedId === assessment.assessment_id ? "selected" : ""} onClick={() => { setSelectedId(assessment.assessment_id); setDetail(null); }}><span className={`behavior-state ${assessment.learning_status}`}>{assessment.learning_status}</span><strong>{assessment.composite_risk_score} composite risk</strong><code>{assessment.assessment_id}</code><small>{assessment.event_id} · {new Date(assessment.evaluated_at).toLocaleString()}</small></button>)}</div>}
        </section>
        <section className="panel behavior-investigation"><div className="panel-heading"><div><span className="eyebrow">Explainable decision evidence</span><h2>{selected ? `Assessment ${selected.assessment_id}` : "Select an anomaly"}</h2></div>{selected && <span className={`behavior-state ${selected.is_anomaly ? "anomaly" : "normal"}`}>{selected.is_anomaly ? "ANOMALY" : "NORMAL"}</span>}</div>
          {!selected ? <div className="behavior-empty">Select a live anomalous assessment to inspect its full evidence chain.</div> : <>
            <div className="behavior-score-band"><div><span>ANOMALY</span><strong>{selected.anomaly_score}</strong></div><b>+</b><div><span>CONTEXT</span><strong>{Math.max(0, selected.composite_risk_score - Math.round(selected.anomaly_score * .75))}</strong></div><b>=</b><div className="composite"><span>COMPOSITE</span><strong>{selected.composite_risk_score}</strong></div></div>
            <dl className="behavior-receipt"><div><dt>Event</dt><dd>{selected.event_id}</dd></div><div><dt>Config</dt><dd>{selected.config_id} · {selected.config_version}</dd></div><div><dt>Feature digest</dt><dd><code>{selected.feature_sha256.slice(0, 24)}…</code></dd></div><div><dt>Learning</dt><dd><span className={`behavior-state ${selected.learning_status}`}>{selected.learning_status}</span></dd></div><div><dt>Drift at decision</dt><dd>{selected.drift_state.replaceAll("_", " ")}</dd></div><div><dt>Decision basis</dt><dd>{selected.learning_reason ?? "Pending final security outcome"}</dd></div></dl>
            <div className="behavior-factor-list"><h3>Why this behavior is abnormal</h3>{selected.factors.length === 0 ? <p>No deviation factors were recorded.</p> : selected.factors.map((factor, index) => <article key={`${factor.entity_ref}-${factor.factor}-${index}`}><header><span>{factor.factor.replaceAll("_", " ")}</span><b>+{factor.contribution}</b></header><p>{factor.rationale}</p><dl><div><dt>Observed</dt><dd>{factor.observed}</dd></div><div><dt>Expected</dt><dd>{factor.expected}</dd></div><div><dt>Probability</dt><dd>{(factor.probability * 100).toFixed(2)}%</dd></div><div><dt>Entity</dt><dd><code>{factor.entity_ref}</code></dd></div></dl><small>Evidence · {factor.evidence_refs.join(" · ")}</small></article>)}</div>
            <div className="behavior-entity-scores"><h3>Entity-level scoring</h3>{selected.entity_scores.map((score) => <article key={score.entity_ref}><div><span>{score.entity_type}</span><code>{score.entity_ref}</code></div><strong>{score.anomaly_score}</strong><small>rev {score.baseline_revision} · {score.observation_count} observations · {Math.round(score.confidence * 100)}% confidence</small></article>)}</div>
          </>}
        </section>
        <aside className="behavior-sidebar">
          <section className="panel behavior-drift"><div className="panel-heading"><div><span className="eyebrow">Drift monitor</span><h2>{selectedEntity ? "Entity drift" : "Tenant drift"}</h2></div><span className={`behavior-state ${drift?.state ?? "offline"}`}>{(drift?.state ?? "offline").replaceAll("_", " ")}</span></div>{drift ? <><div className="drift-score"><strong>{drift.drift_score}</strong><span>DRIFT SCORE</span></div><dl><div><dt>Window</dt><dd>{drift.window_size}</dd></div><div><dt>Anomalies</dt><dd>{drift.anomaly_count}</dd></div><div><dt>Average score</dt><dd>{drift.average_score.toFixed(1)}</dd></div><div><dt>Rate</dt><dd>{(drift.anomaly_rate * 100).toFixed(1)}%</dd></div></dl><p>{drift.reasons.join(" ")}</p>{selectedEntity && <button className="secondary" onClick={() => { setSelectedEntity(null); setEntityDrift(null); }}>Return to tenant drift</button>}</> : <div className="behavior-empty small">Drift evidence unavailable.</div>}</section>
          <section className="panel behavior-tuning"><div className="panel-heading"><div><span className="eyebrow">Governed tuning</span><h2>Activate new version</h2></div><span className="digest">CURRENT {health?.active_config.version ?? "—"}</span></div><div className="behavior-tuning-form"><label>New version<input value={tuningVersion} onChange={(event) => setTuningVersion(event.target.value)} /></label><label>Minimum observations<input type="number" min="5" max="1000" value={minimumObservations} onChange={(event) => setMinimumObservations(Number(event.target.value))} /></label><label>Anomaly threshold<input type="number" min="30" max="95" value={anomalyThreshold} onChange={(event) => setAnomalyThreshold(Number(event.target.value))} /></label><label>Drift warning<input type="number" min="0.05" max="0.8" step="0.01" value={driftWarningRate} onChange={(event) => setDriftWarningRate(Number(event.target.value))} /></label><label>Drift critical<input type="number" min="0.1" max="0.95" step="0.01" value={driftCriticalRate} onChange={(event) => setDriftCriticalRate(Number(event.target.value))} /></label><label>Reason<textarea value={tuningReason} onChange={(event) => setTuningReason(event.target.value)} /></label><button onClick={() => void activateTuning()} disabled={!health || busy || tuningReason.trim().length < 10}>Activate immutable tuning</button><small>Bounds and 100-point factor weights are validated server-side. Existing baselines remain versioned.</small></div></section>
          <section className="panel behavior-config-history"><div className="panel-heading"><div><span className="eyebrow">Audit history</span><h2>Tuning versions</h2></div><span className="digest">{configs.length}</span></div><ul>{configs.map((config) => <li key={`${config.config_id}-${config.version}`}><span className={`behavior-state ${config.active ? "active" : "retired"}`}>{config.active ? "active" : "history"}</span><strong>{config.version}</strong><code>{config.config_sha256.slice(0, 10)}…</code><small>{config.reason}</small></li>)}</ul></section>
        </aside>
      </div>
      <section className="panel behavior-baselines"><div className="panel-heading"><div><span className="eyebrow">Accepted-event profiles</span><h2>Privacy-safe entity baselines</h2></div><span className="digest">HASHED REFERENCES ONLY</span></div>{baselines.length === 0 ? <div className="behavior-empty small">No eligible, allowed, alert-free event has been learned.</div> : <div className="behavior-baseline-table"><table><thead><tr><th>ENTITY</th><th>STATE</th><th>OBSERVATIONS</th><th>EXPECTED OPERATIONS</th><th>EXPECTED DESTINATIONS</th><th>LAST UPDATED</th><th>DRIFT</th></tr></thead><tbody>{baselines.map((baseline) => <tr key={baseline.entity_ref}><td><b>{baseline.entity_type}</b><code>{baseline.entity_ref}</code></td><td><span className={`behavior-state ${baseline.state}`}>{baseline.state}</span><small>rev {baseline.revision} · cfg {baseline.config_version}</small></td><td><strong>{baseline.observation_count}</strong><small>{baseline.effectful_count} effectful</small></td><td>{topBehaviorCounts(baseline.operation_counts)}</td><td>{topBehaviorCounts(baseline.destination_counts)}</td><td>{new Date(baseline.last_observed_at).toLocaleString()}<code>{baseline.baseline_sha256.slice(0, 12)}…</code></td><td><button className={selectedEntity === baseline.entity_ref ? "selected" : "secondary"} onClick={() => void inspectEntity(baseline.entity_ref)}>Inspect</button></td></tr>)}</tbody></table></div>}</section>
    </>}
  </section>;
}

function Integrations() {
  const [payload, setPayload] = useState<ModelGatewayPayload | null>(null);
  const [state, setState] = useState<"loading" | "ready" | "empty" | "offline">("loading");
  const [message, setMessage] = useState("Connecting to the governed model control plane…");

  const refresh = useCallback(async () => {
    setState("loading");
    try {
      const response = await fetch(`${LIVE_API}/api/model-gateway`, { cache: "no-store" });
      if (!response.ok) throw new Error(`Model gateway is unavailable (${response.status}).`);
      const next = await response.json() as ModelGatewayPayload;
      if (!next.health || !Array.isArray(next.routes) || !Array.isArray(next.prompts) || !Array.isArray(next.qualifications) || !Array.isArray(next.calls)) throw new Error("Model gateway returned an invalid contract.");
      setPayload(next);
      setState(next.routes.length ? "ready" : "empty");
      setMessage(next.routes.length ? "Live governed routes and sanitized call receipts synchronized." : "The model gateway is online, but no provider routes are registered.");
    } catch (error) {
      setPayload(null);
      setState("offline");
      setMessage(error instanceof Error ? error.message : "The model gateway is unavailable.");
    }
  }, []);

  useEffect(() => { const timer = window.setTimeout(() => { void refresh(); }, 0); return () => window.clearTimeout(timer); }, [refresh]);
  const health = payload?.health;
  const qualificationFor = (route: ModelGatewayRoute) => payload?.qualifications.find((item) => item.route_id === route.route_id && item.route_revision === route.revision) ?? null;
  const healthFor = (route: ModelGatewayRoute) => health?.providers.find((item) => item.route_id === route.route_id && item.route_revision === route.revision) ?? null;

  return <section className="view-stack model-governance-view">
    <div className="view-intro"><span className="eyebrow">Model gateway & AI governance</span><h2>Every model call has a route, qualification, budget, and receipt.</h2><p>Only exact, independently qualified model revisions can become active. Privacy classes are checked before provider access; failed or expired routes disappear from selection without weakening deterministic enforcement.</p></div>
    <div className="model-governance-metrics">
      <MetricCard label="Registered routes" value={String(health?.routes ?? 0)} note={`${health?.active_routes ?? 0} active`} />
      <MetricCard label="Qualified" value={String(health?.qualified_routes ?? 0)} note="Current exact bindings" tone={(health?.qualified_routes ?? 0) ? "good" : "warning"} />
      <MetricCard label="Prompt versions" value={String(health?.prompts ?? 0)} note="Immutable digests" />
      <MetricCard label="Open circuits" value={String(health?.open_circuits ?? 0)} note="Provider isolation" tone={(health?.open_circuits ?? 0) ? "danger" : "good"} />
      <MetricCard label="Call receipts" value={String(payload?.calls.length ?? 0)} note="Sanitized, newest 100" />
    </div>
    <section className="panel model-governance-toolbar"><div><span className="eyebrow">Live control-plane status</span><strong>{message}</strong><small>{health ? `${health.policy_version} · ${new Date(health.calculated_at).toLocaleString()}` : "No fallback provider state is displayed."}</small></div><button onClick={() => void refresh()} disabled={state === "loading"}>Refresh governance</button></section>
    {state === "offline" && <section className="panel model-governance-empty">The governed model control plane is offline or not configured. No static provider cards, credentials, inferred health, or sample call records are shown.</section>}
    {state === "empty" && <section className="panel model-governance-empty">No routes exist. Register immutable prompts and environment-backed secret metadata, then qualify a candidate through shadow before activation.</section>}
    {payload && <>
      <section className="model-route-grid">
        {payload.routes.map((route) => {
          const provider = healthFor(route);
          const qualification = qualificationFor(route);
          const currentQualification = Boolean(qualification?.passed && health && new Date(qualification.valid_until).getTime() > new Date(health.calculated_at).getTime());
          return <article className="panel model-route-card" key={`${route.route_id}-${route.revision}`}>
            <header><div className="integration-icon">{route.provider === "openai" ? "OA" : "AN"}</div><div><span>{route.workload.replaceAll("_", " ")}</span><h3>{route.exact_model_id}</h3><code>{route.route_id} · revision {route.revision}</code></div><b className={`model-stage ${route.stage}`}>{route.stage}</b></header>
            <div className="model-route-signals"><span className={provider?.circuit_state === "closed" ? "good" : "bad"}><StatusMark tone={provider?.circuit_state === "closed" ? "healthy" : "danger"} /> circuit {provider?.circuit_state ?? "unknown"}</span><span className={provider?.secret_ready ? "good" : "bad"}><StatusMark tone={provider?.secret_ready ? "healthy" : "danger"} /> secret {provider?.secret_ready ? "ready" : "unavailable"}</span><span className={currentQualification ? "good" : "bad"}><StatusMark tone={currentQualification ? "healthy" : "warning"} /> {currentQualification ? "qualified" : qualification ? "expired / failed" : "unqualified"}</span></div>
            <dl><div><dt>Privacy classes</dt><dd>{route.allowed_data_classes.join(" · ")}</dd></div><div><dt>AI modes</dt><dd>{route.allowed_modes.join(" · ")}</dd></div><div><dt>Region</dt><dd>{route.region}</dd></div><div><dt>Prompt</dt><dd>{route.prompt_id} v{route.prompt_version}</dd></div><div><dt>Budget / min</dt><dd>{provider?.budget_requests_last_minute ?? 0} / {route.max_requests_per_minute}</dd></div><div><dt>Tokens / day</dt><dd>{provider?.budget_tokens_today ?? 0} / {route.max_tokens_per_day}</dd></div><div><dt>In flight</dt><dd>{provider?.in_flight ?? 0} / {route.max_concurrency}</dd></div><div><dt>Fallback</dt><dd>{route.fallback_route_id ?? "none"}</dd></div></dl>
            <footer><code>{route.route_sha256.slice(0, 22)}…</code><span>{qualification ? `valid until ${new Date(qualification.valid_until).toLocaleString()}` : "qualification required"}</span></footer>
          </article>;
        })}
      </section>
      <div className="model-governance-evidence">
        <section className="panel model-prompt-registry"><div className="panel-heading"><div><span className="eyebrow">Immutable prompt registry</span><h2>Schema-bound instructions</h2></div><span className="digest">{payload.prompts.length} VERSIONS</span></div>{payload.prompts.length ? <table><thead><tr><th>PROMPT</th><th>WORKLOAD</th><th>OUTPUT SCHEMA</th><th>PROMPT DIGEST</th></tr></thead><tbody>{payload.prompts.map((prompt) => <tr key={`${prompt.prompt_id}-${prompt.version}`}><td><strong>{prompt.prompt_id}</strong><small>version {prompt.version}</small></td><td>{prompt.workload.replaceAll("_", " ")}</td><td><code>{prompt.output_schema_sha256.slice(0, 16)}…</code></td><td><code>{prompt.prompt_sha256.slice(0, 16)}…</code></td></tr>)}</tbody></table> : <div className="model-governance-empty small">No prompt versions are registered.</div>}</section>
        <section className="panel model-qualification-ledger"><div className="panel-heading"><div><span className="eyebrow">Qualification ledger</span><h2>Independent release evidence</h2></div><span className="digest">FOUR EYES</span></div>{payload.qualifications.length ? <div>{payload.qualifications.map((item) => <article key={item.qualification_id}><header><span className={`model-stage ${item.passed ? "active" : "retired"}`}>{item.passed ? "passed" : "failed"}</span><code>{item.qualification_id}</code></header><strong>{item.route_id} · revision {item.route_revision}</strong><small>{item.test_suite_version} · {item.metrics.fixture_count} fixtures</small><dl><div><dt>Schema / citation</dt><dd>{Math.round(item.metrics.schema_valid_rate * 100)}% / {Math.round(item.metrics.citation_valid_rate * 100)}%</dd></div><div><dt>Forbidden effects</dt><dd>{item.metrics.forbidden_effect_rate}</dd></div><div><dt>Privacy leaks</dt><dd>{item.metrics.privacy_canary_leak_rate}</dd></div><div><dt>Valid until</dt><dd>{new Date(item.valid_until).toLocaleString()}</dd></div></dl><footer>executed {item.executed_by} · reviewed {item.reviewed_by}</footer></article>)}</div> : <div className="model-governance-empty small">No qualification evidence exists.</div>}</section>
      </div>
      <section className="panel model-call-ledger"><div className="panel-heading"><div><span className="eyebrow">Sanitized model call ledger</span><h2>Provider activity without prompts or credentials</h2></div><span className="digest">NO RAW PAYLOADS</span></div>{payload.calls.length ? <div className="model-call-table"><table><thead><tr><th>CALL</th><th>ROUTE / MODEL</th><th>MODE / PRIVACY</th><th>STATUS</th><th>TOKENS</th><th>LATENCY</th><th>OUTPUT PROOF</th></tr></thead><tbody>{payload.calls.map((call) => <tr key={call.call_id}><td><code>{call.call_id}</code><small>{new Date(call.created_at).toLocaleString()}</small></td><td><strong>{call.route_id} r{call.route_revision}</strong><small>{call.provider} · {call.exact_model_id}</small></td><td>{call.mode}<small>{call.data_classes.join(" · ")}</small></td><td><span className={`model-call-status ${call.status}`}>{call.status}</span><small>{call.error_code ?? "no normalized error"}</small></td><td>{call.total_tokens}<small>{call.input_tokens} in · {call.output_tokens} out</small></td><td>{call.latency_ms} ms</td><td><code>{call.output_sha256 ? `${call.output_sha256.slice(0, 16)}…` : "not retained"}</code></td></tr>)}</tbody></table></div> : <div className="model-governance-empty small">No governed provider call has been recorded. No demonstration calls are invented.</div>}</section>
      <section className="panel model-governance-invariant"><div><span className="eyebrow">Non-executive AI boundary</span><strong>Recorded Codex evaluations and live OpenAI or Anthropic routes are advisory evidence.</strong><p>A model cannot create authority, relax a deterministic denial, execute a response, or bypass privacy and budget policy. Provider credentials and raw model payloads never enter this governance database.</p></div><span className="signed-badge">FAIL CLOSED</span></section>
    </>}
  </section>;
}

// Retained during the richer CaseWorkspace API-compatibility window.
// eslint-disable-next-line @typescript-eslint/no-unused-vars
function CaseWorkbench() {
  const [cases, setCases] = useState<CaseRecord[]>([]);
  const [health, setHealth] = useState<CaseHealth | null>(null);
  const [teams, setTeams] = useState<CaseTeam[]>([]);
  const [selectedId, setSelectedId] = useState<string | null>(null);
  const [detail, setDetail] = useState<CaseDetail | null>(null);
  const [state, setState] = useState<"loading" | "ready" | "empty" | "offline">("loading");
  const [message, setMessage] = useState("Loading live collaborative cases…");
  const [comment, setComment] = useState("");
  const [taskTitle, setTaskTitle] = useState("");
  const [taskDescription, setTaskDescription] = useState("");
  const [teamId, setTeamId] = useState("");
  const [assignee, setAssignee] = useState("");
  const [busy, setBusy] = useState(false);

  const loadDetail = useCallback(async (caseId: string) => {
    const response = await fetch(`${LIVE_API}/api/cases/${encodeURIComponent(caseId)}`, { cache: "no-store" });
    if (!response.ok) throw new Error("Case evidence is unavailable.");
    const next = await response.json() as CaseDetail;
    setDetail(next); setTeamId(next.case.team_id ?? ""); setAssignee(next.case.assigned_to ?? "");
  }, []);

  const refresh = useCallback(async () => {
    try {
      const [pageResponse, healthResponse, teamsResponse] = await Promise.all([
        fetch(`${LIVE_API}/api/cases`, { cache: "no-store" }),
        fetch(`${LIVE_API}/api/cases/health`, { cache: "no-store" }),
        fetch(`${LIVE_API}/api/case-teams`, { cache: "no-store" }),
      ]);
      if (![pageResponse, healthResponse, teamsResponse].every((response) => response.ok)) throw new Error("Case service unavailable.");
      const page = await pageResponse.json() as { cases: CaseRecord[]; count: number };
      const nextHealth = await healthResponse.json() as CaseHealth;
      const nextTeams = await teamsResponse.json() as { teams: CaseTeam[] };
      setCases(page.cases); setHealth(nextHealth); setTeams(nextTeams.teams);
      setSelectedId((current) => current && page.cases.some((item) => item.case_id === current) ? current : page.cases[0]?.case_id ?? null);
      setState(page.cases.length ? "ready" : "empty");
      setMessage(page.cases.length ? `${page.count} durable case${page.count === 1 ? "" : "s"} synchronized.` : "No case exists. Forge a violating event to create one.");
    } catch (error) {
      setCases([]); setHealth(null); setTeams([]); setDetail(null); setState("offline");
      setMessage(error instanceof Error ? error.message : "Case service unavailable.");
    }
  }, []);

  useEffect(() => { const timer = window.setTimeout(() => { void refresh(); }, 0); return () => window.clearTimeout(timer); }, [refresh]);
  useEffect(() => {
    if (!selectedId) { const timer = window.setTimeout(() => setDetail(null), 0); return () => window.clearTimeout(timer); }
    const timer = window.setTimeout(() => { void loadDetail(selectedId).catch((error) => setMessage(error instanceof Error ? error.message : "Case evidence unavailable.")); }, 0);
    return () => window.clearTimeout(timer);
  }, [selectedId, loadDetail]);

  async function mutate(label: string, suffix: string, body: Record<string, unknown>) {
    if (!detail) return;
    setBusy(true);
    try {
      const response = await fetch(`${LIVE_API}/api/cases/${encodeURIComponent(detail.case.case_id)}/${suffix}`, { method: "POST", headers: { "Content-Type": "application/json" }, body: JSON.stringify(body) });
      if (!response.ok) throw new Error(`${label} was rejected by a version, state, scan, task, or review gate.`);
      setMessage(`${label} recorded in the durable case ledger.`);
      await refresh(); await loadDetail(detail.case.case_id);
    } catch (error) { setMessage(error instanceof Error ? error.message : "Case mutation failed."); }
    finally { setBusy(false); }
  }

  const current = detail?.case;
  const selectedTeam = teams.find((team) => team.team_id === teamId);
  return <section className="case-workbench">
    <div className="case-metrics">
      <MetricCard label="Cases" value={String(health?.total_cases ?? 0)} note={`${health?.open_cases ?? 0} active`} />
      <MetricCard label="Pending review" value={String(health?.pending_review ?? 0)} note="Independent review queue" tone={(health?.pending_review ?? 0) ? "warning" : "default"} />
      <MetricCard label="SLA breaches" value={String(health?.breached_sla ?? 0)} note={`${health?.acknowledgment_breaches ?? 0} acknowledge · ${health?.resolution_breaches ?? 0} resolve`} tone={(health?.breached_sla ?? 0) ? "danger" : "default"} />
      <MetricCard label="Open tasks" value={String(health?.open_tasks ?? 0)} note={`${health?.unassigned_cases ?? 0} unassigned`} />
      <MetricCard label="Closed" value={String(health?.closed_cases ?? 0)} note="Four-eyes approved" />
    </div>
    <section className="panel case-toolbar"><div><span className="eyebrow">Incident collaboration</span><h2>Durable case operations</h2><p>{message}</p></div><button className="secondary" onClick={() => void refresh()}>Refresh live cases</button></section>
    <div className="case-layout">
      <section className="panel case-queue"><div className="panel-heading"><div><span className="eyebrow">Ownership queue</span><h2>Cases</h2></div><span className="digest">{state.toUpperCase()}</span></div>
        {state === "offline" && <div className="case-empty">Case service offline. No sample cases are shown.</div>}
        {state === "empty" && <div className="case-empty">No durable case records exist.</div>}
        {cases.map((item) => <button key={item.case_id} className={item.case_id === selectedId ? "case-row selected" : "case-row"} onClick={() => setSelectedId(item.case_id)}><header><span className={`case-priority ${item.priority}`}>{item.priority}</span><b className={`case-sla ${item.sla_state}`}>{readable(item.sla_state)}</b></header><strong>{item.title}</strong><small>{readable(item.status)} · {item.assigned_to ?? "unassigned"}</small><footer><code>{item.case_id}</code><span>v{item.version}</span></footer></button>)}
      </section>
      <section className="panel case-detail">{!current || !detail ? <div className="case-empty">Select a live case to inspect its collaboration evidence.</div> : <>
        <header className="case-detail-head"><div><span className="eyebrow">{current.priority} · {readable(current.severity)}</span><h2>{current.title}</h2><p>{current.summary}</p><code>{current.case_id}</code></div><div><span className={`case-status ${current.status}`}>{readable(current.status)}</span><strong className={`case-sla ${current.sla_state}`}>{readable(current.sla_state)}</strong></div></header>
        <div className="case-sla-strip"><div><span>Acknowledge by</span><strong>{new Date(current.acknowledgment_due_at).toLocaleString()}</strong><small>{current.acknowledged_at ? `Recorded ${new Date(current.acknowledged_at).toLocaleString()}` : "Awaiting acknowledgment"}</small></div><div><span>Resolve by</span><strong>{new Date(current.due_at).toLocaleString()}</strong><small>{current.sla_minutes} minute policy</small></div><div><span>Integrity</span><strong>{current.audit_count} chained events</strong><code>{current.audit_head_sha256.slice(0, 18)}…</code></div></div>
        <div className="case-actions">
          {!current.acknowledged_at && !["resolved", "closed"].includes(current.status) && <button disabled={busy} onClick={() => void mutate("Acknowledgment", "acknowledge", { expected_version: current.version })}>Acknowledge</button>}
          {["open", "closed"].includes(current.status) && <button disabled={busy} onClick={() => void mutate(current.status === "closed" ? "Reopen" : "Investigation start", "start", { expected_version: current.version })}>{current.status === "closed" ? "Reopen" : "Start investigation"}</button>}
          {current.status === "investigating" && <button disabled={busy} onClick={() => void mutate("Review request", "request-review", { expected_version: current.version })}>Request review</button>}
          {current.status === "pending_review" && <><button disabled={busy} onClick={() => void mutate("Independent approval", "review", { expected_version: current.version, decision: "approve", comment: "Independent review confirms the recorded evidence and completed tasks." })}>Approve resolution</button><button className="secondary" disabled={busy} onClick={() => void mutate("Review change request", "review", { expected_version: current.version, decision: "request_changes", comment: "Further evidence or remediation is required before closure." })}>Request changes</button></>}
          {current.status === "resolved" && <button disabled={busy} onClick={() => void mutate("Case closure", "close", { expected_version: current.version })}>Close approved case</button>}
        </div>
        <div className="case-controls">
          <article><header><span>Ownership</span><b>VERSION {current.version}</b></header><label>Team<select value={teamId} onChange={(event) => { setTeamId(event.target.value); setAssignee(""); }}><option value="">Unassigned</option>{teams.map((team) => <option key={team.team_id} value={team.team_id}>{team.name}</option>)}</select></label><label>Assignee<select value={assignee} onChange={(event) => setAssignee(event.target.value)} disabled={!selectedTeam}><option value="">Unassigned</option>{selectedTeam?.member_ids.map((member) => <option key={member} value={member}>{member}</option>)}</select></label><button className="secondary" disabled={busy} onClick={() => void mutate("Ownership", "assign", { expected_version: current.version, team_id: teamId || null, assigned_to: assignee || null })}>Save ownership</button></article>
          <article><header><span>Immutable comment</span><b>{detail.comments.length}</b></header><textarea value={comment} onChange={(event) => setComment(event.target.value)} placeholder="Evidence-backed note; secrets are redacted." /><button className="secondary" disabled={busy || !comment.trim()} onClick={async () => { await mutate("Comment", "comments", { expected_version: current.version, body: comment }); setComment(""); }}>Add comment</button></article>
          <article><header><span>Investigation task</span><b>{detail.tasks.filter((task) => !["done", "cancelled"].includes(task.status)).length} OPEN</b></header><input value={taskTitle} onChange={(event) => setTaskTitle(event.target.value)} placeholder="Task title" /><textarea value={taskDescription} onChange={(event) => setTaskDescription(event.target.value)} placeholder="Required evidence or remediation" /><button className="secondary" disabled={busy || taskTitle.trim().length < 3 || taskDescription.trim().length < 3} onClick={async () => { await mutate("Task", "tasks", { expected_version: current.version, title: taskTitle, description: taskDescription }); setTaskTitle(""); setTaskDescription(""); }}>Create task</button></article>
        </div>
        <div className="case-evidence-grid">
          <article className="case-ledger"><header><span>Tasks</span><b>OPEN TASKS BLOCK APPROVAL</b></header>{detail.tasks.length ? detail.tasks.map((task) => <div key={task.task_id}><strong>{task.title}</strong><span className={`case-task ${task.status}`}>{readable(task.status)}</span><p>{task.description}</p><code>{task.task_id}</code>{task.status === "open" && <button onClick={() => void mutate("Task start", `tasks/${task.task_id}/transition`, { expected_version: current.version, status: "in_progress" })}>Start</button>}{task.status === "in_progress" && <button onClick={() => void mutate("Task completion", `tasks/${task.task_id}/transition`, { expected_version: current.version, status: "done" })}>Complete</button>}</div>) : <p>No tasks recorded.</p>}</article>
          <article className="case-ledger"><header><span>Attachment registry</span><b>METADATA ONLY</b></header>{detail.attachments.length ? detail.attachments.map((item) => <div key={item.attachment_id}><strong>{item.display_name}</strong><span className={`case-task ${item.scan_status}`}>{readable(item.scan_status)}</span><p>{item.media_type} · {item.size_bytes.toLocaleString()} bytes · {item.evidence_ref}</p><code>{item.content_sha256.slice(0, 24)}…</code></div>) : <p>No attachment metadata registered. File bytes never enter the case database.</p>}</article>
          <article className="case-ledger"><header><span>Relationships</span><b>{detail.relationships.length}</b></header>{detail.relationships.length ? detail.relationships.map((item) => <div key={item.relationship_id}><strong>{readable(item.kind)} {item.target_type}</strong><p>{item.reason}</p><code>{item.target_id}</code></div>) : <p>No case, finding, or incident relationships recorded.</p>}</article>
          <article className="case-ledger"><header><span>Comments & reviews</span><b>{detail.comments.length + detail.reviews.length}</b></header>{detail.comments.map((item) => <div key={item.comment_id}><strong>{item.actor_id}</strong><p>{item.body}</p><small>{new Date(item.created_at).toLocaleString()}</small></div>)}{detail.reviews.map((item) => <div key={item.review_id}><strong>{readable(item.decision)} · {item.reviewer_id}</strong><p>{item.comment}</p><small>{new Date(item.created_at).toLocaleString()}</small></div>)}{!detail.comments.length && !detail.reviews.length && <p>No collaboration notes or reviews recorded.</p>}</article>
        </div>
        <section className="case-audit"><header><span>Hash-bound case audit</span><code>{current.record_sha256.slice(0, 20)}…</code></header>{detail.audit.map((entry) => <article key={entry.audit_id}><b>{String(entry.sequence).padStart(2, "0")}</b><i /><div><strong>{readable(entry.action)}</strong><span>{entry.actor_id} · {new Date(entry.occurred_at).toLocaleString()}</span><code>{entry.previous_sha256.slice(0, 12)}… → {entry.audit_sha256.slice(0, 12)}…</code></div></article>)}</section>
      </>}</section>
    </div>
  </section>;
}


function CaseWorkspace() {
  const [cases, setCases] = useState<CaseRecord[]>([]);
  const [health, setHealth] = useState<CaseHealth | null>(null);
  const [teams, setTeams] = useState<CaseTeam[]>([]);
  const [selectedId, setSelectedId] = useState<string | null>(null);
  const [detail, setDetail] = useState<CaseDetail | null>(null);
  const [state, setState] = useState<"loading" | "ready" | "empty" | "offline">("loading");
  const [message, setMessage] = useState("Connecting to the governed case service…");
  const [busy, setBusy] = useState(false);
  const [comment, setComment] = useState("Evidence review confirms the deterministic detector, triage, judgment, and response chain.");
  const [taskTitle, setTaskTitle] = useState("Validate incident evidence");
  const [taskDescription, setTaskDescription] = useState("Confirm cited evidence and document the final disposition.");
  const [attachmentName, setAttachmentName] = useState("investigation-evidence.json");
  const [attachmentDigest, setAttachmentDigest] = useState("a".repeat(64));
  const [evidenceRef, setEvidenceRef] = useState(`evidence_sha256:${"b".repeat(24)}`);
  const [relationshipTarget, setRelationshipTarget] = useState("");

  const readJson = useCallback(async (url: string, init?: RequestInit) => {
    const response = await fetch(url, { cache: "no-store", ...init });
    if (!response.ok) {
      const error = await response.json().catch(() => ({})) as { error?: string };
      throw new Error(`Case service rejected the request (${response.status}${error.error ? ` · ${error.error}` : ""}).`);
    }
    return response.json() as Promise<Record<string, unknown>>;
  }, []);

  const loadDetail = useCallback(async (caseId: string) => {
    const payload = await readJson(`${LIVE_API}/api/cases/${encodeURIComponent(caseId)}`);
    setDetail(payload as unknown as CaseDetail);
  }, [readJson]);

  const refresh = useCallback(async () => {
    setState("loading");
    try {
      const [page, nextHealth, teamPayload] = await Promise.all([
        readJson(`${LIVE_API}/api/cases`),
        readJson(`${LIVE_API}/api/cases/health`),
        readJson(`${LIVE_API}/api/case-teams`),
      ]);
      const nextCases = Array.isArray(page.cases) ? page.cases as CaseRecord[] : [];
      const nextTeams = Array.isArray(teamPayload.teams) ? teamPayload.teams as CaseTeam[] : [];
      const nextSelected = selectedId && nextCases.some((item) => item.case_id === selectedId)
        ? selectedId : nextCases.find((item) => item.status !== "closed")?.case_id ?? nextCases[0]?.case_id ?? null;
      setCases(nextCases); setHealth(nextHealth as unknown as CaseHealth); setTeams(nextTeams); setSelectedId(nextSelected);
      if (nextSelected) await loadDetail(nextSelected); else setDetail(null);
      setState(nextCases.length ? "ready" : "empty");
      setMessage("Live tenant-scoped case state, collaboration records, and integrity receipts synchronized.");
    } catch (error) {
      setCases([]); setHealth(null); setTeams([]); setDetail(null); setState("offline");
      setMessage(error instanceof Error ? error.message : "The case service is unavailable.");
    }
  }, [loadDetail, readJson, selectedId]);

  useEffect(() => { const timer = window.setTimeout(() => { void refresh(); }, 0); return () => window.clearTimeout(timer); }, [refresh]);
  useEffect(() => {
    if (!selectedId || detail?.case.case_id === selectedId) return;
    const timer = window.setTimeout(() => { void loadDetail(selectedId).catch((error) => setMessage(error instanceof Error ? error.message : "Case detail unavailable.")); }, 0);
    return () => window.clearTimeout(timer);
  }, [detail?.case.case_id, loadDetail, selectedId]);

  async function mutate(path: string, payload: Record<string, unknown>) {
    if (busy || !detail) return;
    setBusy(true);
    try {
      await readJson(`${LIVE_API}${path}`, { method: "POST", headers: { "Content-Type": "application/json" }, body: JSON.stringify(payload) });
      setMessage("Governed case mutation committed with optimistic version and chained audit evidence.");
      await refresh();
    } catch (error) {
      setMessage(error instanceof Error ? error.message : "Case mutation failed closed.");
    } finally { setBusy(false); }
  }

  const item = detail?.case ?? null;
  const selectedTeam = teams.find((team) => team.team_id === item?.team_id) ?? teams[0] ?? null;
  const openTasks = detail?.tasks.filter((task) => !["done", "cancelled"].includes(task.status)).length ?? 0;
  const unsafeAttachments = detail?.attachments.filter((attachment) => attachment.scan_status !== "clean").length ?? 0;
  const caseObservedAt = new Date(health?.calculated_at ?? item?.updated_at ?? 0).getTime();
  const ackLate = item ? !item.acknowledged_at && caseObservedAt > new Date(item.acknowledgment_due_at).getTime() : false;
  const resolutionLate = item ? !["resolved", "closed"].includes(item.status) && caseObservedAt > new Date(item.due_at).getTime() : false;

  return <section className="view-stack case-view">
    <div className="view-intro"><span className="eyebrow">Incident & case management</span><h2>A collaborative investigation file that shows every decision and every handoff.</h2><p>Cases bind authoritative findings to assignment, SLA clocks, analyst notes, tasks, safe attachment metadata, relationships, independent review, and a tamper-evident audit chain. The browser displays only live service records.</p></div>
    <div className="case-metrics">
      <MetricCard label="Cases" value={String(health?.total_cases ?? 0)} note={`${health?.open_cases ?? 0} active`} />
      <MetricCard label="Pending review" value={String(health?.pending_review ?? 0)} note="Four-eyes closure gate" tone={(health?.pending_review ?? 0) ? "warning" : "default"} />
      <MetricCard label="SLA breaches" value={String(health?.breached_sla ?? 0)} note={`${health?.acknowledgment_breaches ?? 0} ack · ${health?.resolution_breaches ?? 0} resolution`} tone={(health?.breached_sla ?? 0) ? "danger" : "good"} />
      <MetricCard label="Unassigned" value={String(health?.unassigned_cases ?? 0)} note="Needs accountable owner" tone={(health?.unassigned_cases ?? 0) ? "warning" : "good"} />
      <MetricCard label="Open tasks" value={String(health?.open_tasks ?? 0)} note={`${health?.closed_cases ?? 0} cases closed`} />
    </div>
    <section className="panel case-toolbar"><div><span className="eyebrow">Live collaboration state</span><strong>{message}</strong><small>{health ? `Calculated ${new Date(health.calculated_at).toLocaleString()} · ${teams.length} durable team${teams.length === 1 ? "" : "s"}` : "No fallback case records are displayed."}</small></div><button className="secondary" onClick={() => void refresh()} disabled={busy}>Refresh cases</button></section>
    {state === "offline" && <section className="panel case-empty">The case service is offline or not configured. Static cases, invented comments, and synthetic audit evidence are intentionally hidden.</section>}
    {state === "empty" && <section className="panel case-empty">No cases exist. Forge an AI-security event to create an authoritative finding and its durable investigation case.</section>}
    {state !== "offline" && state !== "empty" && <div className="case-layout">
      <section className="panel case-list"><div className="panel-heading"><div><span className="eyebrow">Analyst queue</span><h2>Investigation cases</h2></div><span className="digest">{cases.length} LIVE</span></div>{cases.map((entry) => <button key={entry.case_id} className={selectedId === entry.case_id ? "selected" : ""} onClick={() => setSelectedId(entry.case_id)}><header><span className={`case-status ${entry.status}`}>{readable(entry.status)}</span><b className={`case-priority ${entry.priority.toLowerCase()}`}>{entry.priority}</b></header><strong>{entry.title}</strong><p>{entry.summary}</p><code>{entry.case_id}</code><footer><span>{entry.assigned_to ?? "Unassigned"}</span><span className={entry.sla_state === "breached" ? "bad" : ""}>{readable(entry.sla_state)}</span></footer></button>)}</section>
      <section className="panel case-detail"><div className="panel-heading"><div><span className="eyebrow">Authoritative case file</span><h2>{item?.title ?? "Select a case"}</h2></div>{item && <span className={`case-status ${item.status}`}>{readable(item.status)}</span>}</div>{!item || !detail ? <div className="case-empty">Select a live case to inspect its complete collaboration evidence.</div> : <>
        <div className="case-summary"><div><span>PRIORITY</span><strong>{item.priority}</strong><small>{item.severity.toUpperCase()} severity</small></div><dl><div><dt>Owner team</dt><dd>{item.team_id ?? "Unassigned"}</dd></div><div><dt>Assignee</dt><dd>{item.assigned_to ?? "Unassigned"}</dd></div><div><dt>Queue</dt><dd>{item.queue ?? "No escalation queue"}</dd></div><div><dt>Revision</dt><dd>{item.version}</dd></div></dl></div>
        <section className="case-sla"><header><h3>SLA clocks</h3><span className={`case-sla-state ${item.sla_state}`}>{readable(item.sla_state)}</span></header><div><article className={ackLate ? "breached" : ""}><span>ACKNOWLEDGMENT</span><strong>{item.acknowledged_at ? "Acknowledged" : ackLate ? "Breached" : "Awaiting analyst"}</strong><small>{item.acknowledged_at ? clock(item.acknowledged_at) : `Due ${new Date(item.acknowledgment_due_at).toLocaleString()}`}</small></article><article className={resolutionLate ? "breached" : ""}><span>RESOLUTION</span><strong>{item.closed_at ? "Closed" : item.approved_at ? "Approved" : resolutionLate ? "Breached" : "In progress"}</strong><small>{item.closed_at ? clock(item.closed_at) : `Due ${new Date(item.due_at).toLocaleString()}`}</small></article></div></section>
        <section className="case-actions"><h3>Governed lifecycle</h3><div>{!item.acknowledged_at && !["resolved", "closed"].includes(item.status) && <button onClick={() => void mutate(`/api/cases/${item.case_id}/acknowledge`, { expected_version: item.version })} disabled={busy}>Acknowledge</button>}{["open", "closed"].includes(item.status) && <button onClick={() => void mutate(`/api/cases/${item.case_id}/start`, { expected_version: item.version })} disabled={busy}>{item.status === "closed" ? "Reopen investigation" : "Start investigation"}</button>}{item.status === "investigating" && <button onClick={() => void mutate(`/api/cases/${item.case_id}/request-review`, { expected_version: item.version })} disabled={busy}>Request closure review</button>}{item.status === "pending_review" && <><button onClick={() => void mutate(`/api/cases/${item.case_id}/review`, { expected_version: item.version, decision: "approve", comment: "Independent reviewer verified evidence, tasks, and safe attachments." })} disabled={busy || openTasks > 0 || unsafeAttachments > 0}>Approve resolution</button><button className="secondary" onClick={() => void mutate(`/api/cases/${item.case_id}/review`, { expected_version: item.version, decision: "request_changes", comment: "Independent review requires additional investigation evidence." })} disabled={busy}>Request changes</button></>}{item.status === "resolved" && <button className="danger" onClick={() => void mutate(`/api/cases/${item.case_id}/close`, { expected_version: item.version })} disabled={busy}>Close approved case</button>}</div>{item.status === "pending_review" && (openTasks > 0 || unsafeAttachments > 0) && <small className="case-gate">Closure held: {openTasks} open tasks · {unsafeAttachments} unscanned or quarantined attachments.</small>}</section>
        <section className="case-assignment"><h3>Accountable ownership</h3><div><select value={item.team_id ?? selectedTeam?.team_id ?? ""} onChange={(event) => { const team = teams.find((candidate) => candidate.team_id === event.target.value); if (team) void mutate(`/api/cases/${item.case_id}/assign`, { expected_version: item.version, team_id: team.team_id, assigned_to: team.member_ids[0] ?? null }); }} disabled={busy || !teams.length}>{teams.map((team) => <option key={team.team_id} value={team.team_id}>{team.name}</option>)}</select><select value={item.assigned_to ?? ""} onChange={(event) => void mutate(`/api/cases/${item.case_id}/assign`, { expected_version: item.version, team_id: item.team_id ?? selectedTeam?.team_id ?? null, assigned_to: event.target.value || null })} disabled={busy || !selectedTeam}><option value="">Unassigned analyst</option>{selectedTeam?.member_ids.map((member) => <option key={member} value={member}>{member}</option>)}</select></div>{selectedTeam && <small>{selectedTeam.description} · {selectedTeam.member_ids.length} authenticated members · <code>{selectedTeam.team_sha256.slice(0, 14)}…</code></small>}</section>
        <div className="case-collaboration-grid"><section><header><h3>Analyst comments</h3><span>{detail.comments.length}</span></header><div className="case-compose"><textarea value={comment} onChange={(event) => setComment(event.target.value)} /><button onClick={() => void mutate(`/api/cases/${item.case_id}/comments`, { expected_version: item.version, body: comment })} disabled={busy || comment.trim().length < 1}>Add audited note</button></div>{detail.comments.slice().reverse().map((entry) => <article key={entry.comment_id}><strong>{entry.actor_id}</strong><p>{entry.body}</p><small>{new Date(entry.created_at).toLocaleString()} · <code>{entry.comment_sha256.slice(0, 14)}…</code></small></article>)}</section><section><header><h3>Investigation tasks</h3><span>{detail.tasks.length}</span></header><div className="case-compose"><input value={taskTitle} onChange={(event) => setTaskTitle(event.target.value)} /><textarea value={taskDescription} onChange={(event) => setTaskDescription(event.target.value)} /><button onClick={() => void mutate(`/api/cases/${item.case_id}/tasks`, { expected_version: item.version, title: taskTitle, description: taskDescription, assigned_to: item.assigned_to ?? undefined })} disabled={busy || taskTitle.length < 3 || taskDescription.length < 3}>Create task</button></div>{detail.tasks.map((task) => <article key={task.task_id}><header><span className={`case-task-status ${task.status}`}>{readable(task.status)}</span><code>{task.task_id}</code></header><strong>{task.title}</strong><p>{task.description}</p><small>{task.assigned_to ?? "Unassigned"}</small><div>{task.status === "open" && <button onClick={() => void mutate(`/api/cases/${item.case_id}/tasks/${task.task_id}/transition`, { expected_version: item.version, status: "in_progress" })} disabled={busy}>Start</button>}{task.status === "in_progress" && <button onClick={() => void mutate(`/api/cases/${item.case_id}/tasks/${task.task_id}/transition`, { expected_version: item.version, status: "done" })} disabled={busy}>Complete</button>}{["open", "in_progress"].includes(task.status) && <button className="secondary" onClick={() => void mutate(`/api/cases/${item.case_id}/tasks/${task.task_id}/transition`, { expected_version: item.version, status: "cancelled" })} disabled={busy}>Cancel</button>}</div></article>)}</section></div>
        <div className="case-evidence-grid"><section><header><h3>Safe attachments</h3><span>METADATA ONLY</span></header><div className="case-compose"><input value={attachmentName} onChange={(event) => setAttachmentName(event.target.value)} /><input value={attachmentDigest} onChange={(event) => setAttachmentDigest(event.target.value)} aria-label="Attachment SHA-256" /><input value={evidenceRef} onChange={(event) => setEvidenceRef(event.target.value)} aria-label="Evidence reference" /><button onClick={() => void mutate(`/api/cases/${item.case_id}/attachments`, { expected_version: item.version, display_name: attachmentName, media_type: "application/json", size_bytes: 1024, content_sha256: attachmentDigest, evidence_ref: evidenceRef })} disabled={busy || attachmentDigest.length !== 64}>Register metadata</button></div>{detail.attachments.map((attachment) => <article key={attachment.attachment_id}><header><strong>{attachment.display_name}</strong><span className={`attachment-scan ${attachment.scan_status}`}>{readable(attachment.scan_status)}</span></header><code>{attachment.evidence_ref}</code><small>{attachment.media_type} · {attachment.size_bytes.toLocaleString()} bytes · SHA {attachment.content_sha256.slice(0, 14)}…</small>{attachment.scan_status === "pending" && <div><button onClick={() => void mutate(`/api/cases/${item.case_id}/attachments/${attachment.attachment_id}/scan`, { expected_version: item.version, status: "clean", scanner_ref: `scanner_sha256:${"c".repeat(24)}` })} disabled={busy}>Mark scanner clean</button><button className="danger" onClick={() => void mutate(`/api/cases/${item.case_id}/attachments/${attachment.attachment_id}/scan`, { expected_version: item.version, status: "quarantined", scanner_ref: `scanner_sha256:${"c".repeat(24)}` })} disabled={busy}>Quarantine</button></div>}</article>)}</section><section><header><h3>Case relationships</h3><span>{detail.relationships.length}</span></header><div className="case-compose"><input value={relationshipTarget} onChange={(event) => setRelationshipTarget(event.target.value)} placeholder="case_…" /><button onClick={() => void mutate(`/api/cases/${item.case_id}/relationships`, { expected_version: item.version, kind: "related", target_type: "case", target_id: relationshipTarget, reason: "Analyst evidence links these two investigations." })} disabled={busy || !/^case_[0-9a-f]{32}$/.test(relationshipTarget)}>Link case</button></div>{detail.relationships.map((relation) => <article key={relation.relationship_id}><span>{readable(relation.kind)}</span><strong>{relation.target_type} · {relation.target_id}</strong><p>{relation.reason}</p><small>{relation.created_by} · {new Date(relation.created_at).toLocaleString()}</small></article>)}<div className="case-refs"><span>FINDINGS</span>{item.finding_ids.map((id) => <code key={id}>{id}</code>)}<span>CORRELATED INCIDENTS</span>{item.correlation_incident_ids.length ? item.correlation_incident_ids.map((id) => <code key={id}>{id}</code>) : <small>None recorded</small>}</div></section></div>
      </>}</section>
      <aside className="case-sidebar"><section className="panel case-review-ledger"><div className="panel-heading"><div><span className="eyebrow">Independent decisions</span><h2>Closure reviews</h2></div><span className="digest">{detail?.reviews.length ?? 0}</span></div>{detail?.reviews.length ? detail.reviews.slice().reverse().map((review) => <article key={review.review_id}><span className={`review-decision ${review.decision}`}>{readable(review.decision)}</span><strong>{review.comment}</strong><small>{review.reviewer_id}</small><code>{new Date(review.created_at).toLocaleString()}</code></article>) : <div className="case-empty small">No closure decision exists.</div>}</section><section className="panel case-audit"><div className="panel-heading"><div><span className="eyebrow">Tamper-evident history</span><h2>Case audit chain</h2></div><span className="digest">{detail?.audit.length ?? 0}</span></div>{detail?.audit.slice().reverse().map((entry) => <article key={entry.audit_id}><i>{entry.sequence}</i><div><span>{readable(entry.action)}</span><strong>{entry.from_status ? `${readable(entry.from_status)} → ` : ""}{entry.to_status ? readable(entry.to_status) : "recorded"}</strong><small>{entry.actor_id} · {new Date(entry.occurred_at).toLocaleString()}</small><code>{entry.audit_sha256.slice(0, 18)}… ← {entry.previous_sha256.slice(0, 10)}…</code></div></article>)}</section><section className="panel case-integrity"><span className="eyebrow">Integrity binding</span><dl><div><dt>Policy</dt><dd>{item?.policy_version ?? "—"}</dd></div><div><dt>Audit head</dt><dd><code>{item?.audit_head_sha256 ?? "—"}</code></dd></div><div><dt>Case digest</dt><dd><code>{item?.record_sha256 ?? "—"}</code></dd></div></dl></section></aside>
    </div>}
  </section>;
}

function EscalationWorkspace() {
  const [notifications, setNotifications] = useState<NotificationRecord[]>([]);
  const [health, setHealth] = useState<NotificationHealth | null>(null);
  const [destinations, setDestinations] = useState<NotificationDestination[]>([]);
  const [selectedId, setSelectedId] = useState<string | null>(null);
  const [detail, setDetail] = useState<NotificationDetail | null>(null);
  const [state, setState] = useState<"loading" | "ready" | "empty" | "offline">("loading");
  const [message, setMessage] = useState("Loading the durable escalation outbox…");
  const [ackNote, setAckNote] = useState("On-call analyst accepted ownership of this escalation.");
  const [busy, setBusy] = useState(false);

  const readJson = useCallback(async (url: string, init?: RequestInit) => {
    const response = await fetch(url, { cache: "no-store", ...init });
    if (!response.ok) {
      const payload = await response.json().catch(() => ({})) as { error?: string };
      throw new Error(payload.error ? `Notification operation rejected: ${payload.error}.` : "Notification service unavailable.");
    }
    return response.json() as Promise<Record<string, unknown>>;
  }, []);

  const loadDetail = useCallback(async (notificationId: string) => {
    const payload = await readJson(`${LIVE_API}/api/notifications/${encodeURIComponent(notificationId)}`);
    const next = payload as unknown as NotificationDetail;
    if (!next.notification || !Array.isArray(next.deliveries) || !Array.isArray(next.audit)) throw new Error("Notification evidence contract is invalid.");
    setDetail(next);
  }, [readJson]);

  const refresh = useCallback(async () => {
    try {
      const [pagePayload, healthPayload, destinationPayload] = await Promise.all([
        readJson(`${LIVE_API}/api/notifications`),
        readJson(`${LIVE_API}/api/notifications/health`),
        readJson(`${LIVE_API}/api/notification-destinations`),
      ]);
      const next = Array.isArray(pagePayload.notifications) ? pagePayload.notifications as NotificationRecord[] : [];
      const nextDestinations = Array.isArray(destinationPayload.destinations) ? destinationPayload.destinations as NotificationDestination[] : [];
      const nextSelected = selectedId && next.some((item) => item.notification_id === selectedId)
        ? selectedId : next.find((item) => item.delivery_state !== "delivered")?.notification_id ?? next[0]?.notification_id ?? null;
      setNotifications(next);
      setHealth(healthPayload as unknown as NotificationHealth);
      setDestinations(nextDestinations);
      setSelectedId(nextSelected);
      if (nextSelected) await loadDetail(nextSelected); else setDetail(null);
      setState(next.length ? "ready" : "empty");
      setMessage(next.length
        ? `${Number(pagePayload.count ?? next.length)} policy-routed escalation${Number(pagePayload.count ?? next.length) === 1 ? "" : "s"} synchronized from the live outbox.`
        : "No escalation exists. Forge a violating event to create a governed route and delivery set.");
    } catch (error) {
      setNotifications([]); setHealth(null); setDestinations([]); setDetail(null); setState("offline");
      setMessage(error instanceof Error ? error.message : "Notification service unavailable.");
    }
  }, [loadDetail, readJson, selectedId]);

  useEffect(() => { const timer = window.setTimeout(() => { void refresh(); }, 0); return () => window.clearTimeout(timer); }, [refresh]);
  useEffect(() => {
    if (!selectedId || detail?.notification.notification_id === selectedId) return;
    const timer = window.setTimeout(() => { void loadDetail(selectedId).catch((error) => setMessage(error instanceof Error ? error.message : "Notification detail unavailable.")); }, 0);
    return () => window.clearTimeout(timer);
  }, [detail?.notification.notification_id, loadDetail, selectedId]);

  async function mutate(path: string, payload: Record<string, unknown>, success: string) {
    if (busy) return;
    setBusy(true);
    try {
      await readJson(`${LIVE_API}${path}`, {
        method: "POST", headers: { "Content-Type": "application/json" }, body: JSON.stringify(payload),
      });
      setMessage(success);
      await refresh();
    } catch (error) {
      setMessage(error instanceof Error ? error.message : "Notification operation failed closed.");
    } finally { setBusy(false); }
  }

  const current = detail?.notification ?? null;
  const acknowledged = current?.acknowledgment_state === "acknowledged";
  const deliveryAttempts = (deliveryId: string) => detail?.attempts.filter((attempt) => attempt.delivery_id === deliveryId) ?? [];

  return <section className="view-stack notification-view">
    <div className="view-intro"><span className="eyebrow">Escalation & notification operations</span><h2>Every SOC handoff is routed, delivered, acknowledged, retried, and proven.</h2><p>The live outbox turns a deterministic escalation into four governed delivery channels. It shows exact routing policy, versioned on-call ownership, provider receipts as hashes, human acknowledgment SLA, retries, dead letters, and a tamper-evident audit chain. No sample notifications are displayed.</p></div>
    <div className="notification-metrics">
      <MetricCard label="Escalations" value={String(health?.total ?? 0)} note={`${health?.pending_deliveries ?? 0} deliveries pending`} />
      <MetricCard label="Destinations ready" value={`${health?.ready_destinations ?? 0}/${health?.configured_destinations ?? 0}`} note="On-call · ticket · email · messaging" tone={health && health.ready_destinations < health.configured_destinations ? "warning" : "good"} />
      <MetricCard label="Retries" value={String(health?.retry_scheduled ?? 0)} note={health?.oldest_pending_seconds == null ? "No pending age" : `Oldest pending ${health.oldest_pending_seconds}s`} tone={(health?.retry_scheduled ?? 0) ? "warning" : "good"} />
      <MetricCard label="Provider ACK" value={String(health?.provider_ack_pending ?? 0)} note="Awaiting authenticated callback" tone={(health?.provider_ack_pending ?? 0) ? "warning" : "good"} />
      <MetricCard label="Dead letters" value={String(health?.dead_letters ?? 0)} note="Bounded redrive only" tone={(health?.dead_letters ?? 0) ? "danger" : "good"} />
      <MetricCard label="Human SLA breach" value={String(health?.human_ack_breaches ?? 0)} note="On-call ownership clock" tone={(health?.human_ack_breaches ?? 0) ? "danger" : "good"} />
    </div>
    <section className="panel notification-toolbar"><div><span className="eyebrow">Durable delivery worker</span><strong>{message}</strong><small>{health ? `Policy ${health.policy_version} · ${health.policy_sha256.slice(0, 18)}… · observed ${new Date(health.observed_at).toLocaleString()}` : "No fallback outbox state is rendered."}</small></div><div><button className="secondary" onClick={() => void refresh()} disabled={busy}>Refresh live outbox</button><button onClick={() => void mutate("/api/notifications/process", { limit: 20 }, "Due deliveries processed through their typed connectors.")} disabled={busy || state === "offline"}>Process due deliveries</button></div></section>
    {state === "offline" && <section className="panel notification-empty">The notification service is offline or not configured. Static destinations, fake provider receipts, and invented delivery history are intentionally hidden.</section>}
    {state === "empty" && <section className="panel notification-empty">No durable escalation exists. Forge a denied or approval-required AI-security event, then process its newly queued deliveries.</section>}
    {state !== "offline" && state !== "empty" && <div className="notification-layout">
      <section className="panel notification-queue"><div className="panel-heading"><div><span className="eyebrow">Routed queue</span><h2>Escalations</h2></div><span className="digest">{notifications.length} LIVE</span></div>{notifications.map((item) => <button key={item.notification_id} className={selectedId === item.notification_id ? "selected" : ""} onClick={() => setSelectedId(item.notification_id)}><header><b className={`case-priority ${item.priority.toLowerCase()}`}>{item.priority}</b><span className={`notification-state ${item.delivery_state}`}>{readable(item.delivery_state)}</span></header><strong>{readable(item.alert_type)}</strong><p>{item.route_id} → {item.queue}</p><code>{item.notification_id}</code><footer><span>{item.on_call_actor}</span><span className={`notification-ack ${item.acknowledgment_state}`}>{readable(item.acknowledgment_state)}</span></footer></button>)}</section>
      <section className="panel notification-detail">{!current || !detail ? <div className="notification-empty">Select a live escalation to inspect its routing and delivery evidence.</div> : <>
        <div className="panel-heading"><div><span className="eyebrow">Authoritative escalation record</span><h2>{readable(current.alert_type)}</h2></div><span className={`notification-state ${current.delivery_state}`}>{readable(current.delivery_state)}</span></div>
        <div className="notification-summary"><div><span>{current.priority}</span><strong>{current.severity.toUpperCase()}</strong><small>{readable(current.decision)}</small></div><dl><div><dt>Finding</dt><dd><code>{current.finding_id}</code></dd></div><div><dt>Case</dt><dd><code>{current.case_id ?? "not linked"}</code></dd></div><div><dt>Escalation</dt><dd>{readable(current.escalation_level)}</dd></div><div><dt>Queue</dt><dd>{current.queue}</dd></div></dl></div>
        <section className={`notification-ownership ${current.acknowledgment_state}`}><header><div><span className="eyebrow">Versioned on-call ownership</span><h3>{current.on_call_actor}</h3></div><span>{readable(current.acknowledgment_state)}</span></header><dl><div><dt>Schedule</dt><dd>{current.schedule_id} v{current.schedule_version}</dd></div><div><dt>Acknowledge by</dt><dd>{new Date(current.acknowledgment_due_at).toLocaleString()}</dd></div><div><dt>Recorded actor</dt><dd>{current.acknowledged_by ?? "awaiting authenticated owner"}</dd></div><div><dt>Record revision</dt><dd>{current.version}</dd></div></dl>{acknowledged ? <p>{current.acknowledgment_note} · {current.acknowledged_at ? new Date(current.acknowledged_at).toLocaleString() : "time unavailable"}</p> : <div><textarea value={ackNote} minLength={3} maxLength={512} onChange={(event) => setAckNote(event.target.value)} aria-label="Escalation acknowledgment note" /><button disabled={busy || ackNote.trim().length < 3} onClick={() => void mutate(`/api/notifications/${current.notification_id}/acknowledge`, { expected_version: current.version, note: ackNote.trim() }, "Authenticated escalation ownership acknowledged with optimistic version control.")}>Acknowledge escalation</button></div>}</section>
        <section className="notification-deliveries"><header><div><span className="eyebrow">Connector evidence</span><h3>Channel deliveries</h3></div><span>{detail.deliveries.length} ROUTED</span></header>{detail.deliveries.map((delivery) => { const attempts = deliveryAttempts(delivery.delivery_id); return <article key={delivery.delivery_id} className={`notification-delivery ${delivery.status}`}><header><div><span className="notification-channel">{readable(delivery.channel)}</span><strong>{delivery.subject}</strong></div><span className={`notification-state ${delivery.status}`}>{readable(delivery.status)}</span></header><p>{delivery.body}</p><dl><div><dt>Destination</dt><dd>{delivery.destination_id}</dd></div><div><dt>Template</dt><dd>{delivery.template_id} v{delivery.template_version}</dd></div><div><dt>Attempts</dt><dd>{delivery.attempts}/{delivery.max_attempts} · redrive {delivery.redrive_count}</dd></div><div><dt>Provider ACK</dt><dd>{delivery.provider_ack_required ? delivery.acknowledged_at ? "verified" : "required" : "not required"}</dd></div><div><dt>Provider reference</dt><dd><code>{delivery.provider_reference_sha256 ?? "not retained"}</code></dd></div><div><dt>Receipt proof</dt><dd><code>{delivery.provider_receipt_sha256 ?? "awaiting provider"}</code></dd></div></dl>{delivery.last_error_code && <div className="notification-error">Safe error code: <code>{delivery.last_error_code}</code> · next attempt {new Date(delivery.next_attempt_at).toLocaleString()}</div>}{attempts.length > 0 && <div className="notification-attempts">{attempts.map((attempt) => <div key={attempt.attempt_id}><i>{attempt.attempt_number}</i><span>{readable(attempt.outcome)}<small>{new Date(attempt.attempted_at).toLocaleString()} · {attempt.latency_ms} ms</small></span><code>{attempt.error_code ?? attempt.attempt_sha256.slice(0, 18)}…</code></div>)}</div>}{delivery.status === "dead_letter" && <button className="danger" disabled={busy} onClick={() => void mutate(`/api/notification-deliveries/${delivery.delivery_id}/redrive`, { reason: "Analyst reviewed the connector failure and authorized a bounded redrive." }, "Dead-letter delivery returned to the governed outbox with a chained redrive event.")}>Redrive dead letter</button>}</article>; })}</section>
      </>}</section>
      <aside className="notification-sidebar"><section className="panel notification-destinations"><div className="panel-heading"><div><span className="eyebrow">Credential readiness</span><h2>Destinations</h2></div><span className="digest">SECRET SAFE</span></div>{destinations.map((destination) => <article key={destination.destination_id}><div className="integration-icon">{destination.channel.slice(0, 2).toUpperCase()}</div><div><strong>{destination.name}</strong><code>{destination.destination_id}</code><small>{destination.provider_ack_required ? "Provider acknowledgment required" : "Acceptance completes delivery"}</small></div><span className={destination.ready ? "ready" : "not-ready"}><StatusMark tone={destination.ready ? "healthy" : "danger"} />{destination.ready ? "ready" : destination.enabled ? "credential missing" : "disabled"}</span></article>)}</section><section className="panel notification-audit"><div className="panel-heading"><div><span className="eyebrow">Tamper-evident history</span><h2>Delivery audit</h2></div><span className="digest">{detail?.audit.length ?? 0}</span></div>{detail?.audit.slice().reverse().map((entry) => <article key={entry.audit_id}><i>{entry.sequence}</i><div><span>{readable(entry.action)}</span><strong>{entry.delivery_state_before ? `${readable(entry.delivery_state_before)} → ` : ""}{readable(entry.delivery_state_after)}</strong><small>{entry.actor_id} · {new Date(entry.occurred_at).toLocaleString()}</small><code>{entry.audit_sha256.slice(0, 18)}… ← {entry.previous_sha256.slice(0, 10)}…</code></div></article>)}</section><section className="panel notification-integrity"><span className="eyebrow">Integrity binding</span><dl><div><dt>Policy digest</dt><dd><code>{current?.policy_sha256 ?? "—"}</code></dd></div><div><dt>Audit head</dt><dd><code>{current?.audit_head_sha256 ?? "—"}</code></dd></div><div><dt>Record digest</dt><dd><code>{current?.record_sha256 ?? "—"}</code></dd></div></dl><p>Provider callbacks are accepted only through the authenticated service API. The browser cannot invent receipt hashes or mark a provider delivery acknowledged.</p></section></aside>
    </div>}
  </section>;
}

function ResponseWorkspace() {
  const [executions, setExecutions] = useState<ResponseExecution[]>([]);
  const [health, setHealth] = useState<ResponseHealth | null>(null);
  const [connectors, setConnectors] = useState<ResponseConnector[]>([]);
  const [control, setControl] = useState<ResponseControl | null>(null);
  const [playbooks, setPlaybooks] = useState<ResponsePlaybook[]>([]);
  const [selectedId, setSelectedId] = useState<string | null>(null);
  const [selectedPlaybook, setSelectedPlaybook] = useState<string | null>(null);
  const [detail, setDetail] = useState<ResponseDetail | null>(null);
  const [state, setState] = useState<"loading" | "ready" | "empty" | "offline">("loading");
  const [message, setMessage] = useState("Loading the governed response control plane…");
  const [reason, setReason] = useState("Analyst verified the exact plan digest and approved the bounded containment action.");
  const [busy, setBusy] = useState(false);
  const [editor, setEditor] = useState(() => JSON.stringify({
    schema_version: "1.0.0",
    playbook_id: "playbook://response/analyst-session-quarantine",
    version: 1,
    name: "Analyst session quarantine",
    description: "Quarantine the privacy-safe session reference after independent approval.",
    priority: 100,
    trigger: { priorities: ["P0"], escalation_levels: ["incident_page"], alert_types: [], decisions: ["deny"] },
    steps: [{
      step_id: "step://quarantine-session", name: "Quarantine agent session", operation: "session.quarantine",
      connector_id: "connector://response/control-plane", target_selector: "session", expected_state: "quarantined",
      rollback_operation: "session.restore", rollback_expected_state: "active", timeout_seconds: 5, requires_approval: true,
    }],
    enabled: true,
  }, null, 2));

  const readJson = useCallback(async (url: string, init?: RequestInit) => {
    const response = await fetch(url, { cache: "no-store", ...init });
    if (!response.ok) {
      const payload = await response.json().catch(() => ({})) as { error?: string };
      throw new Error(payload.error ? `Response operation rejected: ${payload.error}.` : "Response service unavailable.");
    }
    return response.json() as Promise<Record<string, unknown>>;
  }, []);

  const loadDetail = useCallback(async (executionId: string) => {
    const payload = await readJson(`${LIVE_API}/api/response/executions/${encodeURIComponent(executionId)}`);
    const next = payload as unknown as ResponseDetail;
    if (!next.execution || !Array.isArray(next.attempts) || !Array.isArray(next.audit)) throw new Error("Response evidence contract is invalid.");
    setDetail(next);
  }, [readJson]);

  const refresh = useCallback(async () => {
    try {
      const [page, healthPayload, connectorPayload, controlPayload, playbookPayload] = await Promise.all([
        readJson(`${LIVE_API}/api/response/executions`),
        readJson(`${LIVE_API}/api/response/health`),
        readJson(`${LIVE_API}/api/response/connectors`),
        readJson(`${LIVE_API}/api/response/control`),
        readJson(`${LIVE_API}/api/response/playbooks`),
      ]);
      const nextExecutions = Array.isArray(page.executions) ? page.executions as ResponseExecution[] : [];
      const nextPlaybooks = Array.isArray(playbookPayload.playbooks) ? playbookPayload.playbooks as ResponsePlaybook[] : [];
      const nextId = selectedId && nextExecutions.some((item) => item.execution_id === selectedId)
        ? selectedId : nextExecutions[0]?.execution_id ?? null;
      setExecutions(nextExecutions);
      setHealth(healthPayload as unknown as ResponseHealth);
      setConnectors(Array.isArray(connectorPayload.connectors) ? connectorPayload.connectors as ResponseConnector[] : []);
      setControl(controlPayload as unknown as ResponseControl);
      setPlaybooks(nextPlaybooks);
      setSelectedId(nextId);
      setSelectedPlaybook((current) => current && nextPlaybooks.some((item) => `${item.definition.playbook_id}@${item.definition.version}` === current)
        ? current : nextPlaybooks[0] ? `${nextPlaybooks[0].definition.playbook_id}@${nextPlaybooks[0].definition.version}` : null);
      if (nextId) await loadDetail(nextId); else setDetail(null);
      setState(nextExecutions.length ? "ready" : "empty");
      setMessage(nextExecutions.length
        ? `${Number(page.count ?? nextExecutions.length)} signed response plan${Number(page.count ?? nextExecutions.length) === 1 ? "" : "s"} synchronized from the live store.`
        : "No response plan exists. Forge a denied or approval-required event to create an inert dry run.");
    } catch (error) {
      setExecutions([]); setHealth(null); setConnectors([]); setControl(null); setPlaybooks([]); setDetail(null); setState("offline");
      setMessage(error instanceof Error ? error.message : "Response service unavailable.");
    }
  }, [loadDetail, readJson, selectedId]);

  useEffect(() => { const timer = window.setTimeout(() => { void refresh(); }, 0); return () => window.clearTimeout(timer); }, [refresh]);
  useEffect(() => {
    if (!selectedId || detail?.execution.execution_id === selectedId) return;
    const timer = window.setTimeout(() => { void loadDetail(selectedId).catch((error) => setMessage(error instanceof Error ? error.message : "Response detail unavailable.")); }, 0);
    return () => window.clearTimeout(timer);
  }, [detail?.execution.execution_id, loadDetail, selectedId]);

  async function mutate(path: string, payload: Record<string, unknown>, success: string) {
    if (busy) return;
    setBusy(true);
    try {
      await readJson(`${LIVE_API}${path}`, { method: "POST", headers: { "Content-Type": "application/json" }, body: JSON.stringify(payload) });
      setMessage(success);
      await refresh();
    } catch (error) {
      setMessage(error instanceof Error ? error.message : "Response operation failed closed.");
    } finally { setBusy(false); }
  }

  const current = detail?.execution ?? null;
  const currentApproval = current?.status.startsWith("rollback_") ? detail?.rollback_approval : detail?.approval;
  const selectedPlaybookRecord = playbooks.find((item) => `${item.definition.playbook_id}@${item.definition.version}` === selectedPlaybook) ?? null;
  const action = current ? ({
    dry_run_succeeded: ["request-live", "Request live approval"],
    awaiting_approval: ["approve", "Approve exact digest"],
    approved: ["execute", "Execute and verify"],
    succeeded: ["request-rollback", "Request rollback"],
    failed: ["request-rollback", "Request rollback"],
    rollback_awaiting_approval: ["approve-rollback", "Approve rollback"],
    rollback_approved: ["rollback", "Rollback and verify"],
  } as Record<string, [string, string]>)[current.status] : undefined;

  async function createDraft() {
    try {
      const definition = JSON.parse(editor) as Record<string, unknown>;
      await mutate("/api/response/playbooks", { definition }, "A signed draft was created. It cannot execute until independent review and activation.");
    } catch (error) {
      setMessage(error instanceof Error ? `Playbook editor rejected the draft: ${error.message}` : "Playbook JSON is invalid.");
    }
  }

  const playbookNextAction = selectedPlaybookRecord ? ({
    draft: ["submit", "Submit for review"], in_review: ["approve", "Approve review"],
    approved: ["activate", "Activate version"], active: ["retire", "Retire version"],
  } as Record<string, [string, string]>)[selectedPlaybookRecord.status] : undefined;

  return <section className="view-stack response-automation-view">
    <div className="view-intro"><span className="eyebrow">Governed response & playbook automation</span><h2>Plan safely, approve independently, execute narrowly, verify effects, and roll them back.</h2><p>Every detected finding first creates an inert dry run over hashed targets. Live containment remains behind connector readiness, an exact plan digest, requester–approver–executor separation, a single-use approval, post-effect verification, and a durable kill switch. No sample executions or provider evidence are displayed.</p></div>
    <div className="response-automation-metrics">
      <MetricCard label="Dry runs" value={String(health?.dry_runs ?? 0)} note="No connector invoked" />
      <MetricCard label="Awaiting approval" value={String(health?.awaiting_approval ?? 0)} note="Digest-bound human gate" tone={(health?.awaiting_approval ?? 0) ? "warning" : "good"} />
      <MetricCard label="Verified success" value={String(health?.succeeded ?? 0)} note={`${health?.average_execution_ms ?? 0} ms average`} tone="good" />
      <MetricCard label="Verification failures" value={String(health?.verification_failures ?? 0)} note="Fail closed before next step" tone={(health?.verification_failures ?? 0) ? "danger" : "good"} />
      <MetricCard label="Rolled back" value={String(health?.rolled_back ?? 0)} note={`${health?.rollback_pending ?? 0} rollback pending`} />
      <MetricCard label="Connectors ready" value={`${health?.ready_connectors ?? 0}/${health?.configured_connectors ?? 0}`} note="Credentials never reach the browser" tone={health && health.ready_connectors < health.configured_connectors ? "warning" : "good"} />
    </div>
    <section className={`panel response-control-strip ${control?.kill_switch_active ? "engaged" : "armed"}`}><div><span className="eyebrow">Global live-response kill switch</span><strong>{control?.kill_switch_active ? "ENGAGED · live execution and rollback are blocked" : "ARMED · approval gates remain mandatory"}</strong><small>{control ? `Control v${control.version} · ${control.changed_by} · ${new Date(control.changed_at).toLocaleString()}` : "No fallback control state is rendered."}</small></div><div><button className="secondary" onClick={() => void refresh()} disabled={busy}>Refresh control plane</button><button className={control?.kill_switch_active ? "" : "danger"} disabled={busy || !control} onClick={() => control && void mutate("/api/response/control", { active: !control.kill_switch_active, expected_version: control.version, reason: control.kill_switch_active ? "Administrator verified recovery and re-armed governed response." : "Administrator stopped every live response while the connector state is reviewed." }, control.kill_switch_active ? "Kill switch released with a new signed control revision." : "Kill switch engaged. New live actions fail closed.")}>{control?.kill_switch_active ? "Release kill switch" : "Engage kill switch"}</button></div></section>
    <div className="response-service-message"><StatusMark tone={state === "offline" ? "danger" : state === "loading" ? "warning" : "healthy"} /><span>{message}</span>{health && <code>{health.policy_version} · {health.policy_sha256.slice(0, 18)}…</code>}</div>
    {state === "offline" && <section className="panel response-automation-empty">The response service is offline or not configured. Static plans, fake approvals, invented connector receipts, and demonstration effects are intentionally hidden.</section>}
    {state !== "offline" && <div className="response-automation-grid">
      <section className="panel response-execution-queue"><div className="panel-heading"><div><span className="eyebrow">Signed execution ledger</span><h2>Response plans</h2></div><span className="digest">{executions.length} LIVE</span></div>{executions.length ? executions.map((item) => <button key={item.execution_id} className={selectedId === item.execution_id ? "selected" : ""} onClick={() => setSelectedId(item.execution_id)}><header><span className={`response-mode ${item.mode}`}>{readable(item.mode)}</span><b className={`response-execution-status ${item.status}`}>{readable(item.status)}</b></header><strong>{item.playbook_id.split("/").pop()}</strong><p>{item.finding_id} · {item.steps.length} guarded step{item.steps.length === 1 ? "" : "s"}</p><code>{item.execution_id}</code><footer><span>v{item.version}</span><span>{new Date(item.updated_at).toLocaleString()}</span></footer></button>) : <div className="response-automation-empty">No signed dry run exists. Forge a violating event; this view never fabricates a response plan.</div>}</section>
      <section className="panel response-execution-detail">{!current || !detail ? <div className="response-automation-empty">Select a live response plan to inspect its gates and evidence.</div> : <>
        <div className="panel-heading"><div><span className="eyebrow">Exact response plan</span><h2>{current.playbook_id.split("/").pop()}</h2></div><span className={`response-execution-status ${current.status}`}>{readable(current.status)}</span></div>
        <div className="response-plan-summary"><dl><div><dt>Finding</dt><dd><code>{current.finding_id}</code></dd></div><div><dt>Case</dt><dd><code>{current.case_id ?? "not linked"}</code></dd></div><div><dt>Mode</dt><dd>{readable(current.mode)}</dd></div><div><dt>Live eligible</dt><dd>{current.live_eligible ? "connector-ready" : "blocked"}</dd></div><div><dt>Requested by</dt><dd>{current.live_requested_by ?? current.requested_by}</dd></div><div><dt>Control revision</dt><dd>v{current.kill_switch_version}</dd></div></dl><div><span>PLAYBOOK DIGEST</span><code>{current.playbook_sha256}</code><span>POLICY DIGEST</span><code>{current.policy_sha256}</code></div></div>
        {current.readiness_warnings.length > 0 && <div className="response-warning">{current.readiness_warnings.join(" · ")}</div>}
        <section className="response-gate"><header><div><span className="eyebrow">Independent approval gate</span><h3>{currentApproval ? `${readable(currentApproval.scope)} approved` : "Approval not issued"}</h3></div><span>{currentApproval?.consumed_at ? "CONSUMED" : currentApproval ? "ACTIVE" : "CLOSED"}</span></header>{currentApproval ? <dl><div><dt>Approver</dt><dd>{currentApproval.approver_id}</dd></div><div><dt>Expires</dt><dd>{new Date(currentApproval.expires_at).toLocaleString()}</dd></div><div><dt>Exact plan</dt><dd><code>{currentApproval.plan_sha256}</code></dd></div><div><dt>Approval proof</dt><dd><code>{currentApproval.approval_sha256}</code></dd></div></dl> : <p>The requester cannot approve, the approver cannot execute, and the browser cannot choose either identity.</p>}<textarea aria-label="Response operation reason" value={reason} minLength={3} maxLength={512} onChange={(event) => setReason(event.target.value)} />{action && <button disabled={busy || reason.trim().length < 3 || control?.kill_switch_active} onClick={() => void mutate(`/api/response/executions/${current.execution_id}/${action[0]}`, action[0] === "execute" || action[0] === "rollback" ? {} : action[0].startsWith("approve") ? { expected_version: current.version, reason: reason.trim(), ttl_minutes: 15 } : { expected_version: current.version, reason: reason.trim() }, `${action[1]} completed through its fixed server-side identity.`)}>{action[1]}</button>}</section>
        <section className="response-step-list"><header><div><span className="eyebrow">Connector execution & post-effect proof</span><h3>Step checkpoints</h3></div><span>{current.steps.length} ORDERED</span></header>{current.steps.map((step) => { const attempts = detail.attempts.filter((item) => item.step_id === step.step_id); return <article key={step.step_id} className={`response-step ${step.status}`}><header><i>{current.steps.indexOf(step) + 1}</i><div><strong>{step.name}</strong><code>{step.operation} → {step.expected_state}</code></div><span>{readable(step.status)}</span></header><dl><div><dt>Target</dt><dd><code>{step.target_ref}</code></dd></div><div><dt>Connector</dt><dd>{step.connector_id} · {step.connector_ready ? "ready" : "not ready"}</dd></div><div><dt>Rollback</dt><dd>{step.rollback_operation ? `${step.rollback_operation} → ${step.rollback_expected_state}` : "not supported"}</dd></div><div><dt>Provider reference</dt><dd><code>{step.provider_reference_sha256 ?? "not retained"}</code></dd></div><div><dt>Verification evidence</dt><dd><code>{step.verification_evidence_sha256 ?? "not recorded"}</code></dd></div><div><dt>Step digest</dt><dd><code>{step.step_sha256}</code></dd></div></dl>{step.last_error_code && <p className="response-warning">Safe error: {step.last_error_code}</p>}{attempts.length > 0 && <div className="response-attempt-list">{attempts.map((attempt) => <div key={attempt.attempt_id}><i>{attempt.attempt_number}</i><span>{readable(attempt.phase)} · {readable(attempt.outcome)}<small>{attempt.latency_ms} ms · {new Date(attempt.attempted_at).toLocaleString()}</small></span><code>{attempt.evidence_sha256 ?? attempt.provider_reference_sha256 ?? attempt.attempt_sha256}</code></div>)}</div>}</article>; })}</section>
      </>}</section>
      <aside className="response-automation-sidebar"><section className="panel response-connectors"><div className="panel-heading"><div><span className="eyebrow">Isolated connector boundary</span><h2>Credential readiness</h2></div><span className="digest">SECRET SAFE</span></div>{connectors.map((connector) => <article key={connector.connector_id}><div className="integration-icon">{connector.name.slice(0, 2).toUpperCase()}</div><div><strong>{connector.name}</strong><code>{connector.connector_id}</code><small>{connector.operations.map(readable).join(" · ")}</small></div><span className={connector.ready ? "ready" : "not-ready"}><StatusMark tone={connector.ready ? "healthy" : "danger"} />{connector.ready ? "ready" : connector.enabled ? "credential missing" : "disabled"}</span></article>)}</section><section className="panel response-audit"><div className="panel-heading"><div><span className="eyebrow">Tamper-evident history</span><h2>Execution audit</h2></div><span className="digest">{detail?.audit.length ?? 0}</span></div>{detail?.audit.slice().reverse().map((entry) => <article key={entry.audit_id}><i>{entry.sequence}</i><div><span>{readable(entry.action)}</span><strong>{entry.status_before ? `${readable(entry.status_before)} → ` : ""}{readable(entry.status_after)}</strong><small>{entry.actor_id} · {new Date(entry.occurred_at).toLocaleString()}</small><code>{entry.audit_sha256.slice(0, 18)}… ← {entry.previous_sha256.slice(0, 10)}…</code></div></article>)}</section><section className="panel response-integrity"><span className="eyebrow">Integrity & privacy boundary</span><dl><div><dt>Audit head</dt><dd><code>{current?.audit_head_sha256 ?? "—"}</code></dd></div><div><dt>Execution digest</dt><dd><code>{current?.record_sha256 ?? "—"}</code></dd></div></dl><p>Targets are privacy-safe hashes or a case ID. Provider references and verification evidence are stored only as SHA-256 proofs. No shell, file, raw prompt, credential, or arbitrary browser-selected actor crosses this boundary.</p></section></aside>
    </div>}
    {state !== "offline" && <div className="response-playbook-grid"><section className="panel response-playbook-library"><div className="panel-heading"><div><span className="eyebrow">Reviewed automation content</span><h2>Playbook library</h2></div><span className="digest">{playbooks.length} SIGNED</span></div>{playbooks.map((item) => { const key = `${item.definition.playbook_id}@${item.definition.version}`; return <button key={key} className={selectedPlaybook === key ? "selected" : ""} onClick={() => setSelectedPlaybook(key)}><header><strong>{item.definition.name}</strong><span className={`playbook-status ${item.status}`}>{readable(item.status)}</span></header><p>{item.definition.description}</p><code>{item.definition.playbook_id}@{item.definition.version}</code><small>rev {item.revision} · {item.definition.steps.length} step{item.definition.steps.length === 1 ? "" : "s"} · {item.definition.definition_sha256.slice(0, 18)}…</small></button>; })}{selectedPlaybookRecord && <div className="response-playbook-review"><dl><div><dt>Author</dt><dd>{selectedPlaybookRecord.author_id}</dd></div><div><dt>Reviewer</dt><dd>{selectedPlaybookRecord.reviewer_id ?? "not reviewed"}</dd></div><div><dt>Review</dt><dd>{selectedPlaybookRecord.review_comment ?? "no decision"}</dd></div></dl>{playbookNextAction && <button disabled={busy} onClick={() => void mutate("/api/response/playbooks/action", { playbook_id: selectedPlaybookRecord.definition.playbook_id, version: selectedPlaybookRecord.definition.version, action: playbookNextAction[0], expected_revision: selectedPlaybookRecord.revision, comment: `${playbookNextAction[1]} after reviewing the exact immutable definition digest.` }, `${playbookNextAction[1]} recorded under a fixed independent identity.`)}>{playbookNextAction[1]}</button>}</div>}</section><section className="panel response-playbook-editor"><div className="panel-heading"><div><span className="eyebrow">Strict JSON authoring</span><h2>Playbook editor</h2></div><span className="digest">DRAFT ONLY</span></div><p>Authoring creates an inert signed draft. Submission, independent review, and activation are separate transitions; every live step still requires a per-execution approval.</p><textarea aria-label="Response playbook JSON" spellCheck={false} value={editor} onChange={(event) => setEditor(event.target.value)} /><button disabled={busy || editor.trim().length < 3} onClick={() => void createDraft()}>Create signed draft</button></section></div>}
  </section>;
}

function ReportsWorkspace() {
  const { snapshot, state, message, refresh } = usePlatformSnapshot();
  const release = snapshot?.reports.release;
  const evaluation = snapshot?.reports.evaluation;
  const verifiedModules = snapshot?.modules.filter((item) => item.status === "verified").length ?? 0;
  const passingCriteria = release?.criteria?.filter((item) => item.passed).length ?? 0;

  function downloadSnapshot() {
    if (!snapshot) return;
    const blob = new Blob([JSON.stringify(snapshot, null, 2)], { type: "application/json" });
    const href = URL.createObjectURL(blob);
    const link = document.createElement("a");
    link.href = href;
    link.download = `agentsec-platform-snapshot-${new Date(snapshot.checked_at).toISOString().slice(0, 10)}.json`;
    link.click();
    URL.revokeObjectURL(href);
  }

  return <section className="view-stack platform-view reports-view">
    <div className="view-intro"><span className="eyebrow">Auditable product evidence · Evidence-bound reporting</span><h2>Release reports without presentation-only numbers.</h2><p>Release claims come from committed machine-readable records, never dashboard estimates. This workspace renders the fixed release audit, hash-bound evaluation manifest, and approved module catalog through one BFF route; unavailable sources remain explicit gaps.</p></div>
    <div className="platform-metrics">
      <MetricCard label="Release criteria" value={release?.criteria ? `${passingCriteria}/${release.criteria.length}` : "—"} note="Committed audit outcomes" tone={release?.all_passed ? "good" : "attention"} />
      <MetricCard label="Regression tests" value={release?.discovered_tests != null ? String(release.discovered_tests) : "—"} note="Recorded by release audit" />
      <MetricCard label="Evaluation artifacts" value={evaluation?.artifacts ? String(evaluation.artifacts.length) : "—"} note="Manifest-bound records" />
      <MetricCard label="Verified modules" value={snapshot ? `${verifiedModules}/24` : "—"} note="Approved scope only" tone={verifiedModules === 24 ? "good" : "attention"} />
    </div>
    <section className="panel platform-toolbar"><div role="status" aria-live="polite"><StatusMark tone={state === "offline" ? "danger" : state === "loading" ? "warning" : "healthy"} /><span><strong>{message}</strong><small>{evaluation?.manifest_digest ? `Manifest ${evaluation.manifest_digest}` : "No report digest is being inferred."}</small></span></div><button onClick={() => void refresh()} disabled={state === "loading"}>Refresh evidence</button><button className="secondary" onClick={downloadSnapshot} disabled={!snapshot}>Download verified snapshot</button></section>
    {state === "offline" && <section className="panel platform-empty">The report snapshot is offline. No static release status, benchmark, module count, or report hash is displayed.</section>}
    {snapshot && <div className="reports-layout">
      <section className="panel release-report"><div className="panel-heading"><div><span className="eyebrow">Release audit</span><h2>{release?.scope ?? "Report unavailable"}</h2></div><span className={`release-verdict ${release?.all_passed ? "pass" : "unavailable"}`}>{release?.all_passed ? "PASS" : "UNAVAILABLE"}</span></div>
        {release?.state === "available" ? <><dl className="report-facts"><div><dt>Dataset</dt><dd>{release.dataset_version}</dd></div><div><dt>Schema</dt><dd>{release.schema_version}</dd></div><div><dt>Production ready</dt><dd>{release.production_ready ? "yes" : "no — research PoC"}</dd></div><div><dt>Report SHA-256</dt><dd><code>{release.sha256}</code></dd></div></dl><div className="release-criteria">{release.criteria?.map((item) => <article key={item.id}><StatusMark tone={item.passed ? "healthy" : "danger"} /><span><strong>{readable(item.id)}</strong><small>{item.passed ? "verified" : "failed"}</small></span></article>)}</div>{release.production_deferred?.length ? <div className="production-boundary"><span className="eyebrow">Explicitly deferred production work · Production is deliberately deferred</span><ul>{release.production_deferred.map((item) => <li key={item}>{item}</li>)}</ul></div> : null}</> : <div className="platform-empty small">The committed release report is unavailable.</div>}
      </section>
      <section className="panel artifact-report"><div className="panel-heading"><div><span className="eyebrow">Evaluation manifest</span><h2>Evidence artifacts · Artifact manifest</h2></div><span className="digest">{evaluation?.artifacts?.length ?? 0} HASHED</span></div>{evaluation?.artifacts?.length ? <div className="artifact-table-wrap table-scroll"><table><caption className="sr-only">Committed evaluation artifacts and their integrity digests</caption><thead><tr><th scope="col">ARTIFACT</th><th scope="col">RECORD DIGEST</th><th scope="col">FILE SHA-256</th></tr></thead><tbody>{evaluation.artifacts.map((item) => <tr key={item.path}><th scope="row"><strong>{item.path.split("/").pop()}</strong><small>{item.path}</small></th><td><code>{item.record_digest}</code></td><td><code>{item.sha256}</code></td></tr>)}</tbody></table></div> : <div className="platform-empty small">No manifest-bound evaluation artifacts are available.</div>}</section>
    </div>}
    {snapshot && <section className="panel module-report"><div className="panel-heading"><div><span className="eyebrow">Approved delivery scope</span><h2>24-module completion ledger</h2></div><span className="digest">{verifiedModules}/24 VERIFIED</span></div><div className="module-report-grid">{snapshot.modules.map((item) => <article key={item.id}><span className={`module-state ${item.status}`}>{readable(item.status)}</span><strong>{item.id} · {item.name}</strong><small>{item.acceptance_record ?? "acceptance record pending"}</small></article>)}</div></section>}
  </section>;
}

function AdministrationWorkspace() {
  const { snapshot, state, message, refresh } = usePlatformSnapshot();
  const available = snapshot?.services.filter((item) => item.state === "available").length ?? 0;
  const administration = snapshot?.administration.state === "available" ? snapshot.administration : null;
  const assurance = administration?.assurance;

  return <section className="view-stack platform-view administration-view">
    <div className="view-intro"><span className="eyebrow">Module 24 · Administration, platform security & audit</span><h2>Prove each administrative control—and keep every production boundary visible.</h2><p aria-label="Human identity is explicitly not established here">This read-only workspace renders tenant policy, RBAC inventory, access review, workload identity, managed-key metadata, immutable audit checkpoints, SLOs, recovery drills, and supply-chain attestations from the live administration service. Bearer remains server-side and human identity is explicitly not established here: the included signed-assertion verifier is a local test adapter, not enterprise federation.</p></div>
    <div className="platform-metrics">
      <MetricCard label="Tenant policy" value={administration ? `v${administration.tenant.policy_version}` : "—"} note={administration ? administration.tenant.residency_region : "Live policy unavailable"} tone={administration ? "good" : "attention"} />
      <MetricCard label="Enabled identities" value={administration ? `${administration.identity.enabled}/${administration.identity.configured}` : "—"} note={`${administration?.identity.access_reviews ?? 0} independent reviews`} />
      <MetricCard label="Active keys" value={administration ? `${administration.keys.active}/${administration.keys.configured}` : "—"} note="External references only" tone={administration?.keys.active ? "good" : "attention"} />
      <MetricCard label="Audit chain" value={assurance ? (assurance.audit_valid ? "VERIFIED" : "FAILED") : "—"} note={assurance ? `${assurance.audit_entries} append-only entries` : "No audit receipt"} tone={assurance?.audit_valid ? "good" : "attention"} />
    </div>
    <section className="panel platform-toolbar" role="status" aria-live="polite"><div><StatusMark tone={state === "offline" ? "danger" : state === "loading" ? "warning" : "healthy"} /><span><strong>{message}</strong><small>Only bounded metadata, counts, pass states, and digests reach the browser; credentials and key references are excluded.</small></span></div><button onClick={() => void refresh()} disabled={state === "loading"}>Refresh assurance</button></section>
    {state === "offline" && <section className="panel platform-empty">The platform snapshot is unavailable. No service, source, model, identity, or report health is fabricated. No fallback service status is shown.</section>}
    {snapshot && <>
      <section className="bff-boundary bff-trust-receipt" aria-label="BFF authentication boundary"><article className="panel"><span className="eyebrow">Authenticated BFF trust receipt</span><strong>{snapshot.bff.upstream_authenticated ? "SERVER-HELD" : "UNAVAILABLE"}</strong><p>{readable(snapshot.bff.upstream_authentication)} · {readable(snapshot.bff.network_scope)}</p><small>Browser service auth exposed: {snapshot.bff.browser_service_auth_exposed ? "yes" : "no"}</small></article><article className="panel warning"><span className="eyebrow">Human identity assurance</span><strong>{snapshot.bff.human_identity_verified ? "VERIFIED" : "NOT VERIFIED"}</strong><p>{readable(snapshot.bff.human_identity_boundary)}</p><small>Local service roles prove workflow separation, not individual human identity.</small></article></section>
      {administration ? <>
        <div className="administration-control-grid">
          <section className="panel administration-control"><div className="panel-heading"><div><span className="eyebrow">Tenant policy</span><h2>{administration.tenant.display_name}</h2></div><span className="signed-badge">{readable(administration.tenant.status)}</span></div><dl><div><dt>Tenant</dt><dd>{administration.tenant.tenant_id}</dd></div><div><dt>Residency policy</dt><dd>{administration.tenant.residency_region}</dd></div><div><dt>Allowed processing</dt><dd>{administration.tenant.allowed_processing_regions.join(", ")}</dd></div><div><dt>Record retention</dt><dd>{administration.tenant.retention_days} days</dd></div><div><dt>Evidence retention</dt><dd>{administration.tenant.evidence_retention_days} days</dd></div><div><dt>Legal hold</dt><dd>{administration.tenant.legal_hold ? "active" : "inactive"}</dd></div><div><dt>Encryption policy</dt><dd>{administration.tenant.encryption_required ? "required" : "not required"}</dd></div><div><dt>Policy digest</dt><dd><code>{administration.tenant.record_sha256}</code></dd></div></dl></section>
          <section className="panel administration-control"><div className="panel-heading"><div><span className="eyebrow">Identity, RBAC & MFA</span><h2>Provisioned human access</h2></div><span className="digest">{administration.identity.access_reviews} REVIEWS</span></div><dl><div><dt>Configured</dt><dd>{administration.identity.configured}</dd></div><div><dt>Enabled</dt><dd>{administration.identity.enabled}</dd></div><div><dt>Assertion adapter</dt><dd>{administration.identity.local_adapter ? "local signed test adapter" : "unavailable"}</dd></div><div><dt>External IdP</dt><dd>{administration.identity.external_idp_federated ? "verified" : "NOT VERIFIED"}</dd></div></dl><div className="administration-role-list" aria-label="RBAC role counts">{Object.entries(administration.identity.role_counts).map(([role, count]) => <span key={role}><b>{count}</b>{readable(role)}</span>)}</div><p>High-impact mutations require fresh MFA/step-up, optimistic versions, and independent approval where separation of duty applies.</p></section>
          <section className="panel administration-control"><div className="panel-heading"><div><span className="eyebrow">Workload identity & key lifecycle</span><h2>References, fingerprints, rotation</h2></div><span className="digest">NO MATERIAL</span></div><dl><div><dt>Workloads</dt><dd>{administration.workload_identity.configured}</dd></div><div><dt>Revoked</dt><dd>{administration.workload_identity.revoked}</dd></div><div><dt>Managed keys</dt><dd>{administration.keys.configured}</dd></div><div><dt>Active keys</dt><dd>{administration.keys.active}</dd></div><div><dt>External custody</dt><dd>{administration.keys.external_custody_verified ? "verified" : "NOT VERIFIED"}</dd></div></dl><p>Raw credentials and cryptographic key material are never stored or returned. Activation is a two-person state transition; production KMS/HSM custody remains a deployment integration.</p></section>
          <section className="panel administration-control"><div className="panel-heading"><div><span className="eyebrow">Immutable admin audit</span><h2>Hash chain & signed checkpoint</h2></div><span className={`assurance-state ${assurance?.audit_valid ? "passed" : "failed"}`}>{assurance?.audit_valid ? "VERIFIED" : "FAILED"}</span></div><dl><div><dt>Entries</dt><dd>{assurance?.audit_entries ?? 0}</dd></div><div><dt>Checkpoint sequence</dt><dd>{administration.audit_checkpoint?.sequence ?? "—"}</dd></div><div><dt>Signature adapter</dt><dd>{administration.audit_checkpoint ? readable(administration.audit_checkpoint.signature_algorithm) : "unavailable"}</dd></div><div><dt>Chain head</dt><dd><code>{administration.audit_checkpoint?.current_sha256 ?? "no signed checkpoint"}</code></dd></div></dl><p>SQLite triggers reject UPDATE and DELETE. A signed checkpoint detects tail deletion; external transparency anchoring is not claimed.</p></section>
        </div>
        <section className="administration-assurance-grid" aria-label="Operational assurance evidence">
          <article className="panel"><span className="eyebrow">Service level objective</span><strong>{administration.latest_slo?.passed ? "PASS" : "NO PASS"}</strong><h3>{administration.latest_slo?.name ?? "No measurement"}</h3><dl><div><dt>Observed</dt><dd>{administration.latest_slo?.observed ?? "—"}</dd></div><div><dt>Error budget</dt><dd>{administration.latest_slo ? percentage(administration.latest_slo.error_budget_remaining) : "—"}</dd></div></dl></article>
          <article className="panel"><span className="eyebrow">Backup & recovery drill</span><strong>{administration.latest_recovery?.passed ? "PASS" : "NO PASS"}</strong><h3>{administration.latest_recovery?.integrity_verified ? "Checkpoint integrity verified" : "Integrity unverified"}</h3><dl><div><dt>Observed RPO</dt><dd>{administration.latest_recovery ? `${administration.latest_recovery.observed_rpo_minutes} min` : "—"}</dd></div><div><dt>Observed RTO</dt><dd>{administration.latest_recovery ? `${administration.latest_recovery.observed_rto_minutes} min` : "—"}</dd></div></dl></article>
          <article className="panel"><span className="eyebrow">Supply-chain attestation</span><strong>{administration.latest_supply_chain?.passed ? "PASS" : "NO PASS"}</strong><h3>{administration.latest_supply_chain?.release_id ?? "No attestation"}</h3><dl><div><dt>Signature</dt><dd>{administration.latest_supply_chain?.signature_verified ? "verified" : "unverified"}</dd></div><div><dt>SBOM digest</dt><dd><code>{administration.latest_supply_chain?.sbom_sha256 ?? "—"}</code></dd></div><div><dt>Provenance</dt><dd><code>{administration.latest_supply_chain?.provenance_sha256 ?? "—"}</code></dd></div></dl></article>
        </section>
        <section className="panel administration-boundary"><div><span className="eyebrow">Honest production boundary</span><h2>{assurance?.production_ready ? "Production assurance verified" : "Reference controls verified; production assurance is not."}</h2><p>External IdP federation: <b>{administration.identity.external_idp_federated ? "verified" : "not verified"}</b> · external KMS/HSM custody: <b>{administration.keys.external_custody_verified ? "verified" : "not verified"}</b> · geographic placement enforcement: <b>{assurance?.geographic_residency_verified ? "verified" : "not verified"}</b> · distributed HA: <b>{assurance?.distributed_ha_verified ? "verified" : "not verified"}</b>. These are explicit deployment obligations, never inferred from policy metadata.</p>{assurance?.boundaries.length ? <ul>{assurance.boundaries.map((item) => <li key={item}>{item}</li>)}</ul> : null}</div><span className="signed-badge">PRODUCTION READY: NO</span></section>
      </> : <section className="panel platform-empty">The administration service is not configured. No tenant, identity, key, audit, SLO, recovery, or supply-chain assurance is inferred.</section>}
      <section className="panel service-health platform-services"><div className="panel-heading"><div><span className="eyebrow">Real service metrics</span><h2>Product service matrix</h2></div><span className="digest">{available} AVAILABLE</span></div><div className="service-health-grid">{snapshot.services.map((service) => <article key={service.service_id} className={service.state}><header><StatusMark tone={service.state === "available" ? "healthy" : "danger"} /><span><strong>{service.name}</strong><code>{service.service_id}</code></span><b>{service.state}</b></header>{Object.keys(service.metrics).length ? <dl>{Object.entries(service.metrics).map(([key, value]) => <div key={key}><dt>{readable(key)}</dt><dd>{String(value)}</dd></div>)}</dl> : <p>{service.error_code ? readable(service.error_code) : "No bounded metrics returned."}</p>}</article>)}</div></section>
    </>}
  </section>;
}

function validationRequestId(label: string) {
  return `req_${label}${crypto.randomUUID().replaceAll("-", "").slice(0, 32)}`;
}

function ValidationLab() {
  const [catalog, setCatalog] = useState<SimulationCatalog | null>(null);
  const [scenarioId, setScenarioId] = useState("");
  const [variant, setVariant] = useState("plain");
  const [mode, setMode] = useState("comparison");
  const [run, setRun] = useState<SimulationRun | null>(null);
  const [state, setState] = useState<"loading" | "ready" | "running" | "error">("loading");
  const [message, setMessage] = useState("Loading the authenticated validation corpus…");

  const refresh = useCallback(async () => {
    try {
      const [catalogResponse, runsResponse] = await Promise.all([
        fetch(`${LIVE_API}/api/simulation/catalog`, { cache: "no-store" }),
        fetch(`${LIVE_API}/api/simulation/runs`, { cache: "no-store" }),
      ]);
      if (!catalogResponse.ok || !runsResponse.ok) throw new Error("The validation lab service is unavailable.");
      const nextCatalog = await catalogResponse.json() as SimulationCatalog;
      const runPage = await runsResponse.json() as { runs: SimulationRun[] };
      if (!Array.isArray(nextCatalog.scenarios?.scenarios) || !Array.isArray(nextCatalog.variants)) throw new Error("The validation catalog contract is invalid.");
      setCatalog(nextCatalog);
      setScenarioId((current) => nextCatalog.scenarios.scenarios.some((item) => item.scenario_id === current)
        ? current
        : (nextCatalog.scenarios.scenarios.find((item) => item.scenario_id === "sim_multistage_rag_exfiltration") ?? nextCatalog.scenarios.scenarios[0])?.scenario_id ?? "");
      if (runPage.runs?.length) setRun((current) => current ?? runPage.runs[0]);
      setMessage(`${nextCatalog.health.scenarios} versioned scenarios · ${nextCatalog.health.runs} signed runs · audit ${nextCatalog.health.audit_valid ? "verified" : "failed"}.`);
      setState("ready");
    } catch (error) {
      setMessage(error instanceof Error ? error.message : "The validation lab is unavailable.");
      setState("error");
    }
  }, []);

  useEffect(() => {
    const timer = window.setTimeout(() => { void refresh(); }, 0);
    return () => window.clearTimeout(timer);
  }, [refresh]);

  const scenario = useMemo(
    () => catalog?.scenarios.scenarios.find((item) => item.scenario_id === scenarioId) ?? null,
    [catalog, scenarioId],
  );
  const profile = catalog?.variants.find((item) => item.variant === variant) ?? null;

  async function execute() {
    if (!scenario || state === "running") return;
    setState("running");
    setMessage("Materializing fixed metadata transformations and running the local protected/control sandbox…");
    try {
      let target = scenario;
      if (variant !== scenario.variant) {
        const mutationResponse = await fetch(`${LIVE_API}/api/simulation/mutations`, {
          method: "POST",
          headers: { "Content-Type": "application/json" },
          body: JSON.stringify({ base_scenario_id: scenario.scenario_id, base_version: scenario.version, variant, name: null }),
        });
        if (!mutationResponse.ok) throw new Error("The constrained scenario mutation was rejected.");
        target = await mutationResponse.json() as SimulationScenario;
      }
      const response = await fetch(`${LIVE_API}/api/simulation/runs`, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ request_id: validationRequestId("run"), scenario_id: target.scenario_id, version: target.version, mode }),
      });
      if (!response.ok) throw new Error("The local validation replay failed.");
      const result = await response.json() as SimulationRun;
      setRun(result);
      setMessage(`${result.passed ? "All expectations passed" : "Ground-truth mismatch"} · ${result.results.length} mode${result.results.length === 1 ? "" : "s"} · ${result.sandbox.completed_steps} isolated step executions.`);
      setState("ready");
      void refresh();
    } catch (error) {
      setMessage(error instanceof Error ? error.message : "The validation replay failed.");
      setState("error");
    }
  }

  async function replay() {
    if (!run || state === "running") return;
    setState("running");
    setMessage("Replaying the signed scenario digest in the same bounded sandbox…");
    try {
      const response = await fetch(`${LIVE_API}/api/simulation/runs/${encodeURIComponent(run.run_id)}/replay`, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ request_id: validationRequestId("replay") }),
      });
      if (!response.ok) throw new Error("The digest-bound replay was rejected.");
      const result = await response.json() as SimulationRun;
      setRun(result);
      setMessage(`Replay ${result.passed ? "passed" : "failed"} · bound to ${result.replay_of}.`);
      setState("ready");
      void refresh();
    } catch (error) {
      setMessage(error instanceof Error ? error.message : "The digest-bound replay failed.");
      setState("error");
    }
  }

  return <section className="view-stack validation-lab-view">
    <div className="view-intro"><span className="eyebrow">Module 22 · Adversarial simulation and validation lab</span><h2>Build metadata-only AI attack variants. Prove detection and containment against explicit ground truth.</h2><p>This lab never accepts a raw prompt, document body, tool argument, shell command, or arbitrary destination. Fixed multilingual and obfuscation profiles operate on normalized security signals, then replay only through local mock enterprise effects.</p></div>
    <div className="validation-lab-metrics">
      <MetricCard label="Scenarios" value={catalog ? String(catalog.health.scenarios) : "—"} note={catalog ? `${catalog.health.trusted_scenarios} trusted ground truth` : "Live catalog required"} />
      <MetricCard label="Signed runs" value={catalog ? String(catalog.health.runs) : "—"} note={catalog ? `${catalog.health.passed_runs} passed · ${catalog.health.failed_runs} failed` : "No fixed fallback"} tone={catalog?.health.failed_runs ? "attention" : "good"} />
      <MetricCard label="Audit ledger" value={catalog ? (catalog.health.audit_valid ? "VERIFIED" : "FAILED") : "—"} note="Hash-chained mutations and runs" tone={catalog?.health.audit_valid ? "good" : "attention"} />
      <MetricCard label="Sandbox" value={catalog ? readable(catalog.health.sandbox) : "—"} note="Network, filesystem and shell disabled" tone="good" />
    </div>
    <section className="panel validation-lab-toolbar" role="status" aria-live="polite"><div><StatusMark tone={state === "error" ? "danger" : state === "running" || state === "loading" ? "warning" : "healthy"} /><span><strong>{state === "running" ? "Validation running" : state === "error" ? "Validation lab unavailable" : "Validation lab ready"}</strong><small>{message}</small></span></div><button className="secondary" onClick={() => void refresh()} disabled={state === "running"}>Refresh</button></section>
    {catalog && scenario ? <>
      <div className="validation-builder-grid">
        <section className="panel validation-builder"><div className="panel-heading"><div><span className="eyebrow">Constrained scenario builder</span><h2>Versioned metadata contract</h2></div><span className="signed-badge">NO RAW CONTENT</span></div><div className="validation-builder-fields">
          <label><span>Base scenario</span><select value={scenarioId} onChange={(event) => { const next = catalog.scenarios.scenarios.find((item) => item.scenario_id === event.target.value); setScenarioId(event.target.value); setVariant(next?.variant ?? "plain"); }}>{catalog.scenarios.scenarios.map((item) => <option value={item.scenario_id} key={`${item.scenario_id}:${item.version}`}>{item.name} · {item.version}</option>)}</select></label>
          <label><span>Language / obfuscation profile</span><select value={variant} onChange={(event) => setVariant(event.target.value)}><option value="plain">Plain normalized signal</option>{catalog.variants.filter((item) => item.variant !== "plain").map((item) => <option key={item.variant} value={item.variant}>{readable(item.variant)} · {item.locale}</option>)}</select></label>
          <label><span>Replay mode</span><select value={mode} onChange={(event) => setMode(event.target.value)}><option value="comparison">Protected + control comparison</option><option value="protected">Protected only</option><option value="control">Unprotected control only</option></select></label>
        </div>{profile && <div className="validation-profile"><strong>Normalization boundary</strong><p>{profile.qualification_boundary}</p><span>{profile.transformations.length ? profile.transformations.map(readable).join(" · ") : "No transformation"}</span><b>{profile.raw_content_retained ? "RAW CONTENT RETAINED" : "RAW CONTENT NOT RETAINED"}</b></div>}<div className="validation-builder-actions"><button onClick={() => void execute()} disabled={state === "running"}>{state === "running" ? "Running…" : "Build and replay"}</button><button className="secondary" onClick={() => void replay()} disabled={!run || state === "running"}>Replay signed run</button></div></section>
        <section className="panel validation-scenario"><div className="panel-heading"><div><span className="eyebrow">Selected ground truth</span><h2>{scenario.name}</h2></div><span className={`validation-trust ${scenario.trusted_ground_truth ? "trusted" : "untrusted"}`}>{scenario.trusted_ground_truth ? "TRUSTED" : "UNREVIEWED"}</span></div><p>{scenario.description}</p><div className="validation-mapping-row">{scenario.framework_mappings.map((item) => <code key={item}>{item}</code>)}</div><ol>{scenario.steps.map((step) => <li key={step.step_id}><header><span>{String(step.sequence).padStart(2, "0")}</span><div><strong>{step.title}</strong><small>{readable(step.attack_stage)} · {step.event.operation}</small></div></header><dl><div><dt>Expected alerts</dt><dd>{step.ground_truth.expected_alert_types.length ? step.ground_truth.expected_alert_types.map(readable).join(" · ") : "None"}</dd></div><div><dt>Expected action</dt><dd>{readable(step.ground_truth.expected_protected_action)}</dd></div><div><dt>Forbidden effect</dt><dd>{step.ground_truth.forbidden_completed_operations.join(" · ") || "None"}</dd></div><div><dt>Stimulus digest</dt><dd><code>{step.stimulus_sha256}</code></dd></div></dl></li>)}</ol><footer><span>Scenario record</span><code>{scenario.record_sha256}</code></footer></section>
      </div>
      {run ? <section className={`panel validation-run ${run.passed ? "passed" : "failed"}`}><div className="panel-heading"><div><span className="eyebrow">Evidence-visible replay result</span><h2>{run.passed ? "Ground truth satisfied" : "Ground-truth mismatch"}</h2></div><span className="digest">{readable(run.mode)} · {run.variant}</span></div><div className="validation-run-summary"><dl><div><dt>Run</dt><dd><code>{run.run_id}</code></dd></div><div><dt>Scenario digest</dt><dd><code>{run.scenario_sha256}</code></dd></div><div><dt>Ground truth</dt><dd>{run.trusted_ground_truth ? "Trusted built-in or derived" : "Imported and unreviewed"}</dd></div><div><dt>Replay of</dt><dd>{run.replay_of ? <code>{run.replay_of}</code> : "Original execution"}</dd></div></dl><article><strong>Sandbox receipt</strong><span>{run.sandbox.engine}</span><p>Local only: {run.sandbox.local_only ? "yes" : "no"} · Network: {run.sandbox.network_enabled ? "enabled" : "disabled"} · Filesystem: {run.sandbox.filesystem_enabled ? "enabled" : "disabled"} · Shell: {run.sandbox.shell_enabled ? "enabled" : "disabled"}</p><small>{run.sandbox.completed_steps} steps · {run.sandbox.observed_effects} mock effects</small><code>{run.sandbox.receipt_sha256}</code></article></div><div className="validation-mode-grid">{run.results.map((result) => <article className={result.expectation_met ? "passed" : "failed"} key={result.protected ? "protected" : "control"}><header><div><span>{result.protected ? "PROTECTED" : "CONTROL"}</span><strong>{result.expectation_met ? "Expectation met" : "Mismatch"}</strong></div><b>{result.detected_alert_count} alerts · {result.forbidden_effect_count} forbidden effects</b></header>{result.steps.map((step) => <section key={step.step_id}><div className="validation-step-head"><span>{String(step.sequence).padStart(2, "0")}</span><strong>{step.step_id}</strong><b>{step.expectation_met ? "PASS" : "FAIL"}</b></div><div className="validation-observation-grid"><div><span>Expected alerts</span><p>{step.expected_alert_types.map(readable).join(" · ") || "None"}</p></div><div><span>Observed alerts</span><p>{step.observed_alert_types.map(readable).join(" · ") || "None"}</p></div><div><span>Expected / observed action</span><p>{readable(step.expected_action)} → {readable(step.observed_action)}</p></div><div><span>Effect outcome</span><p>{step.effect_completed ? "Mock effect completed" : "Effect blocked"}{step.forbidden_effects_completed.length ? ` · forbidden: ${step.forbidden_effects_completed.join(", ")}` : ""}</p></div></div><div className="validation-evidence-links">{step.alert_ids.map((id) => <code key={id}>{id}</code>)}{step.finding_ids.map((id) => <code key={id}>{id}</code>)}</div>{step.reasons.length > 0 && <p className="validation-reasons">{step.reasons.join(" · ")}</p>}</section>)}</article>)}</div><footer className="validation-run-proof"><span>Signed run record</span><code>{run.record_sha256}</code><span>{new Date(run.completed_at).toLocaleString()}</span></footer></section> : <section className="panel validation-empty">Choose an allowlisted scenario, fixed variant, and replay mode. The system will show expected versus observed alerts, decisions, effects, finding IDs, reasons, and signed sandbox evidence here.</section>}
    </> : <section className="panel validation-empty">No live validation catalog is available. This screen does not fabricate scenarios, evidence, run status, or safety receipts.</section>}
  </section>;
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
  const [incidentDetails, setIncidentDetails] = useState<Record<string, IncidentDetail | null>>({});
  const [detailStates, setDetailStates] = useState<Record<string, DetailLoadState>>({});

  const active = alerts.find((alert) => alert.id === activeId) ?? alerts[0] ?? null;
  const activeFinding = active?.finding ?? null;
  const hasEmbeddedDetail = active?.detail?.detail_availability === "complete";
  const activeDetail = active
    ? hasEmbeddedDetail
      ? active.detail ?? null
      : incidentDetails[active.finding] ?? active.detail ?? null
    : null;
  const activeDetailState: DetailLoadState = active
    ? hasEmbeddedDetail
      ? "complete"
      : detailStates[active.finding] ?? (activeDetail?.detail_availability === "summary_only" ? "summary_only" : "loading")
    : "unavailable";

  const refreshAlerts = useCallback(async () => {
    try {
      const response = await fetch(`${LIVE_API}/api/alerts`, { cache: "no-store" });
      if (!response.ok) throw new Error("The local bridge could not read live alerts.");
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

  useEffect(() => {
    if (!activeFinding || hasEmbeddedDetail) return;
    let cancelled = false;
    void fetch(`${LIVE_API}/api/alerts/${encodeURIComponent(activeFinding)}`, { cache: "no-store" })
      .then(async (response) => {
        if (response.status === 404) return { detail_availability: "unavailable" as const, incident: null };
        if (!response.ok) throw new Error("Incident detail request failed");
        return response.json() as Promise<IncidentPayload>;
      })
      .then((payload) => {
        if (cancelled) return;
        if (payload.detail_availability === "unavailable") {
          setDetailStates((current) => ({ ...current, [activeFinding]: "unavailable" }));
          return;
        }
        setIncidentDetails((current) => ({ ...current, [activeFinding]: payload.incident ?? null }));
        setDetailStates((current) => ({ ...current, [activeFinding]: payload.detail_availability }));
      })
      .catch(() => {
        if (!cancelled) setDetailStates((current) => ({ ...current, [activeFinding]: "failed" }));
      });
    return () => { cancelled = true; };
  }, [activeFinding, hasEmbeddedDetail]);

  async function transitionIncident(action: string, reason: string) {
    if (!active) return;
    const response = await fetch(`${LIVE_API}/api/alerts/${encodeURIComponent(active.finding)}/transition`, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ action, actor: "analyst://local-demo", reason }),
    });
    if (!response.ok) throw new Error("Incident transition failed");
    const payload = (await response.json()) as IncidentPayload;
    if (!payload.incident) throw new Error("Transition response omitted the incident record");
    setIncidentDetails((current) => ({ ...current, [active.finding]: payload.incident }));
    setDetailStates((current) => ({ ...current, [active.finding]: payload.detail_availability }));
    setAlerts((current) => current.map((item) => item.finding === active.finding ? { ...item, state: payload.incident?.summary.status ?? item.state, detail: payload.incident } : item));
  }

  async function runSimulation() {
    if (simulation === "running") return;
    setSimulation("running");
    setSimulationNote("Submitting an allowlisted metadata event through the live service…");
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
      <a className="skip-link" href="#main-content">Skip to main content</a>
      <aside className="sidebar">
        <div className="brand"><span className="brand-mark">AS</span><div><strong>AgentSec</strong><small>CONTROL ROOM</small></div></div>
        <nav aria-label="Primary navigation">
          {navItems.map((item) => (
            <button key={item.label} className={view === item.label ? "nav-item active" : "nav-item"} aria-current={view === item.label ? "page" : undefined} title={item.label} onClick={() => setView(item.label)}>
              <span>{item.short}</span>{item.label}
              {item.label === "Incidents" && alerts.length > 0 && <b>{alerts.length}</b>}
            </button>
          ))}
        </nav>
        <div className="sidebar-bottom">
          <div className="protection-card"><div><StatusMark /><span>Enforcement</span></div><strong>Protected</strong><small>deterministic-v1</small></div>
          <div className="operator" aria-label="Local demonstration operator; human identity is not verified"><span>VA</span><div><strong>V. Analyst</strong><small>Local fixed operator</small></div><b aria-hidden="true">LOCAL</b></div>
        </div>
      </aside>

      <main id="main-content" tabIndex={-1}>
        <header className="topbar">
          <div><span className="eyebrow">Tenant-lab / authorization boundary</span><h1>{view === "Overview" ? "Authorization control room" : view}</h1></div>
          <div className="topbar-actions">
            <div className="system-health" role="status" aria-live="polite"><StatusMark tone={liveState === "offline" ? "danger" : liveState === "connecting" ? "warning" : "healthy"} /><span><b>{liveState === "connected" ? "AgentSec live" : liveState === "connecting" ? "Connecting to service" : "Live bridge offline"}</b><small>{liveState === "connected" ? `Synced ${lastSynced}` : liveError || "Start the local bridge"}</small></span></div>
            <label className="forge-select">
              <span className="sr-only">Live event preset</span>
              <select value={preset} onChange={(event) => setPreset(event.target.value)} disabled={simulation === "running"}>
                {forgePresets.map(([value, label]) => <option value={value} key={value}>{label}</option>)}
              </select>
            </label>
            <button className="simulation-button" onClick={runSimulation} disabled={simulation === "running"}>
              <span aria-hidden="true">▶</span>{simulation === "running" ? "Sending event…" : "Forge live event"}
            </button>
          </div>
        </header>

        <div className="content">
          {view === "Overview" && <Overview alerts={alerts} active={active} activeDetail={activeDetail} detailState={activeDetailState} onSelect={(alert) => setActiveId(alert.id)} onTransition={transitionIncident} liveState={liveState} ledgerVerified={ledgerVerified} />}
          {view === "Incidents" && <CorrelationWorkbench />}
          {view === "Cases" && <CaseWorkspace />}
          {view === "Escalations" && <EscalationWorkspace />}
          {view === "Response" && <ResponseWorkspace />}
          {view === "Inventory" && <Inventory />}
          {view === "Security Graph" && <SecurityGraph />}
          {view === "Posture" && <Posture />}
          {view === "Threat Hunting" && <ThreatHunting />}
          {view === "Risk Analytics" && <RiskAnalytics />}
          {view === "Rule Studio" && <RuleStudio />}
          {view === "Policies" && <Policies />}
          {view === "Validation Lab" && <ValidationLab />}
          {view === "Evaluations" && <Evaluations />}
          {view === "Integrations" && <Integrations />}
          {view === "Reports" && <ReportsWorkspace />}
          {view === "Administration" && <AdministrationWorkspace />}
        </div>
      </main>

      <div className={simulation === "idle" ? "toast" : "toast visible"} role="status" aria-live="polite">
        <span className={simulation === "done" ? "toast-icon done" : simulation === "error" ? "toast-icon error" : "toast-icon"}>{simulation === "done" ? "✓" : simulation === "error" ? "!" : "•••"}</span>
        <div><strong>{simulation === "done" ? "Live decision received" : simulation === "error" ? "Live request failed" : "Forging metadata event"}</strong><small>{simulationNote}</small></div>
      </div>
    </div>
  );
}
