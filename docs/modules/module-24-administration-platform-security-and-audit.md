# Module 24 — Administration, platform security, and audit

Status: verified after compare → remediate → focused verification → full
regression/security verification → final catalog audit.

## Objective

Provide the governance and operational-assurance plane around AgentSec without
weakening the deterministic security path. An administrator must be able to
define tenant data policy, provision bounded human and workload identities,
rotate external key references, perform independent access review, prove every
administrative mutation, and record SLO, restore, and software-supply-chain
evidence. The product must distinguish implemented reference controls from
unverified production infrastructure.

## Comparison and closed gaps

Before Module 24, individual modules had tenant checks, fixed local roles,
service tokens, hash-chained records, and explicit environment-secret
references. Those controls were intentionally local to each module. The product
did not have one administration domain for:

- the approved six-role human RBAC model;
- provisioned human identity plus signed session assertions;
- issuer, audience, tenant, role-subset, expiry, MFA, and replay validation;
- high-impact step-up and cross-operation separation of duty;
- workload credential rotation and revocation metadata;
- managed-key lifecycle and independent activation;
- independent access certification;
- tenant residency, retention, legal-hold, and encryption policy;
- append-only product administration audit and signed checkpoints;
- objective SLO, backup/restore, and supply-chain assurance records;
- private service reads and a bounded live UI projection; or
- an unambiguous machine-readable production non-claim.

`src/agentsec/administration.py`, the service assembly, schema generator, live
bridge, UI, tests, example policy, and this acceptance record close those gaps
for the single-node reference product.

## Control-plane architecture

```text
signed assertion ----> provisioned identity ----> tenant/role/MFA authorization
                                                     |
             +---------------------------------------+-------------------+
             |                 |                |                       |
       tenant policy     workload identity   managed keys         access review
             |                 |                |                       |
             +-----------------+----------------+-----------------------+
                                       |
                            optimistic durable object store
                                       |
                           append-only administrative audit
                                       |
                              signed chain checkpoint

 SLO measurement ----+
 recovery drill ------+--> recomputed assurance state --> private API
 supply-chain proof --+                                  --> bounded BFF/UI
```

The administration service is deliberately separate from detection,
judgment, notification, and response execution. Its principals cannot rewrite a
finding, relax authorization, manufacture model qualification, approve their
own live response, or bypass any module-specific separation rule.

## Tenant and data-governance policy

`TenantSecurityPolicy` commits:

- tenant identity, display name, and active state;
- residency region and an explicit processing-region allowlist;
- record and evidence retention periods;
- legal-hold state;
- mandatory encryption policy and an external managed-key reference;
- optimistic policy version, updater, timestamp, and canonical digest.

The residency region must be in the processing allowlist, and evidence
retention cannot be shorter than record retention. Configuration is durable and
tamper checked after restart. Policy metadata alone does not prove physical
placement, deletion execution, or encryption by an external key service; those
remain production deployment evidence.

## Human identity, RBAC, MFA, and separation of duty

The approved roles and permissions are:

| Role | Reference authority |
|---|---|
| Viewer | Read administration state. |
| Analyst | Read administration state. |
| Incident commander | Read administration state; response authority stays in Module 19. |
| Policy owner | Read and perform independent access certification. |
| Platform administrator | Manage tenant, identity, workload, key metadata, privacy, and assurance. |
| Security auditor | Read audit and perform independent access certification. |

Every principal binds tenant, actor, session, roles, authentication method,
MFA state, authentication time, expiry, and optional step-up expiry. All
mutations are high impact and require a current MFA/step-up receipt. Tenant
mismatch, expiration, missing permission, or stale step-up fails closed.

`IdentityAssertionVerifier` validates a bounded signed assertion containing
issuer, audience, tenant, subject, session, roles, MFA state, authentication
context, issue/expiry times, and unique assertion ID. The subject must already
be enabled, and asserted roles must be a subset of provisioned roles. Assertion
IDs are stored to reject replay. The HMAC signer is explicitly a local test
adapter; it is not OIDC/SAML federation or an enterprise identity-provider
qualification.

Identity updates use optimistic versions and prevent an administrator from
removing their own last active administration grant. Access review requires a
different reviewer from both the subject and original grantor. Review rationale
is stored only as a SHA-256 commitment, not analyst prose.

## Workload identity and managed keys

Workload records contain an allowlisted `resource:action` scope set, external
credential reference, credential fingerprint, issue/expiry time, rotation and
revocation times, updater, version, and record digest. Rotation must change the
fingerprint; revocation is durable and version checked.

Managed-key records contain an external provider reference and fingerprint,
purpose, rotation deadline, predecessor, state, version, registrar, independent
approver, and digest. A registrar creates a pending key but cannot activate it.
Only a different authorized actor can activate the exact pending version.
Retirement/revocation is allowed only from active state. Rotation must be
scheduled after the update time.

Neither record type accepts or returns a credential secret or cryptographic key
material. The browser projection further removes external references and shows
only counts and assurance flags.

## Immutable administrative audit

Every successful mutation adds an `AdministrationAuditEntry` with a monotonic
sequence, tenant, actor, action, object ID, detail commitment, timestamp,
previous hash, and entry hash. Details are canonicalized and hashed, so access
reasons, configuration bodies, or secrets do not enter the audit stream.

Database triggers reject `UPDATE` and `DELETE` against audit rows. Verification
recomputes sequence continuity, previous hashes, and entry hashes. A checkpoint
commits tenant, sequence, current chain head, creator, time, signature algorithm,
and signature. Verification checks the signature and committed row so both
mutation and tail deletion are detected.

The included `hmac-sha256-poc` checkpoint is deterministic single-node tamper
evidence. Production non-repudiation requires externally custodied signing,
trusted time, replicated immutable retention, and an independent transparency
anchor.

## Operational and supply-chain assurance

The three assurance record families derive pass state from evidence rather than
trusting a caller-supplied verdict:

- An SLO measurement compares the observed value with a versioned objective and
  records remaining error budget.
- A recovery drill verifies backup/source/restored commitments, completion time,
  integrity, and observed-versus-target RPO/RTO.
- A supply-chain attestation binds release, artifact, SBOM, provenance,
  dependency scan, secret scan, and signature evidence, and requires a verifier
  independent of the builder.

Schema validators recompute each `passed` field, so an inconsistent serialized
claim is rejected during ingestion or reload. Health uses the latest objective
measurements, recovery drill, supply-chain attestation, and audit verification.

## API, service assembly, and UI

When `AGENTSEC_ADMIN_DB`, tenant, policy, assertion key, and checkpoint key are
configured, `AuthorizationApplication` assembles the administration plane and
rejects tenant mismatch with other configured product modules. Authenticated
private routes expose:

- `GET /v1/administration` for the complete sanitized core snapshot;
- `GET /v1/administration/health`;
- `GET /v1/administration/audit?limit=...`; and
- `POST /v1/administration/checkpoints` with an exact empty body.

The reference HTTP surface is intentionally read-only apart from checkpoint
creation. Production provisioning mutations need a human-session adapter that
turns verified external IdP sessions into per-request principals; the current
server-side local principal is not presented as a human session.

The fixed loopback BFF adds an eighteenth health probe and a bounded
`administration` projection. It exposes policy metadata, counts, role counts,
assurance values, and digests. It does not expose subjects, emails, credential
or key references, assertion bodies, tokens, secrets, or configuration paths.
The Administration workspace displays live data only and has no fixture
fallback or mutation controls.

## Configuration

```bash
AGENTSEC_ADMIN_DB=/tmp/agentsec-administration.sqlite3
AGENTSEC_ADMIN_TENANT=tenant-lab
AGENTSEC_ADMIN_CONFIG=configs/administration.example.json
AGENTSEC_ADMIN_ASSERTION_ISSUER=https://idp.example.invalid
AGENTSEC_ADMIN_ASSERTION_AUDIENCE=agentsec-administration
AGENTSEC_ADMIN_ASSERTION_KEY=replace-with-at-least-32-random-characters
AGENTSEC_ADMIN_CHECKPOINT_KEY=replace-with-a-different-32-character-key
```

The two keys are mandatory and must be at least 32 characters. They must be
injected at runtime and must differ operationally. The example JSON contains no
secrets. A configuration without the database, keys, or matching tenant fails
startup rather than silently enabling a weaker administration mode.

## Machine-readable production boundary

`AdministrationHealth` structurally fixes these values:

- `local_identity_adapter=true`;
- `external_idp_federated=false`;
- `external_key_custody_verified=false`;
- `geographic_residency_verified=false`;
- `distributed_ha_verified=false`; and
- `production_ready=false`.

The service can be healthy when its reference controls and evidence are valid;
that health must never be interpreted as production authorization. A real
deployment must replace the local adapter with independently verified external
contracts and preserve this distinction in its own release gate.

## Focused verification evidence

The focused tests cover signed-assertion signature/issuer/audience/tenant/role/
MFA/replay validation, high-impact step-up, tenant isolation, optimistic
versions, self-demotion prevention, workload rotation/revocation, scope
validation, two-person key activation, independent access review, hashed review
rationale, record-digest tamper detection, restart durability, append-only audit
triggers, signed checkpoints, SLO/recovery/supply-chain result consistency,
honest health flags, explicit environment keys, exact authenticated HTTP routes,
bounded BFF projection, omitted secret references, UI source/build/render
contracts, and schema generation.

```bash
PYTHONDONTWRITEBYTECODE=1 PYTHONPATH=src python3 -m unittest \
  tests.test_administration tests.test_live_ui_bridge -v
PYTHONDONTWRITEBYTECODE=1 PYTHONPATH=src python3 tools/generate_schemas.py --check
cd ui && npm run lint && npm test
make verify
```

The 10 administration and 21 bridge tests pass, including three separate Python
hash seeds for durable set-order determinism. The UI zero-warning lint,
production build, source contract, and server-render contract pass.

## Honest limitations

- The assertion verifier is not an OIDC/SAML client and does not perform IdP
  discovery, JWKS rotation, device/risk checks, SCIM, or session revocation.
- SQLite is single node. It is not replicated consensus, a managed immutable
  archive, geographically enforced storage, or an HA control plane.
- External credential and key references prove absence of stored secret
  material; they do not prove external custody, rotation execution, access
  policy, deletion, or HSM use.
- Retention/residency/encryption are governed policy metadata until deployment
  adapters return independent enforcement evidence.
- Recovery and SLO records prove the submitted, digest-bound exercise. They do
  not schedule backups, fail traffic over, or establish operational staffing.
- Supply-chain records verify committed scan/signature outcomes. The reference
  service does not build artifacts, issue provenance, host a transparency log,
  or qualify a CI platform.
- Private HTTP mutation APIs are deliberately absent until real per-human
  federation and CSRF/session controls exist.

## Acceptance closure

Module 24 is verified. The full pre-promotion `make verify` gate passed with 391
Python tests, 6 TypeScript SDK tests, 342 generated-schema checks, 12
manifest-bound evaluation records, the 42-case/24-holdout continuous gate,
clean-install reproduction, compilation, secret/dependency scans, release audit,
workflow and recorded-Codex demos, all evaluation modes, and ablation. The
catalog and maturity matrix were then promoted to 24/24. The complete
post-promotion `make verify` gate and `make goal-audit` also pass, so the final
state—not only the pre-promotion implementation—is verified.
