# Security, Dependency, and Modularization Grand Plan

## Scope and Method

This plan is based on:

1. **Deep local repository review** of `Trancendos/prometheus-ai` (current workspace).
2. **Organization-wide baseline audit** across 95 repositories using:
   - `scripts/org-security-audit.mjs`
   - Output: `reports/org-security-audit.md` and `reports/org-security-audit.json`

The org audit is a file-presence baseline (workflows/policies/docs/manifests), intended to quickly identify systemic gaps and prioritization order.

## Current State Summary (Org-Wide)

From `reports/org-security-audit.md`:

- Total repos audited: **95**
- Priority **P0**: **85**
- Priority **P1**: **6**
- Priority **P2**: **3**
- Priority **P3**: **1**
- Missing Dependabot: **76**
- Missing CVE workflow: **85**
- Missing dependency workflow: **85**

Detected stack mix:

- node: 55
- unknown: 22
- python: 5
- ruby: 4
- container: 2
- node+container: 2
- python+container: 3
- go: 1
- python+rust+container: 1

## Key Gaps Identified

### 1) Security and CVE management gaps

- Most repos do not have a consistent CVE scanning workflow.
- Most repos lack a dependency-review gate on pull requests.
- SECURITY.md and CODEOWNERS coverage is inconsistent.

### 2) Dependency governance gaps (N/N-1)

- No consistent enforcement layer for direct dependency drift to N or N-1.
- Dependabot coverage is incomplete for many repos.

### 3) Modular architecture clarity gaps

- Many repos lack architecture/integration docs.
- Integration boundaries are implied by naming conventions, but not contract-defined.
- Similar service repos appear template-derived, indicating a need for shared baseline automation and explicit service contracts.

## Requirements by Repository Archetype

### Node/Python service repos (e.g., `*-ai`, `the-*`, `central-plexus`, `prometheus-ai`)

Required baseline:

- `.github/dependabot.yml`
- CVE scanning workflow (OSV + ecosystem audit)
- PR dependency review workflow
- N/N-1 direct dependency policy checker
- `SECURITY.md`, `CODEOWNERS`, `ARCHITECTURE.md`
- API/event contract documentation

### GitHub Action/tooling repos

Required baseline:

- Action-compatible security scans
- Dependabot for Actions and package manifests
- SECURITY.md and CODEOWNERS
- Release signing/provenance policy (where applicable)

### Template/theme/sample repos (low business criticality)

Required baseline:

- Minimum: Dependabot + SECURITY.md + CODEOWNERS
- Optional: lighter scan cadence if no deployable artifacts

## Merge vs Separate: Modularization Recommendations

### Keep separate

- Keep business-domain services (`the-*`, `*-ai`) separate if ownership differs and runtime boundaries are real.
- Keep `shared-core` separate as the canonical shared contract/types package.

### Merge/consolidate candidates

- Consolidate low-value forks/themes/samples into a dedicated sandbox/examples area where independent lifecycle is unnecessary.
- Merge duplicate template repos if they have overlapping purpose and no unique deployment/runtime.

### Hard rule

- Shared code should flow through versioned package contracts and APIs, not ad-hoc workspace-only links across standalone repos.

## Grand Timeline

| Phase | Window | Goals | Exit Criteria |
| --- | --- | --- | --- |
| 0 | Day 0-2 | Freeze risk growth | Branch protections require passing security/dependency checks for critical repos |
| 1 | Week 1 | Roll out baseline to P0 repos (`.github` templates + workflows + policies) | All P0 repos have CVE workflow, dependency workflow, Dependabot, SECURITY.md, CODEOWNERS |
| 2 | Week 2 | Enforce N/N-1 policy in service repos | N/N-1 checker active and passing for all service repos |
| 3 | Week 3-4 | Architecture contracting | ARCHITECTURE.md + integration contract docs for all platform/service repos |
| 4 | Week 5-6 | Repo topology cleanup | Merge/split decisions executed, archival policy applied, ownership mapped |
| 5 | Ongoing | Continuous governance | Weekly org audit run, monthly risk review, dependency SLA metrics tracked |

## Progress Review Against Action Plan

### Completed in this branch (`prometheus-ai`)

- Added CVE/security baseline workflow.
- Added dependency review workflow.
- Added dependency governance workflow with N/N-1 enforcement.
- Added Dependabot configuration.
- Added `SECURITY.md`, `CODEOWNERS`, `ARCHITECTURE.md`.
- Added scripts:
  - `scripts/check-n-minus-one.mjs`
  - `scripts/org-security-audit.mjs`
- Generated org-level baseline reports in `reports/`.

### Not yet completed org-wide

- P0/P1/P2 rollout across all other repos.
- Contract-level architecture docs and integration standards across ecosystem repos.
- Merge/split execution for overlapping low-value repos.

### Phase 1 execution note

- First P0 batch rollout was initiated for `shared-core`, `central-plexus`, `the-foundation`, `the-nexus`.
- `shared-core` baseline was implemented and validated locally.
- Remote push to additional repositories is currently blocked by GitHub write permissions for the active automation identity (`403`).
- Detailed execution and runbook are tracked in `docs/phase1-rollout-status.md`.

## Repo-by-Repo Gap Source of Truth

For per-repository gaps and priority:

- `reports/org-security-audit.md` (human-readable matrix)
- `reports/org-security-audit.json` (machine-readable for automation)

These files identify exactly what is missing from where, and can be re-generated after each rollout wave to measure closure.
