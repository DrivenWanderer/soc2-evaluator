# Project Progress: SOC 2 Evaluator

## Current Phase: Phase 2 (Repository & Pipeline Controls) - READY FOR REVIEW

- **Target:** Implement repository and pipeline controls (SEC-002..005, CFG-005, DEP-002, CICD-001..003), Semgrep adapter, native code checks, .soc2ignore.yml suppressions engine, GitHub & Azure DevOps collectors, remediation templates, and token scope documentation.
- **Branch:** `phase-2/repo-and-pipeline-controls`
- **Previous PR:** [#2 (Phase 1: Thin Vertical MVP)](https://github.com/DrivenWanderer/soc2-evaluator/pull/2) - Merged into `main`.
- **Current Status:** Phase 2 implementation complete. All unit and integration tests passing (88/88).

---

### Task Status Breakdown

| Task ID | Task Description | Status | Deliverable & Verification |
|---|---|---|---|
| **0.1-0.8** | Phase 0 Foundations, Spikes & PR #1 | **Done** | Core solution, domain models, provenance & evidence hashing, PR review fixes, and Spikes A/B complete. Merged into `main`. |
| **1.1-1.7** | Phase 1 Thin Vertical MVP | **Done** | SEC-001, DEP-001, CFG-002, control mapping, remediation library, baseline diffing, PR #2 merged. |
| **2.1** | Suppressions Engine (`.soc2ignore.yml`) | **Done** | Implemented `ISuppressionService` and `SuppressionService` supporting fingerprint and glob path matching, approver, ticket, justification, and auto-reopening on expiration. 6 unit tests added (Commit `f9d18b9`). |
| **2.2** | Semgrep Scanner Adapter (`Soc2Evaluator.Adapters`) | **Done** | Implemented `SemgrepAdapter` mapping SARIF to SEC-002..005 and CFG-005 with graceful degradation (`NotRun`) on Windows when uninstalled or `--offline` (Commit `4cf9970`). |
| **2.3** | Native Syntax-Based Security & Config Rules | **Done** | Implemented native C# AST/token rules in `Soc2Evaluator.Rules`: `WeakCryptoCheck` (SEC-002), `MissingAuthorizeCheck` (SEC-003), `DisabledCertValidationCheck` (SEC-004), `SqlConcatenationCheck` (SEC-005), `PermissiveCorsCheck` (CFG-005). 16 unit tests added (Commit `1dd4951`). |
| **2.4** | Dependency Lockfile & Pinning Check (`DEP-002`) | **Done** | Implemented `LockfilePinningCheck` detecting missing/unlocked `packages.lock.json` and unpinned floating dependencies in `*.csproj` and `package.json`. 7 unit tests added (Commit `b634041`). |
| **2.5** | GitHub Collector Adapter (`CICD-001..003`) | **Done** | Implemented `GitHubCollector` in `Soc2Evaluator.Collectors` querying branch protection, deployment environments, and scanning workflows for plaintext credentials with evidence redaction. 6 unit tests added (Commit `a196ba6`). |
| **2.6** | Azure DevOps Collector Adapter (`CICD-001..003`) | **Done** | Implemented `AzureDevOpsCollector` querying branch policies and environment approvals, scanning pipeline YAMLs for secrets with redaction. 5 unit tests added (Commit `08e5749`). |
| **2.7** | Remediation Templates & Default Mappings | **Done** | Created remediation markdown files for SEC-002..005, CFG-005, DEP-002, CICD-001..003 in `config/remediations/`, updated default mappings in `config/control-mapping.default.yml`, and documented token scopes in `docs/token-scopes.md` (Commit `dff4850`). |
| **2.8** | Integration, Verification & Phase Exit | **Done** | Full clean build, 88/88 unit and integration tests passing, verified CLI evaluation on test solutions with hashed evidence artifacts. |

---

### Known Issues & Blockers
- None.

### Deviations from Plan
- **DEC-010:** Semgrep does not provide native Windows standalone binaries. Per approved strategy, Semgrep scanner adapter degrades gracefully to `NotRun` on Windows when uninstalled/offline, complemented by native in-process syntax rules in `Soc2Evaluator.Rules` ensuring complete, reproducible assessment on Windows.