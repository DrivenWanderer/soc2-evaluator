# Project Progress: SOC 2 Evaluator

## Current Phase: Phase 1 (Thin Vertical MVP) - COMPLETE (Merged)

- **Target:** Implement the 3-check vertical slice (SEC-001, DEP-001, CFG-002), control mapping and org overrides, remediation library, baseline diffing, and PR review hardening.
- **Previous PR:** [#1 (Phase 0: Foundations and Spikes)](https://github.com/DrivenWanderer/soc2-evaluator/pull/1) - Merged into `main`.
- **Phase 1 PR:** [#2 (Phase 1: Thin Vertical MVP)](https://github.com/DrivenWanderer/soc2-evaluator/pull/2) - Merged into `main`.
- **Next Phase:** Phase 2 (Repo and pipeline controls, additional adapters, and suppression lifecycle).

---

### Task Status Breakdown

| Task ID | Task Description | Status | Deliverable & Verification |
|---|---|---|---|
| **0.1-0.8** | Phase 0 Foundations, Spikes & PR #1 | **Done** | Core solution, domain models, provenance & evidence hashing, PR review fixes, and Spikes A/B complete. Merged into `main`. |
| **1.1** | Control mapping engine & org config loader | **Done** | `config/control-mapping.default.yml` embedded in Core; `IControlMappingService` and `ControlMappingService` supporting default mappings and `--org-config` YAML overrides (org control IDs, severity overrides, disabled rules requiring justifications per DEC-008). |
| **1.2** | Check SEC-001 (Hardcoded Secrets via Gitleaks) | **Done** | Gitleaks SARIF normalization mapping to `SEC-001`, verified against test fixtures (`tests/fixtures/vulnerable-app`, `tests/fixtures/clean-app`), automated test asserting seeded secrets never leak raw into findings or SARIF artifacts. |
| **1.3** | Check DEP-001 (Known-Vulnerable Packages Adapter) | **Done** | Implemented `DependencyScannerAdapter` implementing 3-tier discovery cascade (`osv-scanner` -> `dotnet list package --vulnerable --include-transitive --format json` -> graceful degradation `NotRun`). Normalized to `DEP-001` (CC7.1). Supports file targets, `--offline` mode, and distinct dependency/advisory fingerprints. |
| **1.4** | Check CFG-002 (Verbose Errors / Debug in Prod) | **Done** | Created `Soc2Evaluator.Rules` project, `VerboseErrorsCheck` inspecting `web.config` (`compilation debug="true"`, `customErrors mode="Off"`) and `appsettings*.json` (`DetailedErrors: true`), with `RulesScannerAdapter` generating hashed summary evidence. |
| **1.5** | Remediation library & templates | **Done** | Created `config/remediations/` (SEC-001, DEP-001, CFG-002) embedded in Core assembly, `IRemediationService` and `RemediationService` enriching findings with concrete code/config diffs. |
| **1.6** | Baseline diffing (`--baseline`) | **Done** | Implemented `IBaselineDiffService` and `BaselineDiffService` supporting `EvidenceBundle`, `EvidenceManifest`, and raw finding lists with strict JSON format validation. Categorizes `New`, `Persisting`, and `Resolved` findings based on stable fingerprints. Renders `Delta vs. Baseline` in Markdown and JSON reports. |
| **1.7** | End-to-end integration & Phase 1 exit | **Done** | Verified full end-to-end evaluation with baseline diffing, secret redaction, bundle checksum verification (`manifest.sha256`), and `--fail-on` CI gating (evaluating open findings and rejecting invalid severities). 49 passing tests (`dotnet test`). Merged into `main` via PR #2. |

---

### Known Issues & Blockers
- None.

### Deviations from Plan
- Per Spike A decision (DEC-004 approved by owner), `Soc2Evaluator.Analyzers.Roslyn` is dropped to prevent untrusted code execution during MSBuild project load. Custom gap rules use safe syntax-only parsing in `Soc2Evaluator.Rules`.