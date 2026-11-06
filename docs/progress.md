# Project Progress: SOC 2 Evaluator

## Current Phase: Phase 1 (Thin Vertical MVP) - IN PROGRESS

- **Target:** Implement the 3-check vertical slice (SEC-001, DEP-001, CFG-002), control mapping and org overrides, remediation library, and baseline diffing.
- **Branch:** `phase-1/thin-vertical-mvp`
- **Previous PR:** [#1 (Phase 0: Foundations and Spikes)](https://github.com/DrivenWanderer/soc2-evaluator/pull/1) - Merged into `main`.

---

### Task Status Breakdown

| Task ID | Task Description | Status | Deliverable & Verification |
|---|---|---|---|
| **0.1-0.8** | Phase 0 Foundations, Spikes & PR #1 | **Done** | Core solution, domain models, provenance & evidence hashing, PR review fixes, and Spikes A/B complete. Merged into `main`. |
| **1.1** | Control mapping engine & org config loader | **Done** | `config/control-mapping.default.yml` embedded in Core; `IControlMappingService` and `ControlMappingService` supporting default mappings and `--org-config` YAML overrides (org control IDs, severity overrides, disabled rules with justifications). 6 unit tests passing (26 total). |
| **1.2** | Check SEC-001 (Hardcoded Secrets via Gitleaks) | **Done** | Gitleaks SARIF normalization mapping to `SEC-001`, verified against test fixtures (`tests/fixtures/vulnerable-app`, `tests/fixtures/clean-app`), automated test asserting seeded secrets never leak raw into findings or SARIF artifacts. 27 unit tests passing. |
| **1.3** | Check DEP-001 (Known-Vulnerable Packages Adapter) | **Next** | Dependency scanner adapter (`osv-scanner` / `dotnet list package --vulnerable`), normalized to CC7.1, test fixtures. |
| **1.4** | Check CFG-002 (Verbose Errors / Debug in Prod) | Pending | `Soc2Evaluator.Rules` project with custom `web.config` and `appsettings*.json` rules targeting CC6.1 and CC7.2. |
| **1.5** | Remediation library & templates | Pending | `config/remediations/` templates with concrete code/config diffs wired into findings. |
| **1.6** | Baseline diffing (`--baseline`) | Pending | Run-to-run fingerprint diffing categorizing `New`, `Resolved`, and `Persisting` findings in bundle and report. |
| **1.7** | End-to-end integration & Phase 1 exit | Pending | Full scan of vulnerable and clean .NET fixtures, report verification, and PR opening. |

---

### Known Issues & Blockers
- None.

### Deviations from Plan
- Per Spike A decision (DEC-004 approved by owner), `Soc2Evaluator.Analyzers.Roslyn` is dropped to prevent untrusted code execution during MSBuild project load. Custom gap rules will use safe syntax-only parsing in `Soc2Evaluator.Rules`.