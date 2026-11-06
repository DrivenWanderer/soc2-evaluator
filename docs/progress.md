# Project Progress: SOC 2 Evaluator

## Current Phase: Phase 0 (Foundations and Feasibility Spikes) - COMPLETE

- **Target:** Establish core project skeleton, domain models, provenance & evidence hashing, basic reporters, and run feasibility Spikes A and B.
- **Branch:** `phase-0/foundations-and-spikes`
- **Pull Request:** [#1](https://github.com/DrivenWanderer/soc2-evaluator/pull/1)

---

### Task Status Breakdown

| Task ID | Task Description | Status | Deliverable & Verification |
|---|---|---|---|
| **0.1** | Git repo initialization on `main` | **Done** | `main` branch initialized with `README.md`, `.gitignore`, `LICENSE` (MIT), and `docs/plan.md`. Verified clean and pushed to GitHub `DrivenWanderer/soc2-evaluator`. |
| **0.2** | Branching & solution skeleton | **Done** | Feature branch `phase-0/foundations-and-spikes`, `Soc2Evaluator.slnx`, `Directory.Build.props`, projects (`Cli`, `Core`, `Reporting`, `Tests`), and persistent docs (`progress.md`, `decisions.md`). Verified `dotnet build` and `dotnet test` pass cleanly with nullable enabled and warnings as errors. |
| **0.3** | CLI host, DI, & logging | **Done** | `System.CommandLine` host with DI container and logging. Implemented root, `scan`, and `trend` commands matching Plan Section 8. Verified `--help` and `scan --help` print correctly; unit tests pass. |
| **0.4** | Core models, provenance & evidence hashing | **Done** | Domain models (`EvidenceBundle`, `EvidenceManifest`, `ToolExecutionProvenance`, `Finding`, `ControlMappingEntry`) and `EvidenceHasher` service implementing SHA-256 manifest signing, artifact byte-hash verification, and tamper detection. Unit tests pass. |
| **0.5** | Markdown & JSON reporters | **Done** | `MarkdownReporter` (with disclaimer, executive summary, coverage table, findings, and provenance) and `JsonReporter` with `ReporterFactory`. HTML/markdown escaping and accurate coverage table reporting implemented. |
| **0.6** | Spike A: Roslyn/MSBuild feasibility spike | **Done** | Evaluated safety and cross-platform behavior of `MSBuildWorkspace`. Documented untrusted code execution risks and compatibility hurdles. Owner approved Option 1: drop custom `MSBuildWorkspace` project; rely on Semgrep/.NET CA analyzers for semantic checks and syntax-only parsing for gap checks (DEC-004). |
| **0.7** | Spike B: Scanner adapter contract | **Done** | `IScannerAdapter` abstraction, `IProcessRunner`, `SarifParser` for SARIF 2.1.0 normalization, and `GitleaksAdapter` prototype. Verified graceful degradation when tool is missing and provenance capture. |
| **0.8** | End-to-end integration & Phase 0 exit | **Done** | `soc2eval scan .` end-to-end execution producing hashed, signed evidence bundle (`evidence-bundle.json`), standalone checksum (`manifest.sha256`), and reports (`report.md`, `findings.json`). Full test suite (20 unit tests) passes cleanly. |

---

### PR #1 Review Updates (DEC-007)
- **Artifact Secrecy:** Added `SarifParser.ScrubSarif` to scrub raw secret snippet text before persisting SARIF artifacts to disk.
- **Clean Scan Accuracy:** Removed hardcoded sample finding injection from `EvaluationOrchestrator` so clean scans report 0 findings accurately.
- **Format Validation & CI Gating:** Reject unsupported formats (e.g. `sarif`) and enforce non-zero exit code (exit 2) when `--fail-on` threshold is breached.
- **Accurate Coverage Table:** Status derived directly from execution results (`Evaluated`, `Not Run`, `Failed`).
- **Markdown Escaping:** Added `MarkdownSanitizer` escaping HTML tags and table pipes in untrusted scanner output.
- **Integrity Clarification:** Updated wording from "tamper-evident" to "checksum-backed integrity record", added `VerifyArtifacts` byte-hash validation, and save standalone `manifest.sha256`.

---

### Known Issues & Blockers
- None.

### Deviations from Plan
- Per Spike A decision (DEC-004 approved by owner), `Soc2Evaluator.Analyzers.Roslyn` is dropped to prevent untrusted code execution during MSBuild project load.

### Proposed Starting Point for Phase 1
- Begin Phase 1 (Thin vertical MVP):
  - Check SEC-001 (full gitleaks adapter integration and test fixtures).
  - Check DEP-001 (OSV / `dotnet list package --vulnerable` adapter).
  - Check CFG-002 (custom `web.config` / `appsettings.json` rule).
  - Default control mapping and org override loading.
  - Baseline diffing (`--baseline`).