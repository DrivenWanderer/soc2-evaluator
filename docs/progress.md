# Project Progress: SOC 2 Evaluator

## Current Phase: Phase 0 (Foundations and Feasibility Spikes)

- **Target:** Establish core project skeleton, domain models, provenance & evidence hashing, basic reporters, and run feasibility Spikes A and B.
- **Branch:** `phase-0/foundations-and-spikes`

---

### Task Status Breakdown

| Task ID | Task Description | Status | Deliverable & Verification |
|---|---|---|---|
| **0.1** | Git repo initialization on `main` | **Done** | `main` branch initialized with `README.md`, `.gitignore`, `LICENSE` (MIT), and `docs/plan.md`. Verified clean and pushed to GitHub `DrivenWanderer/soc2-evaluator`. |
| **0.2** | Branching & solution skeleton | **Done** | Feature branch `phase-0/foundations-and-spikes`, `Soc2Evaluator.slnx`, `Directory.Build.props`, projects (`Cli`, `Core`, `Reporting`, `Tests`), and persistent docs (`progress.md`, `decisions.md`). Verified `dotnet build` and `dotnet test` pass cleanly with nullable enabled and warnings as errors. |
| **0.3** | CLI host, DI, & logging | **Done** | `System.CommandLine` host with DI container and logging. Implemented root, `scan`, and `trend` commands matching Plan Section 8. Verified `--help` and `scan --help` print correctly; unit tests pass. |
| **0.4** | Core models, provenance & evidence hashing | **Done** | Domain models (`EvidenceBundle`, `EvidenceManifest`, `ToolExecutionProvenance`, `Finding`, `ControlMappingEntry`) and `EvidenceHasher` service implementing SHA-256 manifest signing and tamper detection. 8 unit tests pass. |
| **0.5** | Markdown & JSON reporters | **Done** | `MarkdownReporter` (with disclaimer, executive summary, coverage table, findings, and provenance) and `JsonReporter` with `ReporterFactory`. 11 unit tests pass. |
| **0.6** | Spike A: Roslyn/MSBuild feasibility spike | **Done** | Evaluated safety and cross-platform behavior of `MSBuildWorkspace`. Documented untrusted code execution risks and compatibility hurdles. Owner approved Option 1: drop custom `MSBuildWorkspace` project; rely on Semgrep/.NET CA analyzers for semantic checks and syntax-only parsing for gap checks (DEC-004). |
| **0.7** | Spike B: Scanner adapter contract | **Pending** | `IScannerAdapter` abstraction and prototype adapter wrapping gitleaks/Semgrep. Verified by mock/fixture tests. |
| **0.8** | End-to-end integration & Phase 0 exit | **Pending** | `soc2eval scan .` producing hashed evidence bundle and reports. Verified exit criteria checklist. |

---

### Known Issues & Blockers
- None at this time.

### Deviations from Plan
- Per Spike A decision (DEC-004 approved by owner), `Soc2Evaluator.Analyzers.Roslyn` is dropped to prevent untrusted code execution during MSBuild project load.

### Next Step
- Proceed to Task 0.7 (Spike B: Scanner adapter contract).