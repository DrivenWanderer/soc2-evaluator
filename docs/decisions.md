# Architecture & Project Decisions

This file tracks all key technical decisions, owner approvals, approved dependencies/tools, and feasibility spike results.

---

### [2026-11-06] DEC-001: Repository Metadata and License
- **Context:** Initializing the public GitHub repository.
- **Decision:**
  - Repo name: `soc2-evaluator`
  - Description: `SOC 2 readiness assessment and evidence collection orchestrator for .NET solutions`
  - License: MIT License (Copyright 2026 Michael Perkins)
  - Remote: `https://github.com/DrivenWanderer/soc2-evaluator.git`
- **Owner Answer:** Approved.

### [2026-11-06] DEC-002: Target .NET Version and Solution Format
- **Context:** .NET 10 LTS environment check (`10.0.403` at `C:\Users\perki\.dotnet`).
- **Decision:** Target `net10.0` with `global.json` pinned to `10.0.403`. Solution uses standard .NET 10 `Soc2Evaluator.slnx` format with `Directory.Build.props` enforcing `<Nullable>enable</Nullable>` and `<TreatWarningsAsErrors>true</TreatWarningsAsErrors>`.
- **Approved Dependencies:** None added yet (using standard BCL and .NET 10 test SDK).

### [2026-11-06] DEC-003: Approved CLI Host, DI, and Logging Dependencies
- **Context:** Selection of packages for CLI argument parsing, dependency injection, and logging for Task 0.3.
- **Decision:** Approve Option 1:
  - `System.CommandLine` version `2.0.0` (MIT)
  - `Microsoft.Extensions.DependencyInjection` version `10.0.0` (MIT)
  - `Microsoft.Extensions.Logging.Console` version `10.0.0` (MIT)
- **Owner Answer:** Approved Option 1.

### [2026-11-06] DEC-004: Feasibility Spike A Outcome (Roslyn / MSBuild Code Analysis)
- **Context:** Evaluating the feasibility, safety, and cross-platform behavior of `MSBuildWorkspace` when loading arbitrary scanned solutions.
- **Findings:**
  - `MSBuildWorkspace` executes MSBuild targets during project evaluation, posing an arbitrary code execution vulnerability when evaluating untrusted repositories.
  - Legacy .NET Framework projects fail to load reliably without Windows-specific Visual Studio MSBuild tools and Mono on Linux/macOS.
  - Custom Roslyn analyzer project adds high maintenance and dependency overhead compared to wrapping mature scanners.
- **Decision:** Approve Option 1: Drop `Soc2Evaluator.Analyzers.Roslyn` and custom `MSBuildWorkspace` semantic compilation. Rely on wrapped mature scanners (.NET CA analyzers and Semgrep) for deep semantic checks, and use safe syntax-only parsing (zero build execution) for custom gap rules.
- **Owner Answer:** Approved Option 1.

### [2026-11-06] DEC-005: Feasibility Spike B Outcome (Scanner Adapter Contract & SARIF Normalization)
- **Context:** Wrapping mature scanners (prototype using gitleaks), verifying SARIF output normalization, provenance capture, and graceful degradation when tools are missing.
- **Findings:**
  - Standard SARIF 2.1.0 provides a clean contract for normalizing findings across scanners (`ruleId`, `locations`, `level`, code snippet).
  - An `IScannerAdapter` contract with `IProcessRunner` abstraction allows testable, platform-agnostic execution, provenance capture (tool version, exact arguments, start/end timestamps, exit code), and raw artifact hashing.
  - When the scanner CLI is missing, the adapter returns `Status = "NotRun"` with specific installation guidance instead of crashing or silently passing.
- **Decision:** Adopt `IScannerAdapter` as the universal adapter contract for all external scanners (Gitleaks, Semgrep, OSV-Scanner, Checkov, Trivy).

### [2026-11-06] DEC-006: Tool Availability, Discovery Cascade, and Native Fallbacks
- **Context:** Preventing developer machine tool installation constraints (e.g. absence of Docker or specific external scanners) from blocking assessments.
- **Decision:**
  - Adopt a deterministic 3-level discovery cascade: (1) Native local binary in PATH / user cache -> (2) In-box .NET SDK / native BCL fallback -> (3) Graceful degradation (`NotRun` with exact install guidance in report).
  - Docker and container runtimes are strictly optional convenience layers (never required).
  - Explicit flags (`--sandbox`, `--offline`) maintain strict predictability and prevent silent fallback behavior.
- **Owner Answer:** Approved.

### [2026-11-06] DEC-007: PR #1 Review Fixes & Integrity Clarifications
- **Context:** Addressing PR #1 review comments on evidence secrecy, accurate clean scans, markdown escaping, CI gating, and checksum verification.
- **Decision:**
  - **Artifact Sanitization:** `SarifParser.ScrubSarif` sanitizes raw snippet text before persisting artifacts to prevent secret leakage into evidence bundles.
  - **Clean Scan Accuracy:** Removed hardcoded sample finding injection from `EvaluationOrchestrator` so clean scans report 0 findings accurately. Sample findings are restricted to test fixtures.
  - **CI Gating & Format Strictness:** Enforced `--fail-on` non-zero exit code (exit 2) when findings meet/exceed threshold, and strictly reject unsupported formats like `sarif` with clear scheduling guidance (Phase 3).
  - **Accurate Coverage Table:** Coverage table derives status directly from `ToolExecutionProvenance` (`Evaluated`, `Not Run`, `Failed`) with specific reasons.
  - **Markdown Escaping:** Implemented `MarkdownSanitizer` to escape HTML tags, pipes, and control characters in untrusted scanner output.
  - **Integrity Terminology:** Replaced "tamper-evident signature" with "checksum-backed integrity record", added `VerifyArtifacts` byte-hash validation, and save a standalone `manifest.sha256` file.

### [2026-11-06] DEC-008: Control Mapping Engine and Embedded Defaults
- **Context:** Per-organization control mapping and default Trust Services Criteria alignment (Plan Section 5.4).
- **Decision:**
  - Default mappings reside in `config/control-mapping.default.yml` and are embedded directly into `Soc2Evaluator.Core` as a linked resource, ensuring the CLI binary can execute anywhere without external directory dependencies.
  - Adopted `YamlDotNet` version `18.1.0` (MIT) for deterministic YAML parsing and deserialization.
  - `ControlMappingService` supports merging an optional organization override file (`--org-config <path>`) specifying custom org control IDs, severity overrides, and rule disabling with required justifications.
  - Disabled rules transition findings to `Suppressed` status with the justification recorded in `RiskExplanation`, providing full auditor auditability.

### [2026-11-06] DEC-009: In-Process Rules Engine, Remediation Library, and Baseline Diffing
- **Context:** Implementing the Phase 1 thin vertical slice (SEC-001, DEP-001, CFG-002), remediation templates, and run-to-run delta diffing.
- **Decision:**
  - Custom gap rules implement `IRuleCheck` in `Soc2Evaluator.Rules` and are wrapped by `RulesScannerAdapter` to seamlessly integrate with orchestrator provenance and artifact tracking.
  - Static parsing (`XDocument` with line info and `JsonDocument`) is used for CFG-002 to avoid untrusted code execution during project compilation.
  - Authoritative remediation templates reside in `config/remediations/` and are embedded in `Soc2Evaluator.Core`, enriching findings with reproducible code/config diffs.
  - `BaselineDiffService` computes run-to-run deltas (`New`, `Persisting`, `Resolved`) using stable finding fingerprints, displayed in Markdown and JSON reports.

### [2026-11-10] DEC-010: Semgrep Adapter and Native In-Box Rules on Windows
- **Context:** Semgrep lacks official standalone native Windows binary distribution, requiring Docker/WSL or degrading gracefully when absent on Windows developer machines.
- **Decision:** Implement `SemgrepScannerAdapter` adhering to `IScannerAdapter` that executes `semgrep` if available on PATH or WSL, and degrades gracefully (`Status = "NotRun"`) with install/WSL guidance on native Windows. Pair this with native syntax-based analyzers in `Soc2Evaluator.Rules` for `SEC-002`, `SEC-003`, `SEC-004`, `SEC-005`, and `CFG-005`, ensuring complete, deterministic, offline evaluation on Windows without Docker or compilation requirements.
- **Owner Answer:** Approved Option 1.