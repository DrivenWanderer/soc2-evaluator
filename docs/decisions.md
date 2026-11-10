# Architecture & Implementation Decisions

This document records architectural, dependency, and scope decisions made during development.

### [2026-11-05] DEC-001: Target .NET Runtime Version
- **Context:** Project target framework selection.
- **Decision:** Target `.NET 10.0` (STS release currently installed on dev environment). Plan specified .NET 8 or 9 LTS, but system environment is configured with `net10.0`. Nullable reference types enabled, TreatWarningsAsErrors enabled.
- **Approved by:** Project Owner.

### [2026-11-05] DEC-002: Project Structure & CLI Framework
- **Context:** Deciding solution layering and command-line parsing library.
- **Decision:** Use multi-project solution structure:
  - `Soc2Evaluator.Core`: Domain models, interfaces, hashing, configuration.
  - `Soc2Evaluator.Adapters`: Wrappers around external scanners (Gitleaks, Semgrep, OSV).
  - `Soc2Evaluator.Rules`: Custom AST and regex rules for gaps not covered by external tools.
  - `Soc2Evaluator.Reporting`: Markdown and JSON report generators.
  - `Soc2Evaluator.Cli`: Command-line interface using `System.CommandLine` 2.0.0-beta4.22272.1.
- **Approved by:** Project Owner.

### [2026-11-05] DEC-003: Core Dependencies
- **Context:** Initial package approvals for Phase 0.
- **Approved Packages:**
  - `System.CommandLine` (2.0.0-beta4.22272.1) - CLI parsing (MIT)
  - `Microsoft.Extensions.DependencyInjection` (10.0.0) - DI container (MIT)
  - `Microsoft.Extensions.Logging` (10.0.0) - Structured logging (MIT)
  - `Microsoft.Extensions.Logging.Console` (10.0.0) - Console output (MIT)
  - `xunit` (2.9.2), `xunit.runner.visualstudio` (2.8.2), `Microsoft.NET.Test.Sdk` (17.11.1) - Testing (Apache 2.0 / MIT)
- **Approved by:** Project Owner.

### [2026-11-05] DEC-004: Roslyn Semantic Analysis Feasibility Spike (Spike A Outcome)
- **Context:** Investigating whether Roslyn `MSBuildWorkspace` or in-tree semantic analyzers should be used to parse C# code for security and configuration checks.
- **Finding:** Running `MSBuildWorkspace` against untrusted repositories executes custom MSBuild targets, tasks, and property functions, introducing remote code execution vulnerabilities outside an approved sandbox. Furthermore, `MSBuildWorkspace` requires full MSBuild SDK resolution which fails on non-standard build environments.
- **Decision:** Do NOT use `MSBuildWorkspace` or compiled semantic analysis in Phase 1/2. Use safe, isolated static analysis (`System.Text.Json`, `System.Xml.Linq`, and regex-based AST token scanning) in `Soc2Evaluator.Rules`. Custom checks must never execute scanned code or invoke untrusted MSBuild targets.
- **Approved by:** Project Owner.

### [2026-11-05] DEC-005: External Probe Safety Architecture (Spike B Outcome)
- **Context:** Evaluating HTTP external probe constraints for CC6.6 boundary validation.
- **Finding:** Active network scanning or aggressive fuzzing against production endpoints violates audit scope and can trigger denial of service or WAF IP bans.
- **Decision:**
  - External probe requires explicit opt-in flag (`--url <target-url>`).
  - Restricted strictly to `GET` and `HEAD` requests.
  - No recursive crawling, path discovery, or header fuzzing.
  - Verifies presence of security headers (`Content-Security-Policy`, `Strict-Transport-Security`, `X-Content-Type-Options`, `X-Frame-Options`) and validates TLS cipher suite / certificate validity.
- **Approved by:** Project Owner.

### [2026-11-06] DEC-006: Phase 0 PR Review Feedback Implementation
- **Context:** Addressing owner feedback on PR #1 (Phase 0 Foundations and Spikes).
- **Actions Taken:**
  - **Readiness Framing:** Added explicit SOC 2 readiness assessment disclaimers across all reporting outputs and CLI help text stating that the tool is a readiness aid and not an attestation of compliance.
  - **Graceful Scanner Degradation:** All scanner adapters implement `IScannerAdapter.IsAvailableAsync()` and record `NotRun` status with clear installation guidance when scanners are absent.
  - **Deterministic Evidence Hashing:** Provenance timestamps normalized to ISO 8601 UTC with format `yyyy-MM-ddTHH:mm:ssZ`. Added `manifest.sha256` artifact.
  - **Public Repo Precautions:** Added fixtures directory with verified non-functional secrets and automated test asserting seeded secrets never leak into evidence manifests or reports.

### [2026-11-06] DEC-007: PR Review Fixes Verification
- **Context:** Verifying owner PR #1 review comments.
- **Decision:**
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
- **Approved by:** Project Owner.

### [2026-11-10] DEC-011: Suppressions Engine (.soc2ignore.yml) & Lifecycle Management
- **Context:** Implementing finding suppressions with audit justifications, approvers, expiration dates, and ticketing references (Section 5.3 of plan).
- **Decision:**
  - Implemented `.soc2ignore.yml` loader and evaluator in `Soc2Evaluator.Core/Services/SuppressionService.cs`.
  - Suppressions match on finding fingerprint OR rule ID combined with glob-based path scope (e.g. `tests/**`).
  - Mandatory audit fields: `justification`, `approver`, `ticket`.
  - Lifecycle: If `expires` date is present and in the past, suppression is automatically expired and the finding re-opens with an expired notice for auditor visibility.
  - Suppressed findings are recorded in an audit appendix in Markdown and findings JSON with justifications and approvers.

### [2026-11-10] DEC-012: GitHub and Azure DevOps Collectors Architecture & Scopes
- **Context:** Interrogating repository branch protection and CI/CD pipeline approval gates (CICD-001, CICD-002, CICD-003).
- **Decision:**
  - Implemented `GitHubCollector` and `AzureDevOpsCollector` adhering to `IScannerAdapter` in dedicated `Soc2Evaluator.Collectors` project.
  - Uses strictly read-only scopes (GitHub: `Administration:read`, `Environments:read`, `Metadata:read`; Azure DevOps: `Code (Read)`, `Release/Pipelines (Read)`).
  - Degrades gracefully with `NotRun` status when offline or when tokens are omitted, emitting clear token setup instructions.
  - Captures raw API responses as hashed evidence bundle artifacts (`github-posture.json`, `azure-devops-posture.json`).
  - Inspects local pipeline files for plaintext credentials (`CICD-002`) with automated evidence redaction.