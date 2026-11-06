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