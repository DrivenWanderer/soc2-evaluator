# SOC 2 Evaluator: Decisions and Implementation Plan (v2)

> **Revision note:** v2 incorporates a critical review of v1. Main changes: the tool is now an **orchestrator over existing scanners** rather than a collection of hand-written detectors; a **feasibility spike** gates the Roslyn approach; **evidence provenance and time-series** are core design principles; control mappings are **per-organization**; a **cloud/IdP collector** phase was added; the MVP was shrunk and the timeline corrected.

## 1. Purpose and Scope

Build a tool that evaluates a web solution against SOC 2 Trust Services Criteria (TSC), identifies gaps, documents them as findings, and proposes a remediation for each, classified as **Code**, **Configuration**, or **Process**.

**Important framing:** SOC 2 is an attestation issued by a licensed CPA firm. This tool is a *readiness assessment and evidence-gathering aid*. It must never claim a site "is compliant". Its output is "findings against a control mapping", and every report says so.

**Type I vs. Type II:** A Type II audit examines operating effectiveness over a period (typically 3-12 months). A single scan proves state on one day only. The tool is therefore designed around *repeated, timestamped, tamper-evident runs* (see section 5.3), not one-off scans.

Initial criteria coverage:

| Phase | Criteria |
|---|---|
| MVP | Security (Common Criteria), focused on CC6 (access), CC7 (monitoring), CC8 (change management) |
| Later | Availability (A), Confidentiality (C), Processing Integrity (PI), Privacy (P) |

---

## 2. Decision 1: Browser Review Tool vs. Solution Review Tool

**Decision: Solution review tool (primary), with a lightweight external probe module (secondary). No browser automation in the MVP.**

| Factor | Browser / external review | Solution (repo + config + infra) review |
|---|---|---|
| Visibility | Only what the public surface exposes | Source, config, dependencies, IaC, CI/CD, pipelines |
| SOC 2 control coverage | Small slice (TLS, headers, cookies, banners, exposed paths) | Majority of automatable controls (not measured; see coverage table in each report for actuals) |
| Change management (CC8) | Not observable | Observable via branch protection, PR rules, pipeline config |
| Logical access (CC6) | Partial (auth behavior) | Auth config, RBAC code, secrets handling, IaC IAM |
| Encryption at rest, logging, retention | Not observable | Observable in config and IaC (intent), cloud APIs (deployed state) |
| Fix quality | "Header missing" | File and line, with a proposed diff |
| Effort and fragility | Browser drivers, flaky, auth flows | Deterministic file and API reads |

SOC 2 is overwhelmingly about controls and evidence, not just runtime behavior. A browser cannot see most of what an auditor asks for.

### External probe (no browser needed)

A plain `HttpClient` probe against a supplied URL covers: TLS version and certificate validity/expiry, security headers, cookie flags, server/version disclosure, verbose error pages, exposed paths (`/.git`, `/elmah.axd`, `/trace.axd`, Swagger in prod), and HTTP-to-HTTPS redirect behavior. The probe is passive (GET/HEAD only), requires an explicit `--url`, and prints an authorization reminder.

Playwright is warranted only for authenticated-flow testing (session timeout, MFA enforcement, lockout) and is **out of scope until after Phase 5**.

---

## 3. Decision 2: Language

**Decision: C# on current .NET LTS (.NET 10).**

- **Target alignment:** Most targets are .NET. Roslyn (`Microsoft.CodeAnalysis`) offers true semantic analysis of C# where it is feasible (see the feasibility spike in Phase 0).
- **.NET config parsing:** `web.config`, `appsettings*.json`, `*.csproj`, `Directory.Packages.props`, `.sln` all have first-class parsing support.
- **Single-file deployment:** `dotnet publish -r <rid> --self-contained -p:PublishSingleFile=true` yields one binary per OS.
- **Team fit:** Home stack, lowest maintenance cost.
- **Libraries:** `System.CommandLine`, `Spectre.Console`, `YamlDotNet`, `Markdig`, `LibGit2Sharp`, `Octokit`.

| Alternative | Verdict |
|---|---|
| Python | Strong ecosystem, fast prototyping, but no native Roslyn. Reasonable if most targets turn out non-.NET. |
| Go | Great single binary, weak for .NET artifacts. |
| TypeScript/Node | Good for browser work, no advantage for the main use case. |

---

## 4. Decision 3: GUI vs. Console App

**Decision: Console app only, outputting Markdown and JSON. No GUI.**

- Findings belong in repos, PRs and tickets; Markdown is diffable and reviewable.
- A CLI runs in CI and can gate builds on severity, producing recurring evidence of ongoing monitoring (CC4, CC7).
- A GUI adds a UI framework, state management, packaging and another attack surface, with no detection benefit.

| Format | Purpose |
|---|---|
| `report.md` | Primary human-readable deliverable |
| `findings.json` | Machine-readable; feeds tickets, dashboards, run-to-run diffing, trend reports |
| `findings.sarif` | GitHub Code Scanning / Azure DevOps display |
| `report.html` (optional, late) | Rendered from MD via Markdig for polished share-outs |

Reconsider a GUI only if non-technical compliance staff become the primary users; an HTML report is the better first step even then.

---

## 5. Architecture

### 5.1 Core principle: orchestrate, don't reinvent

Mature scanners already detect most technical issues. Re-implementing them would cost months and produce worse results. The tool's value is:

1. **Orchestrating** existing scanners and normalizing their output
2. **Mapping** results to Trust Services Criteria and to the organization's own controls
3. **Covering gaps** no scanner covers (CI/CD settings, process evidence, cloud/IdP posture, evidence staleness)
4. **Generating remediation** and audit-ready reports
5. **Tracking evidence over time**

| Concern | Wrap this (adapter) | Write custom only if needed |
|---|---|---|
| .NET code analysis | Built-in .NET CA analyzers, Security Code Scan | Org-specific patterns |
| Multi-language code patterns | Semgrep | Custom rule packs |
| Secrets | gitleaks (or equivalent) | Pipeline-file-specific checks |
| Dependency vulnerabilities | OSV-Scanner, `dotnet list package --vulnerable`, `npm audit` | Lockfile/pinning policy checks |
| IaC and containers | Checkov, Trivy | Org-specific policies |
| Repo/CI settings | GitHub/Azure DevOps APIs | **Custom** (branch protection, approvals, required reviews) |
| Process controls | None | **Custom** (evidence questionnaire, staleness) |
| Cloud/IdP posture | Cloud provider APIs | **Custom** (read-only collectors) |
| TSC mapping and reporting | None | **Custom** (core value) |

Each wrapped tool sits behind an **adapter** that (a) checks the tool is installed or provides install guidance, (b) runs it with pinned arguments, (c) parses its SARIF/JSON into normalized findings, and (d) records the tool name and version as provenance. Missing tools degrade gracefully: the report lists the check as "not run" in the coverage table rather than silently passing.

### 5.2 Component diagram

```
                 +----------------------+
 CLI args  --->  |  Orchestrator        |
 org config      +----------+-----------+
                            |
   +------------+-----------+------------+-------------+
   v            v                        v             v
+--------+ +-----------+          +------------+ +-----------+
|Scanner | | Native    |          | Cloud/IdP  | | Evidence  |
|Adapters| | Collectors|          | Collectors | | Question- |
|(Semgrep| | (repo,CI  |          | (read-only)| | naire     |
| gitleaks| | settings, |          +-----+------+ +-----+-----+
| OSV..) | | HTTP probe)|               |              |
+---+----+ +-----+-----+                 |              |
    +------------+------------------------+--------------+
                 v
        +-----------------+
        | Evidence Store  |  hashed, timestamped, with provenance
        +--------+--------+
                 v
        +-----------------+      +----------------------+
        | Normalizer /    |<-----| Org Control Mapping  |
        | Rules Engine    |      | (defaults + overrides)|
        +--------+--------+      +----------------------+
                 v
        +-----------------+      +----------------------+
        | Findings        |----->| Remediation Library  |
        +--------+--------+      | (+ opt. AI assist)   |
                 v               +----------------------+
        +-----------------+
        | Reporters       |  MD / JSON / SARIF / trend
        +-----------------+
```

### 5.3 Evidence provenance and time-series (core model concern)

Every run produces an immutable **evidence bundle**:

- Run ID, UTC timestamp, tool version, target identifier, commit SHA (if repo)
- For every collector/adapter: name, version, arguments, start/end time, exit status
- SHA-256 hash of each evidence artifact and of the bundle manifest
- Findings with stable fingerprints so the same issue is recognized across runs

This enables:

- **Trend reports:** open/closed/new over time, mean time to remediate (supports CC4 and CC7 narratives)
- **Baseline diffing:** new, resolved, persisting
- **Auditor-friendly sampling:** "show me the scan from the first week of each month"
- **Tamper evidence:** manifest hash can be committed to git or signed

### 5.4 Per-organization control mapping

Auditors test against the *company's own defined controls*, which are mapped to the criteria. The mapping is therefore configuration, not code:

- `control-mapping.default.yml` ships as a **starting point only**. Several defaults (e.g., headers to CC6.6, logging to CC7.2) are judgment calls and are labeled "default, confirm with auditor".
- `control-mapping.<org>.yml` overrides or extends: map a rule to the org's control IDs (e.g., `ACME-AC-04`), change severity, or disable a rule with justification.
- Reports show both the TSC criterion and the org control ID.

### 5.5 Finding model

Rule/check ID, source (native or adapter and version), TSC criteria, org control ID, severity, category (**Code / Configuration / Process**), location (file and line, or setting/resource), redacted evidence snippet, risk explanation, recommended fix, effort estimate, confidence, fingerprint, and status (open, suppressed, resolved).

| Category | Example | Fix output |
|---|---|---|
| **Code** | `MD5.Create()` used for password hashing | Code diff and library guidance |
| **Configuration** | `customErrors mode="Off"` in `web.config` | Corrected config snippet |
| **Process** | No required reviewers on default branch | Procedure text, policy template reference |

### 5.6 Process-issue handling

Process controls (access reviews, onboarding/offboarding, incident response, vendor management, risk assessment, BCP/DR testing) cannot be inferred from code. Two mechanisms:

1. **Technical proxies** where they exist: branch protection, CODEOWNERS, pipeline approvals, stale accounts in the IdP (once connected).
2. **Evidence questionnaire** (`evidence.yml`): the user attests per control with a document link, owner and date. Missing, stale (default >12 months, configurable), or unanswered items become *Process* findings. All are labeled **"Attested, not verified."**

### 5.7 Suppressions (accepted risk)

`.soc2ignore.yml` entries require: finding fingerprint or rule plus scope, justification, **approver**, **ticket/reference ID**, and **expiry date**. Expired suppressions re-open the finding automatically. Suppressions appear in an appendix of every report so an auditor can review accepted risk.

### 5.8 Optional AI-assisted remediation (late phase)

Deterministic fix templates come first because auditors need reproducible results. Optionally, the Claude API can tailor fix suggestions and draft policy language. Because this sends client material to a third party, it is itself a vendor-management and confidentiality matter (CC9.2, C1):

- Off by default; **per-target opt-in** in the org config, not just a CLI flag
- A documented data-handling statement: what is sent (minimal snippets only, never whole repos), redaction before send, no retention assumptions without checking the provider's terms for the account used
- Fully functional offline without it
- AI output is labeled in the report and never changes severity or pass/fail

---

## 6. Tool Security and Threat Model

The tool holds API tokens, reads secrets, and processes untrusted repositories, so it must be held to the standard it checks.

| Threat | Mitigation |
|---|---|
| Scanning an untrusted repo executes its code (MSBuild targets, analyzers, restore scripts) | Default to **syntax-only/static analysis**; semantic build-based analysis only in an opt-in, sandboxed mode (container or disposable VM, no secrets, restricted network). Decision made in the Phase 0 spike. |
| Token over-privilege or leakage | Read-only scopes documented per collector; tokens only via environment variables or OS keystore; never written to reports, logs or evidence bundles |
| Secrets appearing in reports | Redaction pass on all snippets; show masked prefix only; automated test that seeded secrets never appear in output |
| Malicious scanner output or config injecting into reports | Treat adapter output as data; escape when rendering Markdown/HTML |
| Supply chain of wrapped tools | Pin versions and record hashes of adapter binaries in provenance |
| Active probing of sites you don't own | Passive probe only, explicit `--url`, authorization reminder |
| Over-claiming compliance | Fixed disclaimer, explicit coverage table, "findings" not "violations" |

---

## 7. Initial Check Catalog

"Source" indicates whether the check is delivered by a wrapped tool or custom code. Mappings are defaults subject to per-org override (section 5.4).

| ID | Check | Default TSC | Category | Source |
|---|---|---|---|---|
| SEC-001 | Hardcoded secrets / credentialed connection strings | CC6.1 | Code/Config | gitleaks adapter |
| SEC-002 | Weak or deprecated crypto (MD5, SHA1, DES, ECB) | CC6.1, CC6.7 | Code | CA analyzers / Semgrep |
| SEC-003 | Missing `[Authorize]` / risky `AllowAnonymous` | CC6.1, CC6.3 | Code | Roslyn (if spike passes) / Semgrep |
| SEC-004 | TLS cert validation disabled | CC6.7 | Code | CA analyzers / Semgrep |
| SEC-005 | SQL built via string concatenation | CC6.1, CC7.1 | Code | Security Code Scan / Semgrep |
| CFG-001 | HTTPS not enforced / HSTS missing | CC6.7 | Config | Native + probe |
| CFG-002 | Verbose errors / debug enabled in production config | CC6.1, CC7.2 | Config | **Custom** |
| CFG-003 | Missing/weak security headers and cookie flags | CC6.6 | Config | Probe |
| CFG-004 | No audit logging of auth events | CC7.2 | Code/Config | **Custom** (heuristic, low confidence) |
| CFG-005 | Overly permissive CORS | CC6.6 | Config | Native / Semgrep |
| DEP-001 | Known-vulnerable packages (direct and transitive) | CC7.1 | Config | OSV-Scanner / `dotnet list` / `npm audit` |
| DEP-002 | No lockfile / unpinned dependencies | CC8.1 | Config | **Custom** |
| CICD-001 | No branch protection or required reviews | CC8.1 | Process | **Custom** (API) |
| CICD-002 | Secrets in pipeline files; secret scanning not enabled | CC6.1 | Config | gitleaks + **Custom** |
| CICD-003 | Prod deploy without approval gate | CC8.1 | Process | **Custom** (API) |
| IAC-001 | Public storage, open security groups, unencrypted volumes | CC6.1, CC6.6, C1.1 | Config | Checkov / Trivy |
| CLD-001 | MFA / conditional access not enforced for admins | CC6.1, CC6.2 | Config | **Custom** (IdP API) |
| CLD-002 | Deployed state drifts from IaC (public endpoints, missing encryption/backups) | CC6.6, A1.2 | Config | **Custom** (cloud API) |
| PRC-001 | Missing/stale evidence: access review, IR plan, offboarding, vendor list, risk assessment | CC1-CC5, CC9 | Process | **Custom** (questionnaire) |

---

## 8. Project Structure

```
Soc2Evaluator/
  src/
    Soc2Evaluator.Cli/              # System.CommandLine entry point
    Soc2Evaluator.Core/             # Evidence, Finding, Rule, Control models; provenance
    Soc2Evaluator.Adapters/         # Semgrep, gitleaks, OSV, Checkov, Trivy wrappers
    Soc2Evaluator.Collectors/       # Repo, DotNet config, GitHub, AzureDevOps, HttpProbe
    Soc2Evaluator.Cloud/            # Read-only Azure/Entra (and AWS if needed)
    Soc2Evaluator.Rules/            # Custom checks (gaps only)
    Soc2Evaluator.Analyzers.Roslyn/ # Only if Phase 0 spike passes
    Soc2Evaluator.Reporting/        # MD, JSON, SARIF, trend
  config/
    control-mapping.default.yml
    remediations/                   # Fix templates per rule ID
  templates/
    policies/                       # Process policy/procedure starters
  tests/
    Soc2Evaluator.Tests/
    fixtures/                       # Intentionally vulnerable sample projects
  docs/
    adding-a-check.md
    threat-model.md
    data-handling.md
```

### CLI surface (draft)

```
soc2eval scan <path-or-repo-url> [options]
  --url <https://site>             Enable external probe
  --criteria security,availability
  --org-config ./org.yml           Org control mapping, suppressions, AI opt-in
  --evidence ./evidence.yml        Process-control attestations
  --out ./reports
  --format md,json,sarif
  --fail-on high                   Non-zero exit for CI gating
  --baseline ./prev/findings.json
  --sandbox                        Opt-in build-based analysis in isolation
  --offline                        Skip network-dependent checks; list them as not run
soc2eval trend ./reports           Trend report across stored runs
```

---

## 9. Report Structure (`report.md`)

1. **Header:** target, date, tool version, criteria in scope, commit SHA, run ID, evidence-bundle hash
2. **Disclaimer:** readiness assessment only; not an attestation
3. **Executive summary:** counts by severity and category, top risks
4. **Coverage table:** criteria vs. checks run vs. checks not run vs. not automatable (gaps explicit, including missing scanners, `--offline` skips, and absent cloud collectors)
5. **Findings by criterion:** ID, severity, category, source/tool and version, location, evidence, risk, recommended fix, effort
6. **Process / attestation gaps** (labeled "attested, not verified")
7. **Delta vs. baseline** and, when available, trend since first run
8. **Suppressions appendix:** justification, approver, ticket, expiry
9. **Methodology appendix:** tools and versions, rules executed, rules skipped and why

---

## 10. Implementation Phases

Estimates assume focused, full-time effort by one experienced developer. Part-time work will roughly double the calendar time. Treat as planning figures to revisit after Phase 1.

### Phase 0: Foundations and feasibility spike (about 1.5 weeks)
- Solution skeleton, DI, logging, `System.CommandLine` host
- Core models including **evidence bundle, hashing and provenance**
- MD and JSON reporters with a hard-coded sample finding
- **Spike A (Roslyn/MSBuild):** load one legacy .NET Framework solution and one .NET Core solution with `MSBuildWorkspace`; measure success rate, cross-platform behavior, and what code executes during load. **Decide:** sandboxed semantic analysis, syntax-only analysis, or rely on CA analyzers and Semgrep and drop the custom Roslyn project.
- **Spike B (adapter contract):** wrap one scanner (gitleaks or Semgrep) end to end, confirming SARIF normalization and provenance capture
- **Exit:** `soc2eval scan .` produces a valid, hashed report; spike decisions recorded in `docs/`

### Phase 1: Thin vertical MVP (about 2 weeks)
- Three checks across the whole pipeline: SEC-001 (gitleaks adapter), DEP-001 (OSV/`dotnet list` adapter), CFG-002 (custom `web.config`/`appsettings` rule)
- Default control mapping and **org override loading**
- Coverage table, remediation templates for the three checks, secrets-redaction test
- `--baseline` diffing
- **Exit:** a real .NET solution scanned; findings have location, evidence, risk and a concrete fix; seeded secrets never leak into output; false-positive review on 3+ real projects

### Phase 2: Repo and pipeline controls, more adapters (about 3 weeks)
- GitHub and Azure DevOps collectors: branch protection, required reviews, pipeline approvals, secret-scanning status (CICD-001/002/003)
- Semgrep adapter and .NET analyzer rules (SEC-002 to SEC-005, CFG-005)
- DEP-002 lockfile check
- Suppressions with approver, ticket and expiry
- **Exit:** CICD-* checks working via env-var tokens with read-only scopes documented; suppression lifecycle tested

### Phase 3: External probe, non-.NET and IaC (about 2 weeks)
- `HttpProbeCollector` and `--url` (CFG-001, CFG-003)
- Node/Python/Java manifest handling via OSV and `npm audit`
- Checkov/Trivy adapters (IAC-001)
- SARIF output and `--fail-on` CI gating; `--offline` mode
- **Exit:** meaningful results on a non-.NET repo; annotations visible in GitHub; network dependencies documented

### Phase 4: Cloud and identity collectors (about 3 weeks)
- Read-only Entra/Azure collectors (CLD-001, CLD-002): MFA/conditional access, public endpoints, encryption, backups, logging
- AWS equivalents only if needed by real targets
- IaC-vs-deployed drift detection
- **Exit:** deployed-state findings appear in the coverage table; least-privilege role definitions documented. If skipped, the coverage table must keep listing cloud/IdP as "not covered".

### Phase 5: Process controls, trends and polish (about 2 weeks)
- `evidence.yml` schema, staleness logic, PRC-* findings, policy templates
- `soc2eval trend` report from stored evidence bundles
- Availability and Confidentiality criteria expansion
- Optional HTML rendering
- Optional AI-assisted remediation with per-target opt-in and data-handling statement
- Threat model and data-handling docs finalized
- **Exit:** full report with process gaps, trends and templates; documented procedure for adding a check

**Total:** roughly 13-14 weeks full-time for everything; Phases 0-2 (about 6.5 weeks) deliver a useful .NET-focused tool.

---

## 11. Risks and Mitigations

| Risk | Mitigation |
|---|---|
| Over-claiming compliance | Fixed disclaimer, coverage table, "findings" wording |
| Duplicating existing scanners | Adapter-first architecture (5.1); custom code only for documented gaps |
| Roslyn/MSBuild fragility and code execution | Phase 0 spike; sandbox or syntax-only fallback |
| False positives eroding trust | Confidence field, suppressions with approver and expiry, tuning on real repos |
| Secrets leaking into reports | Redaction pass plus automated seeded-secret test |
| Control mapping judgment calls | Defaults labeled "confirm with auditor"; per-org overrides |
| Point-in-time results misrepresented as Type II evidence | Time-series evidence bundles; reports state the observation window |
| Scope creep into a full GRC platform | CLI-first; integrate via JSON/SARIF instead of dashboards |
| Third-party tool or API changes | Pin and record versions; adapter contract tests |
| Sending client data to an AI API | Per-target opt-in, minimal redacted snippets, data-handling statement |

---

## 12. Success Criteria

- A typical .NET solution scans in a few minutes; network use is limited to documented dependencies (vulnerability feed lookups, repo/CI APIs, opted-in probes and AI), and `--offline` lists every skipped check as "not run"
- Every finding includes source tool and version, location, evidence, risk, and a concrete fix
- Every check maps to at least one TSC criterion (overridable per org) and has a test with positive and negative fixtures
- Every run produces a hashed evidence bundle; two runs can be diffed and trended
- Adding a new check requires one class or YAML definition, one mapping entry, and one remediation template
- Seeded secrets never appear in any output artifact

---

## 13. Immediate Next Steps

1. Create the solution skeleton and core models, including evidence provenance (Phase 0)
2. Run Spike A on one legacy .NET Framework and one .NET Core solution; record the decision
3. Run Spike B wrapping gitleaks (or Semgrep) through the adapter contract
4. Build the three-check vertical slice (SEC-001, DEP-001, CFG-002)
5. Have someone who has been through a SOC 2 audit review the first real report to calibrate wording, evidence expectations and the default control mapping
