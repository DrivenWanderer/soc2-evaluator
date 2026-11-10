# soc2-evaluator

SOC 2 readiness assessment and evidence collection orchestrator for .NET and cloud solutions.

> **Important Framing:** SOC 2 is an independent attestation issued exclusively by a licensed CPA firm. This tool is a **readiness assessment and evidence-gathering aid**. It does not certify compliance or state that a target "is compliant"; output consists of automated findings evaluated against an organization-configurable control mapping.

---

## How It Works: Dual-Perspective Evaluation

Auditors verify controls from both **source intent** (code, config, governance) and **operational reality** (deployed behavior). `soc2eval` evaluates targets across both lenses:

```
                          +-------------------------+
                          |      soc2eval CLI       |
                          +------------+------------+
                                       |
            +--------------------------+--------------------------+
            |                                                     |
            v                                                     v
   [ Inside-Out: Solution ]                              [ Outside-In: Browser & Endpoint ]
   • Source Code & Secrets                               • Transport Security (TLS / HSTS) [Planned]
   • App Config (web.config, appsettings)                • Security Headers (CSP, CORS) [Planned]
   • Dependencies (NuGet / Direct / Transitive)          • Cookie Attributes (Secure, HttpOnly) [Planned]
   • CI/CD & Branch Governance                           • Information Leakage & Error Pages [Planned]
```

---

### 1. Solution & Code Review (Inside-Out)
Inspects the repository, project files, and CI/CD configuration directly:

- **Secrets & Credentials (SEC-001 / CC6.1):** Static scan across commits and config files for hardcoded API keys, connection strings, and certificates (with automated masking to ensure raw secrets never leak into reports).
- **Configuration & Debug Flags (CFG-002, CFG-005 / CC6.1, CC7.2):** Inspects `web.config` and `appsettings*.json` for production debug compilation (`compilation debug="true"`), disabled custom errors (`customErrors mode="Off"`), and verbose diagnostic disclosures (`DetailedErrors: true`).
- **Dependency Vulnerabilities (DEP-001, DEP-002 / CC7.1, CC8.1):** Evaluates direct and transitive dependencies against known CVE/GHSA advisories via OSV-Scanner and `dotnet list package --vulnerable`, and flags unpinned dependencies or missing lockfiles.
- **Repository & Pipeline Governance (CICD-001 to CICD-003 / CC8.1):** Queries GitHub/Azure DevOps APIs to verify required pull request approvals, branch protection, deployment approval gates, and native secret-scanning enforcement.

---

### 2. Browser & Endpoint Review (Outside-In) *(Planned for Phase 2)*
*(This capability is scheduled for Phase 2 and is not currently active in the Phase 1 MVP. The `--url` option is documented here as part of the planned architecture.)*

When invoked with `--url <https://site>`, an external probe will evaluate the live, deployed web application:

- **Transport Security & Cryptography (CFG-001 / CC6.7):** Verifies TLS 1.2+ protocol enforcement, certificate validity/expiration, and strict HTTP-to-HTTPS redirect behavior.
- **Security Headers (CFG-003 / CC6.6):** Assesses defense-in-depth HTTP response headers:
  - `Strict-Transport-Security` (HSTS) with recommended `max-age` and `includeSubDomains`.
  - `Content-Security-Policy` (CSP) and `X-Frame-Options` (clickjacking protection).
  - `X-Content-Type-Options: nosniff` (MIME-sniffing prevention) and `Referrer-Policy`.
- **Cookie Security (CC6.1, CC6.6):** Validates that all authentication and session cookies mandate `Secure`, `HttpOnly`, and modern `SameSite` flags.
- **Surface Disclosure & Error Leakage (CC6.1, CC7.2):** Checks for server banner disclosures (`Server`, `X-Powered-By`, `X-AspNet-Version`), exposed administrative/diagnostic paths (`/swagger`, `/elmah.axd`, `/.git`), and default unhandled exception pages.
- *(Future Browser Automation)*: Automated session timeout, MFA enrollment enforcement, and brute-force lockout verification via headless browser flows.

---

## Quick Start

### Basic Local Scan
```powershell
# Scan current directory against default SOC 2 Common Criteria (Security)
soc2eval scan . --out ./reports
```

### Combined Solution & Live Endpoint Scan *(Planned)*
```powershell
# (Planned for Phase 2) Scan local solution files and probe the live deployed staging site
# soc2eval scan ./src/MySolution.slnx --url https://staging.example.com --out ./reports
```

### Baseline Comparison (Delta Tracking)
```powershell
# Compare against a previous run to report New, Persisting, and Resolved findings
soc2eval scan . --baseline ./reports/previous-run/findings.json --out ./reports/new-run
```

---

## Deliverables per Run

Each run generates a cryptographically hashed, immutable evidence bundle:
- **`report.md`**: Human-readable audit report with executive summary, coverage table, and remediation diffs.
- **`findings.json`**: Machine-readable findings with stable SHA-256 fingerprints for tracking and diffing.
- **`manifest.sha256`**: Standalone integrity checksum guaranteeing evidence bundle immutability.
- **`evidence/`**: Raw, sanitized tool artifacts (e.g. scanner SARIF and JSON logs).

---

## Documentation

- [Implementation Plan](docs/plan.md)
- [Architecture & Project Decisions (ADRs)](docs/decisions.md)