### Remediation Guidance for CICD-002: Pipeline Definitions Contain Hardcoded Secrets

**Category:** Configuration / Security
**Default TSC Criterion:** CC6.1 (Logical Access & Credential Protection)

#### Immediate Actions:
1. **Rotate Compromised Credentials:** Treat any secret or token committed into `.github/workflows/*.yml` or `azure-pipelines*.yml` as compromised. Revoke and rotate immediately.
2. **Migrate to Encrypted Pipeline Secrets:**
   - **GitHub Actions:** Store credentials under **Settings > Secrets and variables > Actions** and reference them via `${{ secrets.MY_SECRET }}`. Use GitHub OIDC for cloud provider authentication instead of long-lived access keys.
   - **Azure DevOps:** Store secrets in **Pipelines > Library > Variable Groups** (marked as secret) or bind directly to Azure Key Vault secrets. Reference them via `$(mySecret)`.
3. **Scan in Pre-commit / CI:** Incorporate secret detection (such as `gitleaks`) into CI to prevent future accidental secret commits.