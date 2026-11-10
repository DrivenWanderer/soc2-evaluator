### Remediation Guidance for CICD-003: Deployment Environment Lacks Approval Gate

**Category:** Process / Change Control
**Default TSC Criterion:** CC8.1 (Change Management & Production Release Authorization)

#### Immediate Actions:
1. **GitHub Actions Environments:**
   - Go to **Settings > Environments** and select the production environment (e.g., `production`, `prod`, `release`).
   - Under **Deployment protection rules**, check **Required reviewers**.
   - Add authorized production approvers (leads, release managers, or operations engineers) who must sign off before deployment runs against the environment.
   - Restrict branches that can deploy to this environment to `main` only.
2. **Azure DevOps Pipelines:**
   - Go to **Pipelines > Environments** and select the production environment.
   - Click the three dots `...` and choose **Approvals and checks**.
   - Add **Approvals** and assign designated approvers or approval groups.