### Remediation Guidance for CICD-001: Default Branch Lacks Peer Review Enforcement

**Category:** Process / Change Control
**Default TSC Criterion:** CC8.1 (Change Management & Authorized Modifications)

#### Immediate Actions:
1. **GitHub Repositories:**
   - Navigate to **Settings > Branches > Branch protection rules** (or **Rules > Rulesets**).
   - Add/edit a protection rule targeting `main` or the default branch.
   - Check **Require a pull request before merging** and set **Required number of approvals before merging** to at least `1`.
   - Enable **Dismiss stale pull request approvals when new commits are pushed** and **Do not allow bypassing the above settings**.
2. **Azure DevOps Repositories:**
   - Navigate to **Project Settings > Repositories > [Repository] > Policies**.
   - Under **Branch Policies**, select `main` (or default branch).
   - Enable **Minimum number of reviewers** and set the required review count to at least `1`.
   - Enable **Reset code reviewer votes when there are new changes**.