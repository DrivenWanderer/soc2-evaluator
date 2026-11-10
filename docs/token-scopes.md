# Collector Authentication & Token Scope Requirements

The SOC 2 Evaluator includes automated CI/CD and repository posture collectors that interrogate GitHub and Azure DevOps APIs to evaluate change control policies (`CICD-001`), workflow secrets (`CICD-002`), and production deployment gates (`CICD-003`).

In accordance with the principle of least privilege, collectors require strictly **read-only** permissions. Collectors **never write, mutate, or delete** repository settings, code, or deployment pipelines.

---

## 1. GitHub Collector (`github-collector`)

### Supported Environment Variables
- `GITHUB_TOKEN`
- `GH_TOKEN`

### Supported Authentication Types
- **GitHub App / Fine-Grained Personal Access Token (PAT)** (Recommended)
- **Classic Personal Access Token**

### Required Read-Only Scopes

| Scope Category | Fine-Grained Permission | Classic Scope | Justification |
| :--- | :--- | :--- | :--- |
| **Branch Protection** | `Administration` (Read-only) | `repo` (Read-only) | Reads repository branch protection rules, required approval counts, and dismissal rules (`CICD-001`). |
| **Environments & Gates** | `Environments` (Read-only) | `repo` (Read-only) | Queries defined deployment environments, environment protection rules, and required reviewers (`CICD-003`). |
| **Repository Metadata** | `Metadata` (Read-only) | `repo` (Read-only) | Inspects repository details, default branch name, and repository visibility. |

### Minimum Fine-Grained Token Configuration
1. Go to **GitHub Settings > Developer Settings > Personal access tokens > Fine-grained tokens**.
2. Select **Repository access**: *Only select repositories* (choose the target repository).
3. Under **Repository permissions**:
   - `Administration`: **Read-only**
   - `Environments`: **Read-only**
   - `Metadata`: **Read-only**
4. Set expiration according to organizational policy and store in `GITHUB_TOKEN`.

---

## 2. Azure DevOps Collector (`azure-devops-collector`)

### Supported Environment Variables
- `AZURE_DEVOPS_PAT`
- `SYSTEM_ACCESSTOKEN` (automatically provided in Azure Pipelines agent runs)

### Required Read-Only Scopes

| Scope Category | Azure DevOps REST API Scope | Justification |
| :--- | :--- | :--- |
| **Branch Policies** | `Code (Read)` | Queries policy configurations (`/_apis/policy/configurations`) for required reviewer counts on target repository default branches (`CICD-001`). |
| **Pipelines & Environments** | `Release (Read)` or `Pipelines (Read)` | Queries environments (`/_apis/pipelines/environments`) and configured pre-deployment approval checks (`CICD-003`). |

### Minimum Azure DevOps PAT Configuration
1. In Azure DevOps, go to **User Settings > Personal access tokens**.
2. Create a new token with:
   - **Scopes**: Custom defined
   - **Code**: `Read`
   - **Release**: `Read` (or **Pipelines**: `Read`)
3. Export the token as `AZURE_DEVOPS_PAT`.

---

## 3. Offline Mode & Degraded Execution

When offline (`--offline`) or when tokens are omitted:
- The collector **does not fail the evaluation run**.
- Instead, it degrades gracefully to status `NotRun`.
- Findings for `CICD-001` and `CICD-003` are marked as unassessed with clear remediation guidance explaining the missing environment variable and scopes.
- In-tree pipeline files (e.g., `.github/workflows/*.yml` or `azure-pipelines*.yml`) are still checked locally for hardcoded credentials (`CICD-002`) without requiring external network connectivity.