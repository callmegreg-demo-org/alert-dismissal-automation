# Alert Dismissal Automation

A **GitHub Actions workflow** that automatically reviews pending GitHub security
alert dismissal requests and denies any request whose comment does not meet a
minimum quality bar.

The workflow runs on a configurable schedule (no webhooks required) and
authenticates via a **GitHub App** so that every action is attributed to a
named, auditable identity rather than a personal access token.

---

## How it works

```
┌─────────────┐    schedule     ┌──────────────────────────────────┐
│  GitHub     │ ──────────────► │  Alert Dismissal Workflow         │
│  Actions    │                 │                                  │
└─────────────┘                 │  1. Get GitHub App token         │
                                │  2. Load config.yml              │
                                │  3. Fetch open dismissal         │
                                │     requests at org level        │
                                │     (code scanning,              │
                                │      secret scanning,            │
                                │      Dependabot)                 │
                                │  4. Validate requester comment   │
                                │     ✅ contains phrase?          │
                                │     ✅ not blank?                │
                                │  5. If invalid:                  │
                                │     • Deny the request via       │
                                │       the review endpoint        │
                                │       with a detailed message    │
                                └──────────────────────────────────┘
```

A dismissal request is **denied** if the requester's comment is:

* **Blank** (empty or whitespace-only), OR
* Does **not** contain the phrase `mitigating control`
  (configurable in `config.yml`)

When denied, the dismissal request is rejected via GitHub's review API with a
detailed message explaining why the request was denied, so the requester can see
the reason directly in the dismissal request review.

> [!NOTE]
> This automation uses the [delegated alert dismissal](https://docs.github.com/en/enterprise-cloud@latest/code-security/securing-your-organization/managing-the-security-of-your-organization/delegating-responsibility-for-managing-security-alerts) APIs
> (`/orgs/{org}/dismissal-requests/*`). Delegated alert dismissal must be
> **enabled** in your GitHub organization before this automation can work.

---

## Prerequisites

| Requirement | Notes |
|---|---|
| **GitHub Advanced Security** | Required for code scanning and secret scanning. |
| **Delegated alert dismissal** | Must be enabled in the organization. See [GitHub docs](https://docs.github.com/en/enterprise-cloud@latest/code-security/securing-your-organization/managing-the-security-of-your-organization/delegating-responsibility-for-managing-security-alerts). |
| **GitHub App** | Used for authentication. See [Create a GitHub App](#1-create-a-github-app) below. |
| **Node.js ≥ 20** | Used by the automation script. Provided automatically by `actions/setup-node` in the workflow. |

---

## Setup instructions

### 1. Create a GitHub App

1. Navigate to **Settings → Developer settings → GitHub Apps → New GitHub App**
   (or your organization's **Settings → Developer settings → GitHub Apps**).

2. Fill in the required fields:
   * **GitHub App name**: e.g. `Alert Dismissal Bot`
   * **Homepage URL**: URL of this repository
   * **Webhooks**: uncheck "Active" — this workflow does **not** use webhooks

3. Set the following **Organization permissions**:

   | Permission | Access |
   |---|---|
   | Organization dismissal requests for code scanning | Read & write |
   | Organization dismissal requests for Dependabot | Read & write |
   | Secret scanning alert dismissal requests | Read & write |
   | Members | Read-only |

4. Set the following **Repository permissions**:

   | Permission | Access |
   |---|---|
   | Secret scanning alerts | Read-only | Required by secret scanning dismissal request endpoints |
   | Contents | Read-only |
   | Metadata | Read-only *(required)* |

5. Under **Where can this GitHub App be installed?**, choose **Only on this
   account** or **Any account** depending on your needs.

6. Click **Create GitHub App**.

7. On the App's settings page:
   * Note the **App ID** (shown near the top).
   * Scroll to **Private keys** and click **Generate a private key**. Save the
     downloaded `.pem` file — you will need it in the next step.

8. Click **Install App** and install it on the **organization** that this
   workflow will monitor.

---

### 2. Add repository secrets

In the repository that hosts this workflow, go to
**Settings → Secrets and variables → Actions → New repository secret** and add:

| Secret name | Value |
|---|---|
| `APP_ID` | The numeric App ID from step 1.7 |
| `APP_PRIVATE_KEY` | The full contents of the `.pem` file, including the `-----BEGIN RSA PRIVATE KEY-----` and `-----END RSA PRIVATE KEY-----` lines |

---

### 3. Configure the automation

Edit [`config.yml`](config.yml) in the root of this repository.  All settings
are documented inline.  The most important ones:

```yaml
# Phrase that must appear in every dismissal request comment
required_phrase: "mitigating control"

# Deny blank dismissal request comments
deny_blank_comments: true

# Alert types to monitor
alert_types:
  - code_scanning
  - secret_scanning
  - dependabot

# Organization to monitor (defaults to owner of GITHUB_REPOSITORY)
# organization: my-org

# Team whose members are exempt from auto-deny (use the team slug)
# exempt_team: security-leads
```

---

### 4. Adjust the schedule (optional)

The workflow runs every **15 minutes** by default.  To change this, edit the
`cron` expression in
[`.github/workflows/alert-dismissal-check.yml`](.github/workflows/alert-dismissal-check.yml):

```yaml
on:
  schedule:
    - cron: '*/15 * * * *'   # ← change this
```

---

## Running manually / dry-run

Trigger the workflow from the **Actions** tab and choose `dry_run: true` to
see what the automation *would* do without making any changes.

To run locally:

```bash
export GITHUB_TOKEN=<github-app-installation-token>
export GITHUB_REPOSITORY=my-org/this-repo

# Dry run
DRY_RUN=true node scripts/check-dismissals.js

# Live run
node scripts/check-dismissals.js
```

---

## File structure

```
.
├── .github/
│   ├── copilot-instructions.md   # Copilot workspace context
│   └── workflows/
│       └── alert-dismissal-check.yml  # Scheduled workflow
├── scripts/
│   └── check-dismissals.js       # Core automation script
├── config.yml                    # User-facing configuration
├── package.json
├── package-lock.json
└── README.md
```

---

## Customizing the denial message

Set `denial_message` in `config.yml` using Markdown.  The message is sent via
the dismissal request review API so the requester can see why their request was
denied.  Available placeholders:

| Placeholder | Replaced with |
|---|---|
| `{alert_type}` | e.g. `code scanning` |
| `{alert_number}` | Numeric alert ID |
| `{required_phrase}` | Value of `required_phrase` |
| `{denial_reason}` | Human-readable reason |
| `{requester}` | GitHub username of the person who submitted the request |
| `{repo_full_name}` | `owner/repo` |

---

## Security considerations

* The GitHub App private key is stored as an encrypted repository secret and
  is never logged or exposed in workflow output.
* The App token generated during each run is short-lived (1 hour) and scoped
  to the installations the App has been granted.
* The workflow uses `permissions: contents: read` for the built-in
  `GITHUB_TOKEN`; all security-sensitive operations use the App token.
* Enable [branch protection](https://docs.github.com/en/repositories/configuring-branches-and-merges-in-your-repository/managing-protected-branches/about-protected-branches)
  on the default branch so that changes to `config.yml` and the workflow
  require review.

---

## Troubleshooting

| Symptom | Likely cause | Fix |
|---|---|---|
| Workflow fails with `Resource not accessible` | App not installed in the org, or missing permission | Install the App in the org and verify permissions |
| No dismissal requests found | Delegated alert dismissal not enabled, or no pending requests | Enable delegated alert dismissal in org settings |
| Alert type not checked | Alert type not in `alert_types`, or GHAS feature not enabled | Enable the feature in org/repo settings; check `config.yml` |
| 404 on dismissal request endpoints | Delegated alert dismissal not enabled, or GitHub Advanced Security not enabled | Enable GHAS and delegated dismissal in organization settings |
