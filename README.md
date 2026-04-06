# 🛡️ Sentinel-IAM

> Ruby-based Access Governance CLI & Dashboard for GitHub Organizations

Sentinel-IAM audits GitHub Organization entitlements to identify over-privileged users, stale SSH keys, and access policy violations — generating compliance reports for SOC2, ISO 27001, and HIPAA audit frameworks.

---

## Architecture

```
sentinel-iam/
├── bin/
│   └── sentinel              # CLI entrypoint (Thor-based)
├── lib/
│   ├── audit/
│   │   ├── entitlement_auditor.rb   # Member entitlement audit via Octokit
│   │   └── ssh_key_auditor.rb       # SSH key staleness & weak algo detection
│   ├── rbac/
│   │   └── policy_engine.rb         # RBAC/ABAC policy evaluation engine
│   └── reports/
│       └── report_generator.rb      # Table/JSON/CSV output + compliance reports
├── dashboard/
│   ├── app.rb                # Sinatra web API + dashboard server
│   └── views/
│       └── index.erb         # Full-stack dashboard UI (HTML/CSS/JS)
├── spec/
│   ├── spec_helper.rb
│   └── sentinel_iam_spec.rb  # RSpec test suite
├── data/
│   └── reports/              # Generated compliance reports (JSON)
├── .env.example
├── Gemfile
└── README.md
```

---

## Features

### CLI (`bin/sentinel`)
- **`audit`** — Full IAM audit: entitlements + SSH keys in one pass
- **`entitlements`** — Audit member roles, stale access, over-privileged users
- **`ssh_keys`** — Scan for stale and weak-algorithm SSH keys
- **`access_review`** — Quarterly access review with compliance report generation
- **`dashboard`** — Launch the Sinatra web dashboard

### Entitlement Auditor (`lib/audit/entitlement_auditor.rb`)
Uses **Octokit** to query the GitHub API for:
- All organization members and their roles (admin vs member)
- Last activity timestamps to detect stale access
- Repository permissions to identify over-privileged users (admin on >5 repos)
- Team memberships (flags excessive team membership > 10 teams)
- Outside collaborators with stale access

### SSH Key Auditor (`lib/audit/ssh_key_auditor.rb`)
- Detects keys older than configurable threshold (default: 365 days)
- Flags deprecated algorithms: `ssh-dss` (DSA) and `ecdsa-sha2-nistp256`
- Identifies unverified keys
- Risk-scores each member: `critical | high | medium | low`

### RBAC/ABAC Policy Engine (`lib/rbac/policy_engine.rb`)
Evaluates 6 built-in policies mapped to compliance framework controls:

| Policy ID | Name | Severity | SOC2 | ISO 27001 |
|-----------|------|----------|------|-----------|
| POL-001 | Stale Admin Access | Critical | CC6.1 | A.9.2.5 |
| POL-002 | Least Privilege — Admin Repos | High | CC6.3 | A.9.4.1 |
| POL-003 | Stale Member Access | Medium | CC6.2 | A.9.2.6 |
| POL-004 | Outside Collaborator Review | High | CC6.6 | A.9.2.2 |
| POL-005 | Excessive Team Membership | Low | CC6.3 | A.9.4.1 |
| POL-006 | Secret Team Governance | Medium | CC6.1 | A.9.1.2 |

### Sinatra Dashboard (`dashboard/`)
- **Compliance score** ring chart (0–100)
- **Member entitlements** table with risk badges and violation counts
- **Policy violations** grid with framework control mapping
- **SSH key health** summary and per-member breakdown
- **Lifecycle trend** charts: risk distribution + event latency visualization
- REST API endpoints: `/api/audit`, `/api/members`, `/api/violations`, `/api/ssh`

---

## Setup

```bash
# Clone and install dependencies
git clone https://github.com/Ritesh00007/Sentinel-IAM
cd sentinel-iam
bundle install

# Configure environment
cp .env.example .env
# Edit .env with your GITHUB_TOKEN and GITHUB_ORG
```

### GitHub Token Scopes Required
- `read:org` — List members, teams, outside collaborators
- `read:user` — Fetch user profile and activity
- `repo` — Read repository collaborator permissions

---

## Usage

### CLI

```bash
# Full audit (table output)
./bin/sentinel audit --org your-org

# Entitlements only, JSON output
./bin/sentinel entitlements --org your-org --output json

# SSH key audit with custom stale threshold
./bin/sentinel ssh_keys --org your-org --stale-days 180

# Generate SOC2 quarterly compliance report
./bin/sentinel access_review --org your-org --framework SOC2 --quarter Q1-2025

# Launch web dashboard
./bin/sentinel dashboard --org your-org --port 4567
```

### Dashboard

```bash
./bin/sentinel dashboard --org your-org
# Open http://localhost:4567
```

---

## Output Formats

```bash
# Table (default) — colored terminal output
./bin/sentinel audit --org your-org --output table

# JSON — machine-readable, pipe-friendly
./bin/sentinel audit --org your-org --output json | jq '.summary'

# CSV — spreadsheet-ready
./bin/sentinel entitlements --org your-org --output csv > entitlements.csv
```

---

## Testing

```bash
bundle exec rspec spec/ --format documentation
```

Tests cover:
- `EntitlementAuditor` — member auditing, stale detection, risk calculation
- `SSHKeyAuditor` — key staleness, weak algorithm detection, risk scoring  
- `PolicyEngine` — policy evaluation, compliance scoring, framework mapping

---

## Compliance Reports

Reports are saved to `data/reports/` as JSON:

```json
{
  "meta": {
    "org": "your-org",
    "framework": "SOC2",
    "quarter": "Q1-2025",
    "compliance_score": 87.5
  },
  "executive_summary": { ... },
  "violations": [ ... ],
  "members_requiring_remediation": [ ... ]
}
```

---

## Tech Stack

| Layer | Technology |
|-------|-----------|
| CLI | Ruby, Thor, TTY-Table, Pastel |
| GitHub API | Octokit |
| Web Server | Sinatra, Puma |
| Frontend | Vanilla JS, CSS Grid, JetBrains Mono |
| Testing | RSpec, WebMock, VCR |
| Reports | JSON, CSV |
