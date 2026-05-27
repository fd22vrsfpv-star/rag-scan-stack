# Detection Rules — Writing Guide

Custom detection rules for the OSINT flagging agent. Rules are defined in YAML
and loaded automatically on startup. Changes take effect via the "Reload" button
in the UI or `POST /agent/rules/reload`.

## Quick Start

1. Create a file in `knowledge/detection_rules/custom/my_rules.yaml`
2. Define one or more rules (see examples below)
3. Click **Reload** in the Follow-Up Panel → Rules section
4. Click **Test** next to your rule to verify matches

## Rule Types

### `simple` — Query one table, check field conditions

```yaml
- id: my_simple_rule
  name: "My Simple Rule"
  type: simple
  enabled: true
  severity: medium
  confidence: 0.9
  description: "What this rule detects"
  title_template: "Alert — {target}"
  reason_template: "Explanation for {target}"
  finding_source: recon    # recon | web | vuln | credential
  query:
    table: recon_findings
    columns: [id, target, data]
    where:
      source: my_tool
    time_column: created_at
```

### `pattern` — Query + regex match

```yaml
- id: admin_panel
  name: "Admin Panel"
  type: pattern
  enabled: true
  severity: high
  confidence: 0.85
  description: "Admin panel detected"
  title_template: "Admin panel — {url}"
  reason_template: "Admin panel found at {url}"
  finding_source: web
  query:
    table: web_findings
    columns: [id, url, name, evidence]
    time_column: created_at
  match:
    type: regex
    fields: [url, name]
    pattern: "(admin|administrator|wp-admin|phpmyadmin|cpanel)"
    case_insensitive: true
```

### `cross_source` — Join findings from two tables

```yaml
- id: my_cross_rule
  name: "Cross-Source Correlation"
  type: cross_source
  enabled: true
  severity: high
  confidence: 0.95
  description: "Correlates findings across sources"
  title_template: "Correlated — {host}"
  reason_template: "Multiple signals detected for {host}"
  finding_source: web
  sources:
    - name: source_a
      table: recon_findings
      columns: [target]
      where: { source: tool_a }
      distinct: target
    - name: source_b
      table: web_findings
      columns: [id, url]
      time_column: created_at
      extract_host_from: url
  join:
    left: source_b.host
    right: source_a.target
```

## Available Tables & Columns

| Table | Columns |
|-------|---------|
| `recon_findings` | id, target, data, source, finding_type, severity, confidence, created_at, updated_at, tags |
| `web_findings` | id, url, name, evidence, source, severity, user_tags, created_at, updated_at |
| `vulns` | id, script, output, severity, asset_id, port, protocol, created_at, updated_at |
| `credential_vault` | id, username, domain, credential_value, cracked_value, credential_type, status, source, created_at, updated_at |
| `playwright_findings` | id, url, title, evidence, severity, tags, created_at, updated_at |

## Where Operators

### Direct equality
```yaml
where:
  source: wafw00f          # source = 'wafw00f'
  status: active           # status = 'active'
```

### Array contains
```yaml
where:
  array_contains:
    column: user_tags
    value: default-install   # user_tags @> ARRAY['default-install']
```

### Source list (IN)
```yaml
where:
  source_in: [katana, gau, waybackurls]   # source IN ('katana', 'gau', 'waybackurls')
```

### JSON conditions
```yaml
json_conditions:
  - column: data
    key: detected
    op: is_not_true    # (data->>'detected')::boolean IS NOT TRUE
  - column: data
    key: status
    op: eq
    value: "open"      # data->>'status' = 'open'
```

## Match Types

### `regex` — Regular expression
```yaml
match:
  type: regex
  fields: [url, name, evidence]           # Fields to search (concatenated)
  pattern: "(login|admin|auth)"           # Regex pattern
  case_insensitive: true                  # Optional, default false
```

### `set` — Value in set
```yaml
match:
  type: set
  field: severity
  values: [critical, high]
```

### `python` — Built-in function
```yaml
match:
  type: python
  function: check_self_signed   # Must be registered in PYTHON_MATCH_FUNCTIONS
```

Available built-in functions:
- `check_self_signed` — Checks tlsx data for self-signed certs
- `check_expired_cert` — Checks tlsx data for expired certs
- `check_self_signed_plus_service` — Self-signed on HTTPS ports
- `check_weak_creds` — Common password check on credential_vault
- `check_open_redirect_web` — Redirect patterns in web findings
- `check_open_redirect_recon` — Redirect params in crawled URLs

## Template Variables

Templates use `{field_name}` syntax. Available variables depend on the columns
specified in `query.columns`. Common variables:

| Source | Variables |
|--------|-----------|
| recon_findings | `{target}`, `{data}`, `{source}`, `{finding_type}` |
| web_findings | `{url}`, `{name}`, `{evidence}`, `{source}` |
| vulns | `{script}`, `{output}`, `{severity}`, `{port}` |
| credential_vault | `{username}`, `{domain}`, `{credential_type}` |

## Finding Sources

The `finding_source` field maps to the `follow_up_items.finding_source` column:
- `recon` — recon_findings table
- `web` — web_findings table
- `vuln` — vulns table
- `credential` — credential_vault table

## Ad-Hoc Rules

Ad-hoc rules can be created via:
1. The "New Rule" button in the UI
2. `POST /agent/rules/adhoc` with `{"rule_yaml": "..."}`

Ad-hoc rules are stored in the database and persist across restarts.
They can be deleted via the UI or `DELETE /agent/rules/{id}`.

## Testing Rules

Use the "Test" button in the UI or:
```bash
curl -X POST http://localhost:8000/agent/rules/test \
  -H 'x-api-key: changeme' \
  -H 'content-type: application/json' \
  -d '{"rule_id": "my_rule", "since_minutes": 999999, "limit": 10}'
```

Or test inline YAML:
```bash
curl -X POST http://localhost:8000/agent/rules/test \
  -H 'x-api-key: changeme' \
  -H 'content-type: application/json' \
  -d '{"rule_yaml": "id: test\ntype: pattern\n...", "since_minutes": 999999}'
```

## Security

- Only whitelisted tables and columns can be queried
- All values use parameterized queries (never string interpolation)
- JSON key names must match `^[a-zA-Z0-9_]+$`
- No raw SQL allowed in YAML
