# vault-migration-prep

Prepare HashiCorp Vault KV v2 secrets for Akeyless migration.

## Overview

When migrating secrets from HashiCorp Vault KV v2 to Akeyless, the migration process transfers Vault's per-version metadata alongside the secret values. This metadata has a size constraint that can prevent secrets with extensive version history from migrating or syncing. This repository provides the context to understand the constraint, tools to assess your environment, and steps to resolve it.

## How Vault KV v2 Metadata Works

Vault KV v2 automatically tracks audit metadata for every version of a secret. This includes who created each version, when it was created, and whether it was deleted or destroyed.

This per-version audit metadata is separate from "custom metadata" (user-defined key-value pairs you can attach to a secret). **The Vault UI "Metadata" tab only shows custom metadata** — the per-version audit entries are not visible in the UI.

To see the full metadata, use the CLI or API:

```bash
# CLI
vault kv metadata get -format=json secret/path/to/secret

# API
curl -s -H "X-Vault-Token: $VAULT_TOKEN" \
  $VAULT_ADDR/v1/secret/metadata/path/to/secret | jq .data
```

Every write operation creates a new version — there is no in-place update:

| Operation | Creates New Version? |
|---|---|
| `vault kv put` (create) | Yes |
| `vault kv put` (overwrite) | Yes |
| `vault kv patch` (add/modify field) | Yes |
| Vault UI save | Yes |

## What the Metadata Looks Like

A secret with 1 version produces metadata like this (see [`examples/metadata-1-version.json`](examples/metadata-1-version.json) for the full output):

```json
{
  "cas_required": false,
  "created_time": "2026-04-13T17:41:36.23375086Z",
  "current_version": 1,
  "custom_metadata": null,          // <-- This is what the Vault UI shows (empty here)
  "delete_version_after": "0s",
  "max_versions": 0,
  "oldest_version": 0,
  "updated_time": "...",
  "versions": {                     // <-- This is NOT visible in the Vault UI
    "1": {
      "created_by": { "actor": "token", "client_id": "...", "operation": "create" },
      "created_time": "2026-04-13T17:41:36.23375086Z",
      "deletion_time": "",
      "destroyed": false
    }
  }
}
```

At 1 version, the compact JSON is **~572 bytes**. Each additional version adds approximately **220 bytes** to the `versions` block.

Real examples captured from a Vault instance are in the [`examples/`](examples/) directory:

| File | Versions | Compact Size |
|---|---|---|
| [`metadata-1-version.json`](examples/metadata-1-version.json) | 1 | ~572 bytes |
| [`metadata-3-versions.json`](examples/metadata-3-versions.json) | 3 | ~1,015 bytes |
| [`metadata-4-versions.json`](examples/metadata-4-versions.json) | 4 | ~1,235 bytes |

The difference between what the UI shows and what the API returns:

```
Vault UI "Metadata" Tab          Vault CLI / API
───────────────────────          ────────────────
custom_metadata: (empty)         Full JSON including versions block
                                 with per-version audit entries
Nothing else visible             <-- This is where the size comes from
```

## Migration Behavior

The Akeyless Vault migration tool reads secret values AND full metadata from Vault, then stores the metadata in the Akeyless `item_metadata` field. The `item_metadata` field supports up to **1,024 bytes**.

### Version limits

| Vault Versions | Metadata Size | Initial Migration | Ongoing Sync |
|---|---|---|---|
| 1 | ~572 bytes | Pass | Pass |
| 2 | ~793 bytes | Pass | Pass |
| 3 | ~1,015 bytes | Pass | Next update reaches limit |
| 4+ | ~1,235+ bytes | Exceeds limit | Exceeds limit |

With custom metadata, the threshold is lower (custom metadata adds to the total).

Formula: `metadata_bytes = ~355 + (220 x version_count)`

### Sync behavior

- New secrets added to Vault with 3 or fewer versions sync normally.
- Existing secrets updated in Vault sync as long as total version count stays at 3 or fewer.
- Once a secret exceeds 3 versions in Vault, sync stops for that secret.
- New secrets added to Vault sync independently of existing secret failures.

### Vault `max_versions` setting

Setting `max_versions` limits how many versions of secret **data** are retained, but does not remove existing version **metadata** entries. It is not sufficient as a standalone remediation.

## Where to Check for Issues

### In Vault (before migration)

```bash
# Check a single secret
vault kv metadata get -format=json secret/path/to/secret | jq -c '.data' | wc -c
# Output > 1024 means this secret will not migrate

# Quick scan of all secrets under a path
for s in $(vault kv list -format=json secret/mypath/ | jq -r '.[]'); do
  size=$(vault kv metadata get -format=json "secret/mypath/${s}" | jq -c '.data' | wc -c)
  versions=$(vault kv metadata get -format=json "secret/mypath/${s}" | jq '.data.current_version')
  [ "$size" -gt 1024 ] && echo "EXCEEDS: $s (${versions} versions, ${size} bytes)"
done
```

### In Akeyless (after migration)

- Migrated metadata is visible in the Akeyless console under **General > Description** for each secret.
- Check migration status: `akeyless gateway-get-migration --name <name> --gateway-url <url>`
- Check gateway logs for per-secret errors: look for `item_metadata too long` in `/var/log/akeyless/akeyless-api-proxy-error.log`

## Assessment Tool

`scan.sh` automates the assessment and remediation process. It scans a Vault KV v2 mount, reports which secrets exceed the metadata limit, and optionally fixes them by trimming version history.

### Prerequisites

- `vault` CLI
- `jq`
- Bash 4.0+

### Quick start

```bash
export VAULT_ADDR=https://vault.example.com:8200
export VAULT_TOKEN=s.your-token

# Scan and report
./scan.sh

# Scan a specific path
./scan.sh --path apps/production/

# Scan and export to CSV
./scan.sh --output report.csv

# Fix secrets that exceed the limit (keeps last 3 versions)
./scan.sh --mode fix

# Preview fixes without making changes
./scan.sh --mode fix --dry-run
```

### CLI reference

#### Connection options

| Flag | Description | Default |
|---|---|---|
| `--vault-addr URL` | Vault server URL | `$VAULT_ADDR` |
| `--vault-token TOKEN` | Vault authentication token | `$VAULT_TOKEN` |
| `--mount PATH` | KV v2 mount path | `secret` |
| `--path PREFIX` | Path prefix to scan | entire mount |

#### Behavior options

| Flag | Description | Default |
|---|---|---|
| `--mode MODE` | `scan` (report only) or `fix` (remediate) | `scan` |
| `--dry-run` | Show what fix would do without changes | off |
| `--max-versions N` | Versions to keep when fixing (1-3) | `3` |
| `--max-metadata-size N` | Override metadata byte limit | `1024` |
| `--yes` | Skip confirmation prompts | off |
| `--no-color` | Disable colored output | off |
| `--output FILE` | Write CSV report to FILE | none |

#### Exit codes

| Code | Meaning |
|---|---|
| `0` | All secrets pass validation |
| `1` | Some secrets exceed the metadata limit |
| `2` | Runtime error (missing tools, auth failure, etc.) |

## Remediation

### Option 1: Automated (recommended)

```bash
./scan.sh --mode fix --max-versions 3
```

This backs up each affected secret, removes the version history, and recreates it with the last N versions. Backups are saved locally as JSON files.

### Option 2: Manual (single secret)

```bash
# 1. Save current value
vault kv get -format=json secret/path/to/secret > backup.json

# 2. Delete metadata (removes the secret entirely)
vault kv metadata delete secret/path/to/secret

# 3. Recreate with current value
vault kv put secret/path/to/secret \
  key1=value1 key2=value2

# 4. Verify
vault kv metadata get -format=json secret/path/to/secret | jq -c '.data' | wc -c
```

**Why delete and recreate?** Vault does not support selectively removing version metadata entries. `vault kv destroy` removes version data but keeps the metadata entry. `vault kv metadata delete` is the only way to reset the metadata.

**Important notes:**

- Always back up secrets before remediation.
- Version history beyond the kept versions is permanently removed.
- After remediation, re-run the scan to confirm all secrets are within limits.
- Then initiate migration in Akeyless.

## Recommended Workflow

```
1. Scan      ->  ./scan.sh --output report.csv
2. Review    ->  Examine the report, understand scope
3. Fix       ->  ./scan.sh --mode fix --dry-run  (preview first)
4. Fix       ->  ./scan.sh --mode fix             (apply fixes)
5. Verify    ->  ./scan.sh                         (confirm all pass)
6. Migrate   ->  Initiate migration in Akeyless
```

## License

MIT
