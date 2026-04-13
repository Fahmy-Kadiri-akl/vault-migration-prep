#!/usr/bin/env bash
#
# scan.sh — Validate and condition HashiCorp Vault KV v2 secrets
#            for migration to Akeyless.
#
# Akeyless stores Vault KV v2 metadata in a field called item_metadata, which
# has a 1024-byte limit.  Each version in the metadata costs ~220 bytes and the
# base envelope is ~355 bytes, so anything above ~3 versions will exceed the
# limit and cause the migration to fail silently.
#
# This tool scans a Vault KV v2 mount, reports which secrets will fail, and
# (optionally) fixes them by trimming version history down to a safe number.
#
# Usage:  ./scan.sh [OPTIONS]
#         See --help for full details.
#
# License: MIT
# ─────────────────────────────────────────────────────────────────────────────

set -euo pipefail

###############################################################################
# Defaults
###############################################################################
DEFAULT_MOUNT="secret"
DEFAULT_MODE="scan"
DEFAULT_MAX_METADATA_SIZE=1024
DEFAULT_MAX_VERSIONS=3
MIN_VERSIONS=1
MAX_VERSIONS_CEIL=3

###############################################################################
# Color helpers
###############################################################################
setup_colors() {
  if [[ "${NO_COLOR:-}" == "1" ]] || [[ ! -t 1 ]]; then
    RED="" GREEN="" YELLOW="" BLUE="" CYAN="" BOLD="" DIM="" RESET=""
  else
    RED=$'\033[0;31m'
    GREEN=$'\033[0;32m'
    YELLOW=$'\033[0;33m'
    BLUE=$'\033[0;34m'
    CYAN=$'\033[0;36m'
    BOLD=$'\033[1m'
    DIM=$'\033[2m'
    RESET=$'\033[0m'
  fi
}

###############################################################################
# Logging
###############################################################################
info()  { printf '%s[INFO]%s  %s\n' "$BLUE"  "$RESET" "$*"; }
ok()    { printf '%s[PASS]%s  %s\n' "$GREEN" "$RESET" "$*"; }
warn()  { printf '%s[WARN]%s  %s\n' "$YELLOW" "$RESET" "$*"; }
err()   { printf '%s[FAIL]%s  %s\n' "$RED"   "$RESET" "$*" >&2; }
die()   { err "$@"; exit 2; }

###############################################################################
# Usage / help
###############################################################################
usage() {
  cat <<HELPTEXT
${BOLD}vault-migration-prep${RESET} — Validate Vault KV v2 secrets for Akeyless migration

${BOLD}USAGE${RESET}
  $(basename "$0") [OPTIONS]

${BOLD}CONNECTION${RESET} (flags override env vars; prompted if missing)
  --vault-addr   URL      Vault server URL           (env: VAULT_ADDR)
  --vault-token  TOKEN    Vault authentication token (env: VAULT_TOKEN)
  --mount        PATH     KV v2 mount path           (default: ${DEFAULT_MOUNT})
  --path         PREFIX   Path prefix to scan        (default: entire mount)

${BOLD}BEHAVIOR${RESET}
  --mode         MODE     "scan" (default) or "fix"
  --dry-run               Show what fix would do without changes
  --max-versions N        Versions to keep when fixing (1-3, default: ${DEFAULT_MAX_VERSIONS})
  --max-metadata-size N   Override metadata byte limit (default: ${DEFAULT_MAX_METADATA_SIZE})
  --yes                   Skip confirmation prompts (non-interactive)
  --no-color              Disable colored output
  --output       FILE     Write CSV report to FILE
  --help                  Show this help message

${BOLD}ENVIRONMENT VARIABLES${RESET}
  VAULT_ADDR              Vault server URL
  VAULT_TOKEN             Vault authentication token
  VAULT_KV_MOUNT          KV v2 mount path

${BOLD}EXAMPLES${RESET}
  # Scan the entire "secret" mount
  export VAULT_ADDR=http://127.0.0.1:8200
  export VAULT_TOKEN=s.xxxx
  $(basename "$0")

  # Scan a specific path and write CSV
  $(basename "$0") --mount secret --path apps/ --output report.csv

  # Fix secrets that exceed the limit (keep last 3 versions)
  $(basename "$0") --mode fix --max-versions 3

  # Dry-run fix (no changes made)
  $(basename "$0") --mode fix --dry-run

${BOLD}EXIT CODES${RESET}
  0  All secrets pass validation
  1  Some secrets exceed the metadata limit
  2  Runtime error (missing tools, auth failure, etc.)

HELPTEXT
}

###############################################################################
# Prerequisite checks
###############################################################################
check_prerequisites() {
  local missing=0
  for cmd in vault jq; do
    if ! command -v "$cmd" &>/dev/null; then
      err "Required command not found: $cmd"
      missing=1
    fi
  done
  if [[ "$missing" -eq 1 ]]; then
    die "Install missing prerequisites and retry."
  fi
}

###############################################################################
# Connectivity check
###############################################################################
check_vault_connection() {
  info "Checking Vault connectivity at ${VAULT_ADDR} ..."
  local status
  if ! status=$(vault status -format=json 2>&1); then
    # vault status exits 1 when sealed but still returns JSON
    if ! echo "$status" | jq -e '.initialized' &>/dev/null; then
      die "Cannot reach Vault at ${VAULT_ADDR}. Error: ${status}"
    fi
  fi

  # Quick auth check: try to look up the token
  if ! vault token lookup -format=json &>/dev/null 2>&1; then
    die "Vault authentication failed. Check your VAULT_TOKEN."
  fi

  ok "Vault connection and authentication verified."
}

###############################################################################
# Recursive secret listing
###############################################################################
# Populates the global ALL_SECRETS array.
declare -a ALL_SECRETS=()

list_secrets_recursive() {
  local mount="$1"
  local prefix="$2"  # may be empty

  local keys
  if keys=$(vault kv list -format=json -mount="$mount" "$prefix" 2>/dev/null); then
    local count
    count=$(echo "$keys" | jq -r 'length')

    for (( i=0; i<count; i++ )); do
      local key
      key=$(echo "$keys" | jq -r ".[$i]")

      if [[ "$key" == */ ]]; then
        # It's a directory — recurse
        list_secrets_recursive "$mount" "${prefix}${key}"
      else
        ALL_SECRETS+=("${prefix}${key}")
      fi
    done
  elif vault kv metadata get -mount="$mount" "$prefix" &>/dev/null; then
    # Path is a single secret, not a directory
    ALL_SECRETS+=("$prefix")
  fi
  return 0
}

###############################################################################
# Metadata size calculation
###############################################################################
get_metadata_size() {
  local mount="$1"
  local secret_path="$2"
  local meta_json

  meta_json=$(vault kv metadata get -format=json -mount="$mount" "$secret_path" 2>/dev/null) || {
    echo "ERROR"
    return
  }

  # The .data field is what Akeyless stores as item_metadata
  local data_field
  data_field=$(echo "$meta_json" | jq -c '.data')
  echo "$data_field" | wc -c | tr -d ' '
}

###############################################################################
# Analyze a single secret — prints a JSON object
###############################################################################
analyze_secret() {
  local mount="$1"
  local secret_path="$2"
  local meta_json

  meta_json=$(vault kv metadata get -format=json -mount="$mount" "$secret_path" 2>&1) || {
    jq -cn --arg p "$secret_path" '{path:$p, error:"metadata_fetch_failed", meta_size:0, total_versions:0, active_versions:0, destroyed_versions:0, has_custom_metadata:false}'
    return
  }

  local data_field
  data_field=$(echo "$meta_json" | jq -c '.data')
  local meta_size
  meta_size=$(printf '%s' "$data_field" | wc -c | tr -d ' ')

  local total_versions active_versions destroyed_versions has_custom_metadata
  total_versions=$(echo "$meta_json"   | jq '[.data.versions | to_entries[]] | length')
  active_versions=$(echo "$meta_json"  | jq '[.data.versions | to_entries[] | select(.value.destroyed == false and .value.deletion_time == "")] | length')
  destroyed_versions=$(echo "$meta_json" | jq '[.data.versions | to_entries[] | select(.value.destroyed == true)] | length')
  has_custom_metadata=$(echo "$meta_json" | jq '.data.custom_metadata != null and (.data.custom_metadata | length) > 0')

  jq -cn \
    --arg   p  "$secret_path" \
    --argjson ms "$meta_size" \
    --argjson tv "$total_versions" \
    --argjson av "$active_versions" \
    --argjson dv "$destroyed_versions" \
    --argjson cm "$has_custom_metadata" \
    '{path:$p, meta_size:$ms, total_versions:$tv, active_versions:$av, destroyed_versions:$dv, has_custom_metadata:$cm}'
}

###############################################################################
# Progress indicator
###############################################################################
show_progress() {
  local current="$1" total="$2" path="$3"
  # Truncate path for display
  local display_path="$path"
  if (( ${#display_path} > 50 )); then
    display_path="...${display_path: -47}"
  fi
  printf '\r%s[%d/%d]%s %s%-50s%s' \
    "$CYAN" "$current" "$total" "$RESET" \
    "$DIM" "$display_path" "$RESET"
}

###############################################################################
# Report generation
###############################################################################
print_report() {
  local mount="$1" path_prefix="$2" limit="$3"
  shift 3
  # Remaining args: JSON result files (one per line in $RESULTS_FILE)

  local total=0 passing=0 failing=0
  local -a fail_entries=()

  # Size distribution buckets
  local bucket_lt512=0 bucket_512_768=0 bucket_768_1024=0 bucket_gt1024=0

  # Root cause counters
  local cause_versions=0 cause_custom=0 cause_both=0

  while IFS= read -r line; do
    (( total++ )) || true

    local ms tv cm err_flag
    err_flag=$(echo "$line" | jq -r '.error // empty')
    if [[ -n "$err_flag" ]]; then
      (( failing++ )) || true
      fail_entries+=("$line")
      continue
    fi

    ms=$(echo "$line" | jq -r '.meta_size')
    tv=$(echo "$line" | jq -r '.total_versions')
    cm=$(echo "$line" | jq -r '.has_custom_metadata')

    # Distribution
    if   (( ms < 512 ));   then (( bucket_lt512++ )) || true
    elif (( ms < 768 ));   then (( bucket_512_768++ )) || true
    elif (( ms <= limit )); then (( bucket_768_1024++ )) || true
    else                         (( bucket_gt1024++ )) || true
    fi

    if (( ms <= limit )); then
      (( passing++ )) || true
    else
      (( failing++ )) || true
      fail_entries+=("$line")

      # Root cause
      local too_many=false has_cm=false
      [[ "$tv" -gt "$DEFAULT_MAX_VERSIONS" ]] && too_many=true
      [[ "$cm" == "true" ]] && has_cm=true

      if $too_many && $has_cm; then
        (( cause_both++ )) || true
      elif $too_many; then
        (( cause_versions++ )) || true
      elif $has_cm; then
        (( cause_custom++ )) || true
      fi
    fi
  done < "$RESULTS_FILE"

  local pass_pct=0 fail_pct=0
  if (( total > 0 )); then
    pass_pct=$(( passing * 100 / total ))
    fail_pct=$(( failing * 100 / total ))
  fi

  echo ""
  printf '%s=== Vault Migration Readiness Report ===%s\n\n' "$BOLD" "$RESET"
  printf 'Mount: %s/\n' "$mount"
  printf 'Path:  %s\n' "${path_prefix:-(entire mount)}"
  printf 'Limit: %s bytes\n\n' "$limit"
  printf 'Total secrets scanned:  %d\n' "$total"
  printf '%sReady for migration:    %3d (%d%%)%s\n' "$GREEN" "$passing" "$pass_pct" "$RESET"

  if (( failing > 0 )); then
    printf '%sWill FAIL migration:    %3d (%d%%)%s\n' "$RED" "$failing" "$fail_pct" "$RESET"
  else
    printf 'Will FAIL migration:      0 (0%%)\n'
  fi

  # Failing secrets table
  if (( ${#fail_entries[@]} > 0 )); then
    echo ""
    printf '%s--- Secrets exceeding metadata limit ---%s\n' "$BOLD" "$RESET"
    printf '%-50s %8s %10s %8s\n' "SECRET" "VERSIONS" "META SIZE" "OVER BY"
    for entry in "${fail_entries[@]}"; do
      local p ms tv over_by
      p=$(echo "$entry" | jq -r '.path')
      err_flag=$(echo "$entry" | jq -r '.error // empty')
      if [[ -n "$err_flag" ]]; then
        printf '%s%-50s %s%s\n' "$RED" "$p" "ERROR: $err_flag" "$RESET"
        continue
      fi
      ms=$(echo "$entry" | jq -r '.meta_size')
      tv=$(echo "$entry" | jq -r '.total_versions')
      over_by=$(( ms - limit ))
      printf '%s%-50s %8d %10s %8s%s\n' "$RED" "$p" "$tv" \
        "$(printf '%d' "$ms")" \
        "$(printf '+%d' "$over_by")" "$RESET"
    done
  fi

  # Size distribution
  echo ""
  printf '%s--- Size distribution ---%s\n' "$BOLD" "$RESET"
  printf '< 512 bytes:    %4d secrets\n' "$bucket_lt512"
  printf '512-768 bytes:  %4d secrets\n' "$bucket_512_768"
  if (( bucket_768_1024 > 0 )); then
    printf '%s768-%d bytes: %4d secrets (close to limit!)%s\n' "$YELLOW" "$limit" "$bucket_768_1024" "$RESET"
  else
    printf '768-%d bytes: %4d secrets\n' "$limit" "$bucket_768_1024"
  fi
  if (( bucket_gt1024 > 0 )); then
    printf '%s> %d bytes:   %4d secrets (WILL FAIL)%s\n' "$RED" "$limit" "$bucket_gt1024" "$RESET"
  else
    printf '> %d bytes:   %4d secrets\n' "$limit" "$bucket_gt1024"
  fi

  # Root causes
  if (( failing > 0 )); then
    echo ""
    printf '%s--- Root causes for failures ---%s\n' "$BOLD" "$RESET"
    printf 'Too many versions:  %4d secrets\n' "$cause_versions"
    printf 'Custom metadata:    %4d secrets\n' "$cause_custom"
    printf 'Both:               %4d secrets\n' "$cause_both"
  fi

  echo ""

  # CSV output
  if [[ -n "${OUTPUT_FILE:-}" ]]; then
    info "Writing CSV report to ${OUTPUT_FILE} ..."
    echo "path,meta_size,total_versions,active_versions,destroyed_versions,has_custom_metadata,status" > "$OUTPUT_FILE"
    while IFS= read -r line; do
      local p ms tv av dv cm status
      p=$(echo "$line" | jq -r '.path')
      ms=$(echo "$line" | jq -r '.meta_size')
      tv=$(echo "$line" | jq -r '.total_versions')
      av=$(echo "$line" | jq -r '.active_versions')
      dv=$(echo "$line" | jq -r '.destroyed_versions')
      cm=$(echo "$line" | jq -r '.has_custom_metadata')
      if (( ms <= limit )); then status="PASS"; else status="FAIL"; fi
      echo "\"$p\",$ms,$tv,$av,$dv,$cm,$status" >> "$OUTPUT_FILE"
    done < "$RESULTS_FILE"
    ok "CSV report written to ${OUTPUT_FILE}"
  fi
}

###############################################################################
# Fix a single secret
###############################################################################
fix_secret() {
  local mount="$1"
  local secret_path="$2"
  local max_ver="$3"
  local limit="$4"
  local backup_dir="$5"
  local dry_run="$6"

  # Step 1: Read current and previous versions
  local -a version_data=()
  local -a version_nums=()

  # Get metadata to find version numbers
  local meta_json
  meta_json=$(vault kv metadata get -format=json -mount="$mount" "$secret_path" 2>/dev/null) || {
    err "Cannot read metadata for ${secret_path}"
    return 1
  }

  # Get sorted version numbers (descending = newest first)
  local versions_list
  versions_list=$(echo "$meta_json" | jq -r '[.data.versions | to_entries[] | select(.value.destroyed == false and .value.deletion_time == "") | .key | tonumber] | sort | reverse | .[]')

  local count=0
  while IFS= read -r ver; do
    [[ -z "$ver" ]] && continue
    [[ "$count" -ge "$max_ver" ]] && break

    local ver_json
    ver_json=$(vault kv get -format=json -mount="$mount" -version="$ver" "$secret_path" 2>/dev/null) || {
      warn "Cannot read version $ver of ${secret_path}, skipping version"
      continue
    }
    version_data+=("$ver_json")
    version_nums+=("$ver")
    (( count++ )) || true
  done <<< "$versions_list"

  if (( ${#version_data[@]} == 0 )); then
    err "No readable versions found for ${secret_path}"
    return 1
  fi

  # Step 2: Backup to local directory
  local backup_file="${backup_dir}/${secret_path//\//__}.json"
  mkdir -p "$(dirname "$backup_file")"
  echo "$meta_json" | jq --argjson vdata "$(printf '%s\n' "${version_data[@]}" | jq -s '.')" \
    '{metadata: .data, versions: $vdata}' > "$backup_file"

  if [[ "$dry_run" == "true" ]]; then
    info "[DRY-RUN] Would fix ${secret_path}: delete metadata, recreate with ${#version_data[@]} version(s), max_versions=${max_ver}"
    return 0
  fi

  # Step 3: Delete metadata (nukes the secret entirely)
  vault kv metadata delete -mount="$mount" "$secret_path" &>/dev/null || {
    err "Failed to delete metadata for ${secret_path}"
    return 1
  }

  # Step 4: Set max_versions on the path
  vault kv metadata put -mount="$mount" -max-versions="$max_ver" "$secret_path" &>/dev/null || {
    err "Failed to set max_versions for ${secret_path}"
    return 1
  }

  # Step 5: Write versions back (oldest first so newest ends up as current)
  local i
  for (( i=${#version_data[@]}-1; i>=0; i-- )); do
    local kv_data
    kv_data=$(echo "${version_data[$i]}" | jq -r '.data.data | to_entries | map("\(.key)=\(.value)") | .[]')

    # Build vault kv put arguments
    local -a put_args=()
    while IFS= read -r pair; do
      [[ -z "$pair" ]] && continue
      put_args+=("$pair")
    done <<< "$kv_data"

    if (( ${#put_args[@]} > 0 )); then
      vault kv put -mount="$mount" "$secret_path" "${put_args[@]}" &>/dev/null || {
        err "Failed to write version back for ${secret_path}"
        return 1
      }
    fi
  done

  # Step 6: Verify new metadata size
  local new_size
  new_size=$(get_metadata_size "$mount" "$secret_path")
  if [[ "$new_size" == "ERROR" ]]; then
    err "Cannot verify new metadata for ${secret_path}"
    return 1
  fi

  if (( new_size <= limit )); then
    ok "Fixed ${secret_path}: ${new_size} bytes (under ${limit} limit)"
    return 0
  else
    warn "Fixed ${secret_path} but still ${new_size} bytes (limit ${limit}). May need fewer versions."
    return 0
  fi
}

###############################################################################
# Main
###############################################################################
main() {
  setup_colors

  # Parse arguments
  local vault_addr="${VAULT_ADDR:-}"
  local vault_token="${VAULT_TOKEN:-}"
  local mount="${VAULT_KV_MOUNT:-$DEFAULT_MOUNT}"
  local path_prefix=""
  local mode="$DEFAULT_MODE"
  local dry_run="false"
  local max_versions="$DEFAULT_MAX_VERSIONS"
  local max_metadata_size="$DEFAULT_MAX_METADATA_SIZE"
  local auto_yes="false"
  local output_file=""

  while [[ $# -gt 0 ]]; do
    case "$1" in
      --vault-addr)   vault_addr="$2";          shift 2 ;;
      --vault-token)  vault_token="$2";         shift 2 ;;
      --mount)        mount="$2";               shift 2 ;;
      --path)         path_prefix="$2";         shift 2 ;;
      --mode)         mode="$2";                shift 2 ;;
      --dry-run)      dry_run="true";           shift   ;;
      --max-versions) max_versions="$2";        shift 2 ;;
      --max-metadata-size) max_metadata_size="$2"; shift 2 ;;
      --yes)          auto_yes="true";          shift   ;;
      --no-color)     NO_COLOR=1; setup_colors; shift   ;;
      --output)       output_file="$2";         shift 2 ;;
      --help|-h)      usage; exit 0 ;;
      *)              die "Unknown option: $1 (see --help)" ;;
    esac
  done

  # Validate mode
  case "$mode" in
    scan|fix) ;;
    *) die "Invalid mode '$mode'. Must be 'scan' or 'fix'." ;;
  esac

  # Validate max_versions
  if (( max_versions < MIN_VERSIONS || max_versions > MAX_VERSIONS_CEIL )); then
    die "--max-versions must be between ${MIN_VERSIONS} and ${MAX_VERSIONS_CEIL}"
  fi

  # Prerequisites
  check_prerequisites

  # Prompt for missing connection info
  if [[ -z "$vault_addr" ]]; then
    if [[ -t 0 ]]; then
      printf '%sVault address:%s ' "$BOLD" "$RESET"
      read -r vault_addr
    else
      die "VAULT_ADDR not set. Use --vault-addr or export VAULT_ADDR."
    fi
  fi

  if [[ -z "$vault_token" ]]; then
    if [[ -t 0 ]]; then
      printf '%sVault token:%s ' "$BOLD" "$RESET"
      read -rs vault_token
      echo ""
    else
      die "VAULT_TOKEN not set. Use --vault-token or export VAULT_TOKEN."
    fi
  fi

  export VAULT_ADDR="$vault_addr"
  export VAULT_TOKEN="$vault_token"
  OUTPUT_FILE="$output_file"

  # Connectivity check
  check_vault_connection

  # Discover secrets
  info "Listing secrets under ${mount}/${path_prefix} ..."
  list_secrets_recursive "$mount" "$path_prefix"

  local total=${#ALL_SECRETS[@]}
  if (( total == 0 )); then
    warn "No secrets found under ${mount}/${path_prefix}"
    exit 0
  fi
  ok "Found ${total} secrets to scan."

  # Scan phase
  RESULTS_FILE=$(mktemp)
  trap 'rm -f "$RESULTS_FILE"' EXIT

  info "Scanning metadata sizes ..."
  local idx=0
  for secret in "${ALL_SECRETS[@]}"; do
    (( idx++ )) || true
    show_progress "$idx" "$total" "${mount}/${secret}"
    analyze_secret "$mount" "$secret" >> "$RESULTS_FILE"
  done
  # Clear the progress line
  printf '\r%80s\r' ""

  ok "Scan complete."

  # Report phase
  print_report "$mount" "$path_prefix" "$max_metadata_size"

  # Count failures for exit code and fix phase
  local fail_count
  fail_count=$(jq -r --argjson limit "$max_metadata_size" \
    'select(.meta_size > $limit or .error != null) | .path' "$RESULTS_FILE" 2>/dev/null | wc -l | tr -d ' ')

  # Fix phase
  if [[ "$mode" == "fix" ]] && (( fail_count > 0 )); then
    echo ""
    printf '%s=== Fix Phase ===%s\n\n' "$BOLD" "$RESET"

    # Collect secrets to fix
    local -a to_fix=()
    while IFS= read -r p; do
      [[ -z "$p" ]] && continue
      to_fix+=("$p")
    done < <(jq -r --argjson limit "$max_metadata_size" \
      'select(.meta_size > $limit and .error == null) | .path' "$RESULTS_FILE" 2>/dev/null)

    if (( ${#to_fix[@]} == 0 )); then
      warn "No fixable secrets found (failures may be due to errors)."
    else
      info "Secrets to fix: ${#to_fix[@]}"
      echo ""
      for s in "${to_fix[@]}"; do
        printf '  - %s\n' "$s"
      done
      echo ""

      if [[ "$dry_run" == "true" ]]; then
        warn "DRY-RUN mode: no changes will be made."
      else
        printf '%sAction:%s For each secret above:\n' "$BOLD" "$RESET"
        printf '  1. Back up all current data locally\n'
        printf '  2. Delete metadata (removes the secret entirely)\n'
        printf '  3. Set max_versions=%d on the path\n' "$max_versions"
        printf '  4. Recreate with the last %d version(s) of data\n' "$max_versions"
        printf '  5. Verify new metadata size is under %d bytes\n\n' "$max_metadata_size"
      fi

      # Confirmation
      if [[ "$auto_yes" != "true" && "$dry_run" != "true" ]]; then
        printf '%s⚠  This is a destructive operation. Version history beyond the last %d will be lost.%s\n' \
          "$YELLOW" "$max_versions" "$RESET"
        printf '%sContinue? (yes/no):%s ' "$BOLD" "$RESET"
        local confirm
        read -r confirm
        if [[ "$confirm" != "yes" ]]; then
          info "Aborted."
          exit 0
        fi
      fi

      # Create backup directory
      local backup_dir
      backup_dir="./vault-migration-backup-$(date +%Y%m%d-%H%M%S)"
      mkdir -p "$backup_dir"
      info "Backups will be saved to ${backup_dir}/"

      local fixed=0 failed=0 skipped=0
      for secret in "${to_fix[@]}"; do
        if fix_secret "$mount" "$secret" "$max_versions" "$max_metadata_size" "$backup_dir" "$dry_run"; then
          (( fixed++ )) || true
        else
          (( failed++ )) || true
        fi
      done

      echo ""
      printf '%s=== Fix Summary ===%s\n' "$BOLD" "$RESET"
      printf '%sFixed:   %d%s\n' "$GREEN"  "$fixed"  "$RESET"
      printf '%sFailed:  %d%s\n' "$RED"    "$failed" "$RESET"
      printf '%sSkipped: %d%s\n' "$YELLOW" "$skipped" "$RESET"
      echo ""
      info "Backups saved to: ${backup_dir}/"
      info "To restore a secret from backup, use the JSON files in that directory."
    fi
  fi

  # Exit code
  if (( fail_count > 0 )) && [[ "$mode" == "scan" ]]; then
    exit 1
  fi
  exit 0
}

main "$@"
