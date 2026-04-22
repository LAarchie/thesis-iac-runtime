#!/usr/bin/env bash
set -euo pipefail

# ---------------------------------------------------------------------------
# run_shift_left.sh — Scan CIS scenario folders with Checkov, Trivy, and KICS
#
# Folder convention:
#   scenarios/<Section>/<CIS_ID>_<description>/
#   e.g. scenarios/Monitoring/CloudWatch.1_root_usage_alarm/
#
# Usage:
#   ./run_shift_left.sh --section Monitoring
#   ./run_shift_left.sh --section S3
#   ./run_shift_left.sh --control CloudWatch.1
#   ./run_shift_left.sh --all
#   ./run_shift_left.sh --baseline
# ---------------------------------------------------------------------------

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(dirname "$SCRIPT_DIR")"

MATRIX_FILE="$REPO_ROOT/matrix/cis_v1_4_0_compliance_matrix.json"
TOOLS_FILE="$REPO_ROOT/tools.json"

CHECKOV_IMAGE=$(jq -r '.shift_left_tools.checkov.image' "$TOOLS_FILE")
KICS_IMAGE=$(jq -r '.shift_left_tools.kics.image' "$TOOLS_FILE")
# Trivy runs as a native binary — no Docker image

# ---------------------------------------------------------------------------
# Usage
# ---------------------------------------------------------------------------
usage() {
    cat <<EOF
Usage: $(basename "$0") [OPTION]

Scan CIS AWS Foundations Benchmark v1.4.0 scenario folders with Checkov,
Trivy, and KICS. Results are saved to results/<tool>/<tool>__<CIS_ID>.json.

Options:
  --section <SECTION>   Scan all controls in a section (e.g. Monitoring, S3, IAM)
  --control <CIS_ID>    Scan a single control (e.g. CloudWatch.1, S3.5)
  --all                 Scan all controls in the matrix
  --baseline            Scan only _base folders for each section (FPR measurement)

Examples:
  ./scripts/run_shift_left.sh --section Monitoring
  ./scripts/run_shift_left.sh --control CloudWatch.1
  ./scripts/run_shift_left.sh --all
  ./scripts/run_shift_left.sh --baseline
EOF
}

if [[ $# -eq 0 ]]; then
    usage
    exit 1
fi

# ---------------------------------------------------------------------------
# Argument parsing
# ---------------------------------------------------------------------------
MODE=""
MODE_VALUE=""

case "$1" in
    --section)
        [[ $# -ge 2 ]] || { echo "Error: --section requires a value" >&2; exit 1; }
        MODE="section"
        MODE_VALUE="$2"
        ;;
    --control)
        [[ $# -ge 2 ]] || { echo "Error: --control requires a value" >&2; exit 1; }
        MODE="control"
        MODE_VALUE="$2"
        ;;
    --all)
        MODE="all"
        ;;
    --baseline)
        MODE="baseline"
        ;;
    -h|--help)
        usage
        exit 0
        ;;
    *)
        echo "Error: Unknown option: $1" >&2
        usage
        exit 1
        ;;
esac

# ---------------------------------------------------------------------------
# Helper: find scenario folder for a given cis_id and section.
# Matches folders starting with exact cis_id followed by _ or end of name.
# Excludes _base folders.
# ---------------------------------------------------------------------------
find_scenario_dir() {
    local cis_id="$1"
    local section="$2"
    local base_path="$REPO_ROOT/scenarios/${section}"

    find "$base_path" -maxdepth 1 -type d \
        \( -name "${cis_id}_*" -o -name "${cis_id}" \) \
        2>/dev/null \
        | grep -v '_base' \
        | head -1 \
        || true
}

# ---------------------------------------------------------------------------
# Build list of controls as a JSON array of {cis_id, section}
# ---------------------------------------------------------------------------
case "$MODE" in
    all|baseline)
        CONTROLS=$(jq -c '[.controls[] | {cis_id, section}]' "$MATRIX_FILE")
        ;;
    section)
        CONTROLS=$(jq -c --arg sec "$MODE_VALUE" \
            '[.controls[] | select(.section == $sec) | {cis_id, section}]' \
            "$MATRIX_FILE")
        if [[ $(echo "$CONTROLS" | jq 'length') -eq 0 ]]; then
            echo "Error: No controls found for section '$MODE_VALUE'" >&2
            exit 1
        fi
        ;;
    control)
        CONTROLS=$(jq -c --arg id "$MODE_VALUE" \
            '[.controls[] | select(.cis_id == $id) | {cis_id, section}]' \
            "$MATRIX_FILE")
        if [[ $(echo "$CONTROLS" | jq 'length') -eq 0 ]]; then
            echo "Error: Control '$MODE_VALUE' not found in matrix" >&2
            exit 1
        fi
        ;;
esac

# ---------------------------------------------------------------------------
# Create output directories
# ---------------------------------------------------------------------------
mkdir -p \
    "$REPO_ROOT/results/checkov" \
    "$REPO_ROOT/results/trivy" \
    "$REPO_ROOT/results/kics"

# ---------------------------------------------------------------------------
# Helper: get non-null, non-CHANGE_ rule IDs for a control+tool as JSON array.
# Handles rule_id that is a string, an array, or null.
# ---------------------------------------------------------------------------
get_rule_ids() {
    local cis_id="$1"
    local tool="$2"   # checkov | trivy | kics
    jq -c --arg id "$cis_id" --arg tool "$tool" '
        [
            .controls[]
            | select(.cis_id == $id)
            | .[$tool].rule_id
            | if   . == null       then empty
              elif type == "array" then .[]
              else .
              end
        ]
        | map(select(. != null and (startswith("CHANGE_") | not)))
    ' "$MATRIX_FILE"
}

# ---------------------------------------------------------------------------
# Helper: print one summary line
# ---------------------------------------------------------------------------
print_summary() {
    local tool="$1"
    local cis_id="$2"
    local status="$3"
    local matched="$4"
    printf "%-10s | %-28s | %-4s | %s\n" "$tool" "$cis_id" "$status" "$matched"
}

# ---------------------------------------------------------------------------
# Checkov — Docker
# BASELINE_MODE=1 skips rule_id matching and just reports finding counts.
# ---------------------------------------------------------------------------
run_checkov() {
    local cis_id="$1"
    local scenario_dir="$2"
    local baseline_mode="${3:-0}"
    local output_file="$REPO_ROOT/results/checkov/checkov__${cis_id}.json"

    docker run --rm \
        -v "${REPO_ROOT}:/src" \
        "$CHECKOV_IMAGE" \
        -d "/src/$(realpath --relative-to="$REPO_ROOT" "$scenario_dir")" \
        --output json --quiet \
        2>/dev/null > "$output_file" || true

    if [[ "$baseline_mode" == "1" ]]; then
        local failed passed
        failed=$(jq '.results.failed_checks | length' "$output_file" 2>/dev/null || echo "?")
        passed=$(jq '.results.passed_checks | length' "$output_file" 2>/dev/null || echo "?")
        print_summary "checkov" "$cis_id" "BASE" "passed=${passed} failed=${failed}"
        return 0
    fi

    local rule_ids
    rule_ids=$(get_rule_ids "$cis_id" "checkov")

    local status="PASS"
    local matched="no match found"

    if [[ -s "$output_file" ]] && [[ $(echo "$rule_ids" | jq 'length') -gt 0 ]]; then
        local hit
        hit=$(jq -r --argjson rids "$rule_ids" '
            .results.failed_checks[]?
            | select(.check_id as $id | $rids | index($id) != null)
            | .check_id
        ' "$output_file" 2>/dev/null | head -1 || true)
        if [[ -n "$hit" ]]; then
            status="FAIL"
            matched="$hit"
        else
            hit=$(jq -r --argjson rids "$rule_ids" '
                .results.passed_checks[]?
                | select(.check_id as $id | $rids | index($id) != null)
                | .check_id
            ' "$output_file" 2>/dev/null | head -1 || true)
            if [[ -n "$hit" ]]; then
                matched="$hit"
            fi
        fi
    fi

    print_summary "checkov" "$cis_id" "$status" "$matched"
}

# ---------------------------------------------------------------------------
# Trivy — native binary (apt 0.69.3)
# BASELINE_MODE=1 skips rule_id matching and just reports finding counts.
# ---------------------------------------------------------------------------
run_trivy() {
    local cis_id="$1"
    local scenario_dir="$2"
    local baseline_mode="${3:-0}"
    local output_file="$REPO_ROOT/results/trivy/trivy__${cis_id}.json"

    if ! command -v trivy &>/dev/null; then
        print_summary "trivy" "$cis_id" "ERR" "trivy binary not found"
        return 0
    fi

    trivy config "$scenario_dir" \
        --format json \
        --quiet \
        2>/dev/null > "$output_file" || true

    if [[ "$baseline_mode" == "1" ]]; then
        local count
        count=$(jq '[.Results[].Misconfigurations[]?] | length' "$output_file" 2>/dev/null || echo "?")
        print_summary "trivy" "$cis_id" "BASE" "misconfigurations=${count}"
        return 0
    fi

    local rule_ids
    rule_ids=$(get_rule_ids "$cis_id" "trivy")

    local status="PASS"
    local matched="no match found"

    if [[ -s "$output_file" ]] && [[ $(echo "$rule_ids" | jq 'length') -gt 0 ]]; then
        local hit
        hit=$(jq -r --argjson rids "$rule_ids" '
            .Results[]?.Misconfigurations[]?
            | select(.ID as $id | $rids | index($id) != null)
            | .ID
        ' "$output_file" 2>/dev/null | head -1 || true)
        if [[ -n "$hit" ]]; then
            status="FAIL"
            matched="$hit"
        else
            local has_results
            has_results=$(jq '.Results | length' "$output_file" 2>/dev/null || echo "0")
            if [[ "$has_results" -gt 0 ]]; then
                matched=$(echo "$rule_ids" | jq -r '.[0] // "no match found"')
            fi
        fi
    fi

    print_summary "trivy" "$cis_id" "$status" "$matched"
}

# ---------------------------------------------------------------------------
# KICS — Docker, two volumes
# BASELINE_MODE=1 skips rule_id matching and just reports finding counts.
# ---------------------------------------------------------------------------
run_kics() {
    local cis_id="$1"
    local scenario_dir="$2"
    local baseline_mode="${3:-0}"
    local kics_out_dir="$REPO_ROOT/results/kics"
    local tmp_results="$kics_out_dir/results.json"
    local output_file="$kics_out_dir/kics__${cis_id}.json"

    rm -f "$tmp_results"

    docker run --rm \
        -v "${scenario_dir}:/src" \
        -v "${kics_out_dir}:/output" \
        "$KICS_IMAGE" \
        scan -p /src --report-formats json -o /output \
        > /dev/null 2>&1 || true

    if [[ -f "$tmp_results" ]]; then
        mv "$tmp_results" "$output_file"
    else
        echo '{"queries":[]}' > "$output_file"
    fi

    if [[ "$baseline_mode" == "1" ]]; then
        local count
        count=$(jq '[.queries[]? | select((.files | length) > 0)] | length' \
            "$output_file" 2>/dev/null || echo "?")
        print_summary "kics" "$cis_id" "BASE" "queries_triggered=${count}"
        return 0
    fi

    local rule_ids
    rule_ids=$(get_rule_ids "$cis_id" "kics")

    local status="PASS"
    local matched="no match found"

    if [[ -s "$output_file" ]] && [[ $(echo "$rule_ids" | jq 'length') -gt 0 ]]; then
        local hit
        hit=$(jq -r --argjson rids "$rule_ids" '
            .queries[]?
            | select(.query_id as $id | $rids | index($id) != null)
            | select((.files | length) > 0)
            | .query_id
        ' "$output_file" 2>/dev/null | head -1 || true)
        if [[ -n "$hit" ]]; then
            status="FAIL"
            matched="$hit"
        else
            hit=$(jq -r --argjson rids "$rule_ids" '
                .queries[]?
                | select(.query_id as $id | $rids | index($id) != null)
                | .query_id
            ' "$output_file" 2>/dev/null | head -1 || true)
            if [[ -n "$hit" ]]; then
                matched="$hit"
            fi
        fi
    fi

    print_summary "kics" "$cis_id" "$status" "$matched"
}

# ---------------------------------------------------------------------------
# Scan a single scenario directory with all three tools.
# Pass baseline_mode=1 to skip rule_id matching (used for _base folders).
# ---------------------------------------------------------------------------
scan_scenario() {
    local cis_id="$1"
    local scenario_dir="$2"
    local baseline_mode="${3:-0}"

    run_checkov "$cis_id" "$scenario_dir" "$baseline_mode"
    run_trivy   "$cis_id" "$scenario_dir" "$baseline_mode"
    run_kics    "$cis_id" "$scenario_dir" "$baseline_mode"
}

# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------
echo "Shift-left scan — CIS AWS Foundations Benchmark v1.4.0"
echo "Matrix : $MATRIX_FILE"
echo "Tools  : $TOOLS_FILE"
echo "Checkov: $CHECKOV_IMAGE"
echo "KICS   : $KICS_IMAGE"
echo "Trivy  : native binary (apt 0.69.3)"
echo ""
printf "%-10s | %-28s | %-4s | %s\n" "TOOL" "CIS_ID" "STAT" "RULE_ID"
printf '%0.s-' {1..80}
echo ""

if [[ "$MODE" == "baseline" ]]; then
    # Skanuj _base dla każdej unikalnej sekcji — pomiar False Positive Rate.
    # baseline_mode=1 pomija get_rule_ids i drukuje liczby zamiast match/no match.
    while IFS= read -r section; do
        base_dir="$REPO_ROOT/scenarios/${section}/_base"
        if [[ -d "$base_dir" ]]; then
            scan_scenario "_base_${section}" "$base_dir" "1"
        else
            printf "%-10s | %-28s | %-4s | %s\n" \
                "SKIP" "_base_${section}" "---" "folder not found"
        fi
    done < <(echo "$CONTROLS" | jq -r '.[].section' | sort -u)
else
    # Skanuj scenariusze podatne
    while IFS= read -r control; do
        cis_id=$(echo "$control" | jq -r '.cis_id')
        section=$(echo "$control" | jq -r '.section')

        scenario_dir=$(find_scenario_dir "$cis_id" "$section")

        if [[ -z "$scenario_dir" ]]; then
            printf "%-10s | %-28s | %-4s | %s\n" \
                "SKIP" "$cis_id" "---" "folder not found"
            continue
        fi

        scan_scenario "$cis_id" "$scenario_dir" "0"
    done < <(echo "$CONTROLS" | jq -c '.[]')
fi

echo ""
echo "Done. Results saved to $REPO_ROOT/results/"