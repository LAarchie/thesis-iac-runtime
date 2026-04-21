#!/usr/bin/env bash
set -euo pipefail

# ---------------------------------------------------------------------------
# run_shift_left.sh — Scan CIS scenario folders with Checkov, Trivy, and KICS
#
# Usage:
#   ./run_shift_left.sh --section Monitoring
#   ./run_shift_left.sh --section S3
#   ./run_shift_left.sh --control CloudWatch.1
#   ./run_shift_left.sh --all
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

Examples:
  ./run_shift_left.sh --section Monitoring
  ./run_shift_left.sh --section S3
  ./run_shift_left.sh --control CloudWatch.1
  ./run_shift_left.sh --all
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
# Build list of controls to process as a JSON array of {cis_id, section}
# ---------------------------------------------------------------------------
case "$MODE" in
    all)
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
# Helper: get non-null, non-CHANGE_ rule IDs for a control+tool as JSON array
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
    printf "%-10s | %-20s | %-4s | %s\n" "$tool" "$cis_id" "$status" "$matched"
}

# ---------------------------------------------------------------------------
# Checkov — Docker
# ---------------------------------------------------------------------------
run_checkov() {
    local cis_id="$1"
    local section="$2"
    local scenario_dir="$REPO_ROOT/scenarios/$section/$cis_id"
    local output_file="$REPO_ROOT/results/checkov/checkov__${cis_id}.json"

    [[ -d "$scenario_dir" ]] || return 0

    local _exit=0
    docker run --rm \
        -v "${REPO_ROOT}:/src" \
        "$CHECKOV_IMAGE" \
        -d "/src/scenarios/${section}/${cis_id}" \
        --output json --quiet \
        > "$output_file" 2>/dev/null || _exit=$?

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
# Trivy — native binary
# ---------------------------------------------------------------------------
run_trivy() {
    local cis_id="$1"
    local section="$2"
    local scenario_dir="$REPO_ROOT/scenarios/$section/$cis_id"
    local output_file="$REPO_ROOT/results/trivy/trivy__${cis_id}.json"

    [[ -d "$scenario_dir" ]] || return 0

    local _exit=0
    trivy config "$scenario_dir" --format json \
        > "$output_file" 2>/dev/null || _exit=$?

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
# ---------------------------------------------------------------------------
run_kics() {
    local cis_id="$1"
    local section="$2"
    local scenario_dir="$REPO_ROOT/scenarios/$section/$cis_id"
    local kics_out_dir="$REPO_ROOT/results/kics"
    local tmp_results="$kics_out_dir/results.json"
    local output_file="$kics_out_dir/kics__${cis_id}.json"

    [[ -d "$scenario_dir" ]] || return 0

    rm -f "$tmp_results"

    local _exit=0
    docker run --rm \
        -v "${scenario_dir}:/src" \
        -v "${kics_out_dir}:/output" \
        "$KICS_IMAGE" \
        scan -p /src --report-formats json -o /output \
        > /dev/null 2>&1 || _exit=$?

    if [[ -f "$tmp_results" ]]; then
        mv "$tmp_results" "$output_file"
    else
        echo '{"queries":[]}' > "$output_file"
    fi

    local rule_ids
    rule_ids=$(get_rule_ids "$cis_id" "kics")

    local status="PASS"
    local matched="no match found"

    if [[ -s "$output_file" ]] && [[ $(echo "$rule_ids" | jq 'length') -gt 0 ]]; then
        local hit
        # query has files with issues → FAIL
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
            # query present but no files → PASS with matched rule
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
# Main
# ---------------------------------------------------------------------------
echo "Shift-left scan — CIS AWS Foundations Benchmark v1.4.0"
echo "Matrix : $MATRIX_FILE"
echo "Tools  : $TOOLS_FILE"
echo "Checkov: $CHECKOV_IMAGE"
echo "KICS   : $KICS_IMAGE"
echo "Trivy  : native binary"
echo ""
printf "%-10s | %-20s | %-4s | %s\n" "TOOL" "CIS_ID" "STAT" "RULE_ID"
printf '%0.s-' {1..72}
echo ""

while IFS= read -r control; do
    cis_id=$(echo "$control" | jq -r '.cis_id')
    section=$(echo "$control" | jq -r '.section')

    run_checkov "$cis_id" "$section"
    run_trivy   "$cis_id" "$section"
    run_kics    "$cis_id" "$section"
done < <(echo "$CONTROLS" | jq -c '.[]')

echo ""
echo "Done. Results saved to $REPO_ROOT/results/"
