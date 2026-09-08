#!/usr/bin/env bash
set -euo pipefail

if [[ $# -lt 1 || $# -gt 2 ]]; then
    echo "usage: $0 <frozen-migtd-elf> [evidence-directory]" >&2
    exit 2
fi

binary=$(readlink -f "$1")
evidence_dir=${2:-"$(pwd)/snp-stage-a-evidence"}
policy_file=${MIGTD_POLICY_FILE:?MIGTD_POLICY_FILE must name the fixture policy}
root_ca_file=${MIGTD_ROOT_CA_FILE:?MIGTD_ROOT_CA_FILE must name the fixture root CA}
peer_address=${MIGTD_STAGE_A_PEER_ADDRESS:-127.0.0.1:19410}
timeout_seconds=${MIGTD_STAGE_A_TIMEOUT_SECONDS:-90}

[[ -f "$binary" && -x "$binary" ]] || {
    echo "frozen ELF is not an executable file: $binary" >&2
    exit 2
}
[[ -f "$policy_file" ]] || {
    echo "fixture policy not found: $policy_file" >&2
    exit 2
}
[[ -f "$root_ca_file" ]] || {
    echo "fixture root CA not found: $root_ca_file" >&2
    exit 2
}

mkdir -p "$evidence_dir"
source_log="$evidence_dir/source.log"
destination_log="$evidence_dir/destination.log"
manifest="$evidence_dir/manifest.txt"
binary_hash=$(sha256sum "$binary" | awk '{print $1}')
destination_pid=
source_pid=

stop_group() {
    local pid=$1
    if [[ -n "$pid" ]] && kill -0 "$pid" 2>/dev/null; then
        kill -TERM -- "-$pid" 2>/dev/null || true
        sleep 1
        kill -KILL -- "-$pid" 2>/dev/null || true
    fi
}

cleanup() {
    stop_group "$source_pid"
    stop_group "$destination_pid"
}
trap cleanup EXIT INT TERM

run_role() {
    local role=$1
    local log=$2
    local pid_variable=$3
    setsid env \
        MIGTD_POLICY_FILE="$policy_file" \
        MIGTD_ROOT_CA_FILE="$root_ca_file" \
        timeout --signal=TERM --kill-after=5s "${timeout_seconds}s" \
        "$binary" \
        --process standalone \
        --autostart \
        --role "$role" \
        --peer-address "$peer_address" >"$log" 2>&1 &
    printf -v "$pid_variable" '%s' "$!"
}

run_role destination "$destination_log" destination_pid
for ((attempt = 0; attempt < 200; attempt++)); do
    if grep -q "PEER_CHANNEL_LISTENING" "$destination_log" 2>/dev/null; then
        break
    fi
    if ! kill -0 "$destination_pid" 2>/dev/null; then
        echo "destination exited before peer-listener readiness" >&2
        wait "$destination_pid" || true
        exit 1
    fi
    sleep 0.1
done
grep -q "PEER_CHANNEL_LISTENING" "$destination_log" || {
    echo "destination peer-listener readiness timed out" >&2
    exit 1
}

run_role source "$source_log" source_pid
set +e
wait "$source_pid"
source_status=$?
wait "$destination_pid"
destination_status=$?
set -e
source_pid=
destination_pid=

final_hash=$(sha256sum "$binary" | awk '{print $1}')
[[ "$binary_hash" == "$final_hash" ]] || {
    echo "frozen ELF changed during Stage A" >&2
    exit 1
}

{
    echo "binary=$binary"
    echo "sha256=$binary_hash"
    echo "source_binary=$binary"
    echo "source_sha256=$binary_hash"
    echo "destination_binary=$binary"
    echo "destination_sha256=$binary_hash"
    echo "source_exit=$source_status"
    echo "destination_exit=$destination_status"
    echo "peer_address=$peer_address"
} >"$manifest"

[[ "$source_status" -eq 0 && "$destination_status" -eq 0 ]] || {
    echo "Stage A process failure: source=$source_status destination=$destination_status" >&2
    exit 1
}

for role in source destination; do
    log="$evidence_dir/$role.log"
    grep -q "START_MIGRATION_WORKFLOW_BEGIN: role=$role request_id=1" "$log"
    grep -q "operation=TAV_VERIFY_ATTESTATION.*result=success" "$log"
    grep -q "operation=MSG_VERIFY_REPORT.*result=success" "$log"
    grep -q "operation=MSG_KEY_REQ.*result=success" "$log"
    grep -q "operation=MSG_SET_MIGRATION_INFO.*result=success" "$log"
    grep -q "START_MIGRATION_WORKFLOW_END: result=success request_id=1" "$log"
    if grep -Eq \
        "(migration key|key_bytes|private key|MSK).*[=:][[:space:]]*([[:xdigit:]]{16,}|\[[0-9, ]{16,}\])" \
        "$log"; then
        echo "$role log appears to contain secret key material" >&2
        exit 1
    fi
done

if grep -Eq "role=unknown|request_id=0" "$source_log" "$destination_log"; then
    echo "Stage A contains unbound platform-operation trace context" >&2
    exit 1
fi

echo "Stage A passed: $binary ($binary_hash)"
