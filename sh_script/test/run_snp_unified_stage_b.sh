#!/usr/bin/env bash
set -euo pipefail

if [[ $# -lt 2 || $# -gt 3 ]]; then
    echo "usage: $0 <frozen-migtd-elf> <host-wfr-test> [evidence-directory]" >&2
    exit 2
fi

binary=$(readlink -f "$1")
controller=$(readlink -f "$2")
evidence_dir=${3:-"$(pwd)/snp-stage-b-evidence"}
policy_file=${MIGTD_POLICY_FILE:?MIGTD_POLICY_FILE must name the fixture policy}
root_ca_file=${MIGTD_ROOT_CA_FILE:?MIGTD_ROOT_CA_FILE must name the fixture root CA}
source_host_address=${MIGTD_STAGE_B_SOURCE_HOST_ADDRESS:-127.0.0.1:19501}
destination_host_address=${MIGTD_STAGE_B_DESTINATION_HOST_ADDRESS:-127.0.0.1:19502}
peer_address=${MIGTD_STAGE_B_PEER_ADDRESS:-127.0.0.1:19503}
timeout_seconds=${MIGTD_STAGE_B_TIMEOUT_SECONDS:-90}

for executable in "$binary" "$controller"; do
    [[ -f "$executable" && -x "$executable" ]] || {
        echo "required executable not found: $executable" >&2
        exit 2
    }
done
for fixture in "$policy_file" "$root_ca_file"; do
    [[ -f "$fixture" ]] || {
        echo "fixture input not found: $fixture" >&2
        exit 2
    }
done
if [[ "$source_host_address" == "$peer_address" ||
      "$destination_host_address" == "$peer_address" ||
      "$source_host_address" == "$destination_host_address" ]]; then
    echo "Stage B host-control and peer addresses must be distinct" >&2
    exit 2
fi

mkdir -p "$evidence_dir"
source_log="$evidence_dir/source.log"
destination_log="$evidence_dir/destination.log"
source_controller_log="$evidence_dir/source-controller.log"
destination_controller_log="$evidence_dir/destination-controller.log"
source_ready="$evidence_dir/source-controller.ready"
destination_ready="$evidence_dir/destination-controller.ready"
source_gate="$evidence_dir/source-start.gate"
destination_gate="$evidence_dir/destination-start.gate"
rm -f "$source_ready" "$destination_ready" "$source_gate" "$destination_gate"

binary_hash=$(sha256sum "$binary" | awk '{print $1}')
controller_hash=$(sha256sum "$controller" | awk '{print $1}')
source_pid=
destination_pid=
source_controller_pid=
destination_controller_pid=

stop_group() {
    local pid=$1
    if [[ -n "$pid" ]] && kill -0 "$pid" 2>/dev/null; then
        kill -TERM -- "-$pid" 2>/dev/null || true
        sleep 1
        kill -KILL -- "-$pid" 2>/dev/null || true
    fi
}

cleanup() {
    stop_group "$source_controller_pid"
    stop_group "$destination_controller_pid"
    stop_group "$source_pid"
    stop_group "$destination_pid"
}
trap cleanup EXIT INT TERM

wait_for_log() {
    local log=$1
    local pattern=$2
    local pid=$3
    local description=$4
    for ((attempt = 0; attempt < 300; attempt++)); do
        grep -q "$pattern" "$log" 2>/dev/null && return 0
        if ! kill -0 "$pid" 2>/dev/null; then
            echo "$description process exited before readiness" >&2
            return 1
        fi
        sleep 0.1
    done
    echo "$description readiness timed out" >&2
    return 1
}

run_ma() {
    local role=$1
    local host_address=$2
    local log=$3
    local pid_variable=$4
    setsid env \
        MIGTD_POLICY_FILE="$policy_file" \
        MIGTD_ROOT_CA_FILE="$root_ca_file" \
        timeout --signal=TERM --kill-after=5s "${timeout_seconds}s" \
        "$binary" \
        --process standalone \
        --start-mode wfr \
        --role "$role" \
        --host-address "$host_address" \
        --peer-address "$peer_address" >"$log" 2>&1 &
    printf -v "$pid_variable" '%s' "$!"
}

run_controller() {
    local mode=$1
    local address=$2
    local ready_file=$3
    local gate_file=$4
    local log=$5
    local pid_variable=$6
    setsid env \
        MIGTD_WFR_GATE_TIMEOUT_SECONDS="$timeout_seconds" \
        timeout --signal=TERM --kill-after=5s "${timeout_seconds}s" \
        "$controller" "$mode" "$address" \
        --ready-file "$ready_file" \
        --start-gate "$gate_file" >"$log" 2>&1 &
    printf -v "$pid_variable" '%s' "$!"
}

run_ma destination "$destination_host_address" "$destination_log" destination_pid
wait_for_log "$destination_log" "PEER_CHANNEL_LISTENING" "$destination_pid" "destination MA"

run_controller --server "$source_host_address" "$source_ready" "$source_gate" \
    "$source_controller_log" source_controller_pid
wait_for_log "$source_controller_log" "Listening on" "$source_controller_pid" "source controller"

run_ma source "$source_host_address" "$source_log" source_pid
wait_for_log "$destination_log" "TcpTransport: bound" "$destination_pid" "destination WFR"

run_controller --client "$destination_host_address" "$destination_ready" "$destination_gate" \
    "$destination_controller_log" destination_controller_pid

for ready_file in "$source_ready" "$destination_ready"; do
    for ((attempt = 0; attempt < 300; attempt++)); do
        [[ -f "$ready_file" ]] && break
        sleep 0.1
    done
    [[ -f "$ready_file" ]] || {
        echo "WFR controller did not complete pre-migration sequence: $ready_file" >&2
        exit 1
    }
done

touch "$destination_gate"
wait_for_log "$destination_log" \
    "START_MIGRATION_WORKFLOW_BEGIN: role=destination request_id=1003" \
    "$destination_pid" "destination StartMigration"
touch "$source_gate"

set +e
wait "$source_pid"
source_status=$?
wait "$destination_pid"
destination_status=$?
wait "$source_controller_pid"
source_controller_status=$?
wait "$destination_controller_pid"
destination_controller_status=$?
set -e
source_pid=
destination_pid=
source_controller_pid=
destination_controller_pid=

final_hash=$(sha256sum "$binary" | awk '{print $1}')
[[ "$binary_hash" == "$final_hash" ]] || {
    echo "frozen ELF changed during Stage B" >&2
    exit 1
}

{
    echo "binary=$binary"
    echo "sha256=$binary_hash"
    echo "source_binary=$binary"
    echo "source_sha256=$binary_hash"
    echo "destination_binary=$binary"
    echo "destination_sha256=$binary_hash"
    echo "controller=$controller"
    echo "controller_sha256=$controller_hash"
    echo "source_exit=$source_status"
    echo "destination_exit=$destination_status"
    echo "source_controller_exit=$source_controller_status"
    echo "destination_controller_exit=$destination_controller_status"
    echo "source_host_address=$source_host_address"
    echo "destination_host_address=$destination_host_address"
    echo "peer_address=$peer_address"
} >"$evidence_dir/manifest.txt"

if [[ "$source_status" -ne 0 || "$destination_status" -ne 0 ||
      "$source_controller_status" -ne 0 || "$destination_controller_status" -ne 0 ]]; then
    echo "Stage B process failure; see $evidence_dir/manifest.txt" >&2
    exit 1
fi

for role in source destination; do
    log="$evidence_dir/$role.log"
    grep -q "RUNTIME_PROFILE: process=standalone start=wfr role=$role" "$log"
    grep -q "TcpTransport: recv opcode=0x01 request_id=1003" "$log"
    grep -q "START_MIGRATION_WORKFLOW_BEGIN: role=$role request_id=1003" "$log"
    grep -q "operation=TAV_VERIFY_ATTESTATION.*result=success" "$log"
    grep -q "operation=MSG_VERIFY_REPORT.*result=success" "$log"
    grep -q "operation=MSG_KEY_REQ.*result=success" "$log"
    grep -q "operation=MSG_SET_MIGRATION_INFO.*result=success" "$log"
    grep -q "START_MIGRATION_WORKFLOW_END: result=success request_id=1003" "$log"
    if grep -Eq \
        "(migration key|key_bytes|private key|MSK).*[=:][[:space:]]*([[:xdigit:]]{16,}|\[[0-9, ]{16,}\])" \
        "$log"; then
        echo "$role log appears to contain secret key material" >&2
        exit 1
    fi
done

grep -q "WFR sequence complete" "$source_controller_log"
grep -q "WFR sequence complete" "$destination_controller_log"
if grep -Eq "role=unknown|request_id=0" "$source_log" "$destination_log"; then
    echo "Stage B contains unbound platform-operation trace context" >&2
    exit 1
fi

echo "Stage B passed: $binary ($binary_hash)"
