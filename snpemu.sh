#!/bin/bash

# MigTD SnpEmu Runner Script
# Builds and runs MigTD in AMD SNP Emulator mode (SnpEmu feature).
# No TDX hardware, no TPM, no Azure CVM required — runs on any Linux machine.
#
# SnpEmu uses real TAV (tee-attestation-verification-lib) certificate chain
# verification (ASK→VCEK) with fixture data; ARK is TAV's pinned Milan ARK from src/snp_emu/src/fixture_data/.
# Use --skip-ra to bypass attestation entirely for quick connectivity tests.

set -e

ulimit -c unlimited || true

# Build environment required for SnpEmu (openssl-sys builds from source)
export AS=nasm
export AR=ar
export CC=gcc
export OPENSSL_NO_VENDOR=1

# Defaults
DEFAULT_ROLE="source"
DEFAULT_REQUEST_ID="1"
DEFAULT_DEST_IP="127.0.0.1"
DEFAULT_DEST_PORT="8001"
DEFAULT_BUILD_MODE="debug"

ROLE="$DEFAULT_ROLE"
REQUEST_ID="$DEFAULT_REQUEST_ID"
DEST_IP="$DEFAULT_DEST_IP"
DEST_PORT="$DEFAULT_DEST_PORT"
BUILD_MODE="$DEFAULT_BUILD_MODE"
SKIP_RA=false
RUN_BOTH=false
EXTRA_FEATURES=""
CUSTOM_LOG_LEVEL=""

# Colors
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m'

show_usage() {
    echo -e "${BLUE}MigTD SnpEmu Runner Script${NC}"
    echo
    echo "Usage: $0 [OPTIONS]"
    echo
    echo "Options:"
    echo "  -r, --role ROLE         Set role as 'source' or 'destination' (default: source)"
    echo "  -i, --request-id ID     Set migration request ID (default: 1)"
    echo "  -d, --dest-ip IP        Set destination IP address (default: 127.0.0.1)"
    echo "  -p, --dest-port PORT    Set destination port (default: 8001)"
    echo "  --debug                 Build in debug mode (default)"
    echo "  --release               Build in release mode"
    echo "  --skip-ra               Skip remote attestation entirely (no TAV cert chain check)"
    echo "  --features FEATURES     Add extra cargo features (comma-separated)"
    echo "  --log-level LEVEL       Set Rust log level (trace, debug, info, warn, error)"
    echo "                          Default: debug for debug builds, info for release builds"
    echo "  --both                  Start destination first, then source (localhost only)"
    echo "  -h, --help              Show this help message"
    echo
    echo "Attestation modes:"
    echo "  (default)    Real TAV verification: ASK→VCEK chain + report signature (ARK pinned in TAV)"
    echo "               Uses fixture data from src/snp_emu/src/fixture_data/ (Milan/Genoa/Turin)"
    echo "  --skip-ra    Bypass all attestation — SPDM session only, accept-all policy"
    echo
    echo "Build environment (auto-set):"
    echo "  AS=nasm  AR=ar  CC=gcc  OPENSSL_NO_VENDOR=1"
    echo
    echo "Examples:"
    echo "  $0 --both                          # Build debug + run source+destination (full TAV)"
    echo "  $0 --skip-ra --both                # Build debug + run source+destination (no attestation)"
    echo "  $0 --role destination              # Run destination only (full TAV)"
    echo "  $0 --role source --dest-ip 10.0.0.2   # Run source to remote destination"
    echo "  $0 --release --both                # Build release + run both"
    echo "  $0 --skip-ra --debug --log-level trace --both   # Trace logging, no attestation"
    echo "  $0 --features extra_feat --both    # Add extra cargo features"
}

# Build the cargo features string
build_features_string() {
    local features="SnpEmu"

    if [[ "$SKIP_RA" == true ]]; then
        features="$features,test_disable_ra_and_accept_all"
    fi

    if [[ -n "$EXTRA_FEATURES" ]]; then
        features="$features,$EXTRA_FEATURES"
    fi

    echo "$features"
}

# Build MigTD
build_migtd() {
    local build_mode="$1"
    local features="$2"

    echo -e "${BLUE}Building MigTD (SnpEmu) in $build_mode mode with features: $features${NC}"
    echo -e "${BLUE}  AS=$AS  AR=$AR  CC=$CC  OPENSSL_NO_VENDOR=$OPENSSL_NO_VENDOR${NC}"

    if [[ "$build_mode" == "debug" ]]; then
        if ! cargo build --no-default-features --features "$features"; then
            echo -e "${RED}Error: Build failed${NC}" >&2
            exit 1
        fi
    else
        if ! cargo build --release --no-default-features --features "$features"; then
            echo -e "${RED}Error: Build failed${NC}" >&2
            exit 1
        fi
    fi
    echo -e "${GREEN}Build completed successfully${NC}"
}

# Build the migtd run command args
build_run_args() {
    local role="$1"
    local req_id="$2"
    local args=("--role" "$role" "--request-id" "$req_id")

    if [[ "$role" == "source" ]]; then
        args+=("--dest-ip" "$DEST_IP" "--dest-port" "$DEST_PORT")
    fi

    echo "${args[@]}"
}

# Resolve log level
resolve_log_level() {
    if [[ -n "$CUSTOM_LOG_LEVEL" ]]; then
        echo "$CUSTOM_LOG_LEVEL"
    elif [[ "$BUILD_MODE" == "debug" ]]; then
        echo "debug"
    else
        echo "info"
    fi
}

# Parse arguments
while [[ $# -gt 0 ]]; do
    case $1 in
        -r|--role)
            ROLE="$2"; shift 2 ;;
        -i|--request-id)
            REQUEST_ID="$2"; shift 2 ;;
        -d|--dest-ip)
            DEST_IP="$2"; shift 2 ;;
        -p|--dest-port)
            DEST_PORT="$2"; shift 2 ;;
        --debug)
            BUILD_MODE="debug"; shift ;;
        --release)
            BUILD_MODE="release"; shift ;;
        --skip-ra)
            SKIP_RA=true; shift ;;
        --both)
            RUN_BOTH=true; shift ;;
        --features)
            EXTRA_FEATURES="$2"; shift 2 ;;
        --log-level)
            CUSTOM_LOG_LEVEL="$2"; shift 2 ;;
        -h|--help)
            show_usage; exit 0 ;;
        *)
            echo -e "${RED}Unknown option: $1${NC}" >&2
            show_usage; exit 1 ;;
    esac
done

# Validate role
if [[ "$ROLE" != "source" && "$ROLE" != "destination" ]]; then
    echo -e "${RED}Error: role must be 'source' or 'destination'${NC}" >&2
    exit 1
fi

# Determine binary path
if [[ "$BUILD_MODE" == "debug" ]]; then
    MIGTD_BINARY="$(pwd)/target/debug/migtd"
else
    MIGTD_BINARY="$(pwd)/target/release/migtd"
fi

CARGO_FEATURES=$(build_features_string)
LOG_LEVEL=$(resolve_log_level)

# Print effective config
echo -e "${BLUE}SnpEmu Configuration:${NC}"
echo "  Mode:        $([ "$SKIP_RA" == true ] && echo 'skip-ra (no attestation)' || echo 'full TAV verification')"
echo "  Build:       $BUILD_MODE"
echo "  Features:    $CARGO_FEATURES"
echo "  Log level:   $LOG_LEVEL"
if [[ "$RUN_BOTH" == true ]]; then
    echo "  Running:     destination + source (localhost $DEST_IP:$DEST_PORT)"
else
    echo "  Role:        $ROLE"
    echo "  Request ID:  $REQUEST_ID"
    [[ "$ROLE" == "source" ]] && echo "  Destination: $DEST_IP:$DEST_PORT"
fi
echo

# Build
build_migtd "$BUILD_MODE" "$CARGO_FEATURES"

echo

if [[ "$RUN_BOTH" == true ]]; then
    DEST_LOG="$(pwd)/snpemu_dest.log"
    echo -e "${BLUE}Starting destination (request-id $REQUEST_ID)...${NC}"
    echo -e "  Log: $DEST_LOG"

    RUST_LOG="$LOG_LEVEL" "$MIGTD_BINARY" --role destination --request-id "$REQUEST_ID" \
        > "$DEST_LOG" 2>&1 &
    DEST_PID=$!
    echo "  PID: $DEST_PID"

    # Wait for destination to start listening
    echo -e "${YELLOW}Waiting for destination to listen on port $DEST_PORT...${NC}"
    for i in $(seq 1 20); do
        if ss -tln 2>/dev/null | grep -q ":$DEST_PORT "; then
            break
        fi
        sleep 0.5
    done

    echo -e "${BLUE}Starting source (request-id $REQUEST_ID)...${NC}"
    echo -e "  Command: RUST_LOG=$LOG_LEVEL $MIGTD_BINARY --role source --request-id $REQUEST_ID --dest-ip $DEST_IP --dest-port $DEST_PORT"
    echo

    RUST_LOG="$LOG_LEVEL" "$MIGTD_BINARY" --role source --request-id "$REQUEST_ID" \
        --dest-ip "$DEST_IP" --dest-port "$DEST_PORT"
    SRC_EXIT=$?

    # Check result
    if grep -q "SNP migration key exchange successful" "$DEST_LOG" 2>/dev/null; then
        echo -e "\n${GREEN}[DEST] SNP migration key exchange successful!${NC}"
    fi

    kill "$DEST_PID" 2>/dev/null || true

    if [[ $SRC_EXIT -ne 0 ]]; then
        echo -e "\n${RED}Source exited with error $SRC_EXIT. Destination log:${NC}"
        tail -30 "$DEST_LOG"
        exit $SRC_EXIT
    fi
else
    DST_ARGS=$(build_run_args "$ROLE" "$REQUEST_ID")
    echo -e "${BLUE}Running: RUST_LOG=$LOG_LEVEL $MIGTD_BINARY $DST_ARGS${NC}"
    echo
    # shellcheck disable=SC2086
    RUST_LOG="$LOG_LEVEL" "$MIGTD_BINARY" $DST_ARGS
fi
