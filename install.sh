#!/bin/bash
#
# CrowdSec UniFi Suite — Interactive Installer
# One-command installer for the complete CrowdSec + UniFi security stack
#
# Usage:
#   curl -sSL https://raw.githubusercontent.com/wolffcatskyy/crowdsec-unifi-suite/main/install.sh | bash
#
# Components (on-device):
#   - CrowdSec Engine
#   - UniFi Parser Collection
#   - UniFi Bouncer (ipset firewall)
#
# Components (server/Docker):
#   - Sidecar Proxy (decision prioritization)
#   - Blocklist Import (threat feed importer)
#   - AbuseIPDB Reporter
#

INSTALLER_VERSION="1.0.0"
SELF_URL="https://raw.githubusercontent.com/wolffcatskyy/crowdsec-unifi-suite/main/install.sh"
GITHUB_BASE="https://github.com/wolffcatskyy"
GITHUB_RAW="https://raw.githubusercontent.com/wolffcatskyy"
LOG_FILE="$HOME/.crowdsec-suite-install.log"

# ─────────────────────────────────────────────────────────────────────────────
# curl | bash stdin fix — re-exec from file so `read` works
# ─────────────────────────────────────────────────────────────────────────────
if [ ! -t 0 ]; then
    TMPFILE=$(mktemp /tmp/unifi-suite-install.XXXXXX.sh)
    trap 'rm -f "$TMPFILE"' EXIT
    cat > "$TMPFILE"        # stdin is the piped script
    exec bash "$TMPFILE" "$@" </dev/tty
fi

# ─────────────────────────────────────────────────────────────────────────────
# Colors & Symbols
# ─────────────────────────────────────────────────────────────────────────────
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
CYAN='\033[0;36m'
BOLD='\033[1m'
DIM='\033[2m'
NC='\033[0m'

SYM_OK="${GREEN}✓${NC}"
SYM_FAIL="${RED}✗${NC}"
SYM_PARTIAL="${YELLOW}~${NC}"
SYM_ARROW="${CYAN}→${NC}"

# ─────────────────────────────────────────────────────────────────────────────
# Logging
# ─────────────────────────────────────────────────────────────────────────────
log() { echo "[$(date '+%Y-%m-%d %H:%M:%S')] $*" >> "$LOG_FILE"; }
msg()  { echo -e "$*"; }
info() { msg "  ${BLUE}INFO${NC}  $*"; log "INFO: $*"; }
ok()   { msg "  ${SYM_OK}  $*"; log "OK: $*"; }
warn() { msg "  ${YELLOW}WARN${NC}  $*"; log "WARN: $*"; }
err()  { msg "  ${SYM_FAIL}  $*"; log "ERROR: $*"; }

# Single-keypress read helper — always reads from /dev/tty
readkey() {
    local _var=$1
    read -n 1 -s "$_var" </dev/tty
    echo
}

# Prompt with retry/skip/abort on failure
retry_prompt() {
    local what="$1"
    while true; do
        msg ""
        msg "  ${RED}$what failed${NC}"
        msg "  ${DIM}[R]etry  [S]kip  [A]bort${NC}"
        local choice
        readkey choice
        case "$choice" in
            r|R) return 0 ;;   # caller should retry
            s|S) return 1 ;;   # caller should skip
            a|A) msg "\n  Aborted."; exit 1 ;;
            *)   ;;
        esac
    done
}

press_any_key() {
    msg ""
    msg "  ${DIM}Press any key to continue...${NC}"
    readkey _discard
}

# ─────────────────────────────────────────────────────────────────────────────
# Banner & UI helpers
# ─────────────────────────────────────────────────────────────────────────────
WIDTH=62

draw_line() {
    printf '  '
    printf '%.0s_' $(seq 1 $WIDTH)
    echo
}

banner() {
    clear
    msg ""
    msg "  ${CYAN}${BOLD}CrowdSec UniFi Suite${NC} ${DIM}v${INSTALLER_VERSION}${NC}"
    msg "  ${DIM}Detect → Decide → Enforce${NC}"
    draw_line
    msg ""
}

# ─────────────────────────────────────────────────────────────────────────────
# Detection (runs once at startup)
# ─────────────────────────────────────────────────────────────────────────────
IS_UNIFI=false
DEVICE_MODEL="Unknown"
DEVICE_SHORTNAME=""
DEVICE_ARCH=""
IPSET_CAP=0
HAS_DOCKER=false
HAS_CROWDSEC=false
HAS_PARSER=false
HAS_BOUNCER=false
HAS_SIDECAR=false
HAS_BLOCKLIST=false
HAS_ABUSEIPDB=false
CS_VERSION=""
BOUNCER_VERSION=""

detect_all() {
    # Architecture
    DEVICE_ARCH=$(uname -m)
    case "$DEVICE_ARCH" in
        aarch64|arm64) DEVICE_ARCH="arm64" ;;
        x86_64|amd64)  DEVICE_ARCH="amd64" ;;
        mips64)
            err "mips64 architecture not supported (USG/USG Pro)"
            err "This suite requires arm64 or amd64."
            exit 1
            ;;
    esac

    # UniFi device detection
    if [ -f /proc/ubnthal/system.info ]; then
        IS_UNIFI=true
        DEVICE_SHORTNAME=$(grep shortname /proc/ubnthal/system.info 2>/dev/null | cut -d= -f2)
    elif command -v ubnt-device-info &>/dev/null; then
        IS_UNIFI=true
        DEVICE_MODEL=$(ubnt-device-info model 2>/dev/null || echo "Unknown")
        DEVICE_SHORTNAME=$(ubnt-device-info model_short 2>/dev/null || echo "")
    elif [ -d /data/unifi-core ]; then
        IS_UNIFI=true
    fi

    # Device model from unifi-os.json
    if [ -f /etc/unifi-os/unifi-os.json ]; then
        IS_UNIFI=true
        local m
        m=$(grep -o '"model":"[^"]*"' /etc/unifi-os/unifi-os.json 2>/dev/null | cut -d'"' -f4)
        [ -n "$m" ] && DEVICE_MODEL="$m"
    fi

    # ipset capacity from model shortname
    case "$DEVICE_SHORTNAME" in
        UXGENTERPRISE|EFG) IPSET_CAP=80000 ;;
        UDMSE|UDMPRO|UCGULTRA|CGM) IPSET_CAP=50000 ;;
        UDM|UDR) IPSET_CAP=15000 ;;
        *) IPSET_CAP=0 ;;
    esac

    # Docker
    if command -v docker &>/dev/null; then
        HAS_DOCKER=true
    elif [ -x /usr/local/bin/docker ]; then
        HAS_DOCKER=true
    fi

    # CrowdSec engine
    if command -v cscli &>/dev/null; then
        HAS_CROWDSEC=true
        CS_VERSION=$(cscli version 2>/dev/null | grep -oP 'version:\s*\Kv\S+' || cscli version 2>/dev/null | head -1)
    fi

    # Parser collection
    if [ -f /etc/crowdsec/collections/unifi.yaml ] || \
       cscli collections list 2>/dev/null | grep -q "unifi"; then
        HAS_PARSER=true
    fi

    # Bouncer binary
    if [ -f /data/crowdsec-bouncer/crowdsec-firewall-bouncer ] || \
       [ -f /usr/local/bin/crowdsec-firewall-bouncer ]; then
        HAS_BOUNCER=true
        BOUNCER_VERSION=$(/data/crowdsec-bouncer/crowdsec-firewall-bouncer -version 2>/dev/null || echo "")
    fi

    # Sidecar (Docker)
    if [ "$HAS_DOCKER" = true ]; then
        if docker ps --format '{{.Names}}' 2>/dev/null | grep -q crowdsec-sidecar; then
            HAS_SIDECAR=true
        fi
        if docker ps -a --format '{{.Names}}' 2>/dev/null | grep -q crowdsec-blocklist-import; then
            HAS_BLOCKLIST=true
        fi
    fi

    # AbuseIPDB (check sidecar env)
    if [ "$HAS_SIDECAR" = true ]; then
        local env_val
        env_val=$(docker inspect crowdsec-sidecar --format '{{range .Config.Env}}{{println .}}{{end}}' 2>/dev/null | grep ABUSEIPDB_REPORT_ENABLED | cut -d= -f2)
        [ "$env_val" = "true" ] && HAS_ABUSEIPDB=true
    fi

    log "Detection: UNIFI=$IS_UNIFI MODEL=$DEVICE_MODEL ARCH=$DEVICE_ARCH DOCKER=$HAS_DOCKER CS=$HAS_CROWDSEC"
}

# ─────────────────────────────────────────────────────────────────────────────
# Status display
# ─────────────────────────────────────────────────────────────────────────────
status_icon() {
    if [ "$1" = true ]; then echo -e "$SYM_OK"; else echo -e "$SYM_FAIL"; fi
}

show_status() {
    banner
    msg "  ${BOLD}Installation Status${NC}"
    msg ""

    msg "  ${BOLD}Environment${NC}"
    if [ "$IS_UNIFI" = true ]; then
        msg "    Device     $(status_icon true) ${GREEN}UniFi${NC} ($DEVICE_MODEL)"
        [ "$IPSET_CAP" -gt 0 ] && msg "    ipset cap  ${DIM}$IPSET_CAP entries${NC}"
    else
        msg "    Device     ${DIM}Not a UniFi device${NC}"
    fi
    msg "    Arch       ${DIM}$DEVICE_ARCH${NC}"
    msg "    Docker     $(status_icon $HAS_DOCKER)"
    msg ""

    msg "  ${BOLD}On-Device Components${NC}"
    msg "    CrowdSec Engine   $(status_icon $HAS_CROWDSEC) ${DIM}${CS_VERSION}${NC}"
    msg "    UniFi Parser      $(status_icon $HAS_PARSER)"
    msg "    UniFi Bouncer     $(status_icon $HAS_BOUNCER) ${DIM}${BOUNCER_VERSION}${NC}"
    msg ""

    msg "  ${BOLD}Server Components (Docker)${NC}"
    msg "    Sidecar Proxy     $(status_icon $HAS_SIDECAR)"
    msg "    Blocklist Import  $(status_icon $HAS_BLOCKLIST)"
    msg "    AbuseIPDB Report  $(status_icon $HAS_ABUSEIPDB)"
    msg ""

    draw_line
    msg ""
    msg "  ${DIM}[R] Refresh   [B] Back${NC}"

    local choice
    readkey choice
    case "$choice" in
        r|R) detect_all; show_status ;;
        *)   main_menu ;;
    esac
}

# ─────────────────────────────────────────────────────────────────────────────
# Install: CrowdSec Engine
# ─────────────────────────────────────────────────────────────────────────────
install_crowdsec() {
    if [ "$HAS_CROWDSEC" = true ]; then
        ok "CrowdSec already installed ($CS_VERSION)"
        return 0
    fi

    info "Installing CrowdSec Engine..."
    log "Installing CrowdSec via official installer"

    if curl -s https://install.crowdsec.net | bash >> "$LOG_FILE" 2>&1; then
        ok "CrowdSec Engine installed"
        HAS_CROWDSEC=true
        CS_VERSION=$(cscli version 2>/dev/null | grep -oP 'version:\s*\Kv\S+' || echo "installed")
        return 0
    else
        return 1
    fi
}

# ─────────────────────────────────────────────────────────────────────────────
# Install: UniFi Parser
# ─────────────────────────────────────────────────────────────────────────────
install_parser() {
    if [ "$HAS_PARSER" = true ]; then
        ok "UniFi Parser already installed"
        return 0
    fi

    if [ "$HAS_CROWDSEC" != true ]; then
        err "CrowdSec Engine required — install it first"
        return 1
    fi

    info "Installing UniFi Parser Collection..."
    log "Installing parser from crowdsec-unifi-parser repo"

    local tmpdir
    tmpdir=$(mktemp -d /tmp/unifi-parser.XXXXXX)
    trap "rm -rf '$tmpdir'" RETURN

    if curl -sSL "${GITHUB_RAW}/crowdsec-unifi-parser/main/install.sh" -o "$tmpdir/install.sh" && \
       bash "$tmpdir/install.sh" >> "$LOG_FILE" 2>&1; then
        ok "UniFi Parser Collection installed"
        HAS_PARSER=true
        return 0
    else
        return 1
    fi
}

# ─────────────────────────────────────────────────────────────────────────────
# Install: UniFi Bouncer
# ─────────────────────────────────────────────────────────────────────────────
install_bouncer() {
    if [ "$HAS_BOUNCER" = true ]; then
        ok "UniFi Bouncer already installed"
        return 0
    fi

    info "Installing UniFi Bouncer..."
    log "Installing bouncer from crowdsec-unifi-bouncer repo"

    local tmpdir
    tmpdir=$(mktemp -d /tmp/unifi-bouncer.XXXXXX)
    trap "rm -rf '$tmpdir'" RETURN

    if curl -sSL "${GITHUB_RAW}/crowdsec-unifi-bouncer/main/bootstrap.sh" -o "$tmpdir/bootstrap.sh" && \
       bash "$tmpdir/bootstrap.sh" >> "$LOG_FILE" 2>&1; then
        ok "UniFi Bouncer installed"
        HAS_BOUNCER=true
    else
        return 1
    fi

    # Configure LAPI connection
    msg ""
    msg "  ${BOLD}Bouncer LAPI Configuration${NC}"
    msg ""

    local lapi_url lapi_key
    msg "  Enter CrowdSec LAPI URL"
    msg "  ${DIM}(default: http://192.168.1.1:8080/)${NC}"
    printf "  > "
    read -r lapi_url </dev/tty
    lapi_url="${lapi_url:-http://192.168.1.1:8080/}"

    msg ""
    msg "  Enter Bouncer API Key"
    msg "  ${DIM}(from: cscli bouncers add unifi-bouncer)${NC}"
    printf "  > "
    read -r lapi_key </dev/tty

    if [ -z "$lapi_key" ]; then
        warn "No API key provided — configure manually later"
        warn "Edit: /data/crowdsec-bouncer/crowdsec-firewall-bouncer.yaml"
        return 0
    fi

    local cfg="/data/crowdsec-bouncer/crowdsec-firewall-bouncer.yaml"
    if [ -f "$cfg" ]; then
        sed -i "s|api_url:.*|api_url: $lapi_url|" "$cfg"
        sed -i "s|api_key:.*|api_key: $lapi_key|" "$cfg"
        ok "Bouncer configured: $lapi_url"
    else
        warn "Config file not found at $cfg"
        warn "Set api_url and api_key manually after install"
    fi

    return 0
}

# ─────────────────────────────────────────────────────────────────────────────
# Install: Sidecar Proxy (Docker)
# ─────────────────────────────────────────────────────────────────────────────
install_sidecar() {
    if [ "$HAS_SIDECAR" = true ]; then
        ok "Sidecar Proxy already running"
        return 0
    fi

    if [ "$HAS_DOCKER" != true ]; then
        err "Docker required for Sidecar Proxy"
        return 1
    fi

    info "Installing Sidecar Proxy..."

    # Select device tier
    msg ""
    msg "  ${BOLD}Select your UniFi device tier:${NC}"
    msg ""
    msg "  ${CYAN}[1]${NC} Enterprise ${DIM}(EFG/UXG-Enterprise)${NC}  — 80,000"
    msg "  ${CYAN}[2]${NC} Pro ${DIM}(UDM-SE/UDM-Pro/UCG-Ultra)${NC} — 50,000"
    msg "  ${CYAN}[3]${NC} Consumer ${DIM}(UDM/UDR)${NC}              — 15,000"
    msg "  ${CYAN}[4]${NC} Custom"
    msg ""

    local tier_choice max_decisions
    readkey tier_choice
    case "$tier_choice" in
        1) max_decisions=75000 ;;
        2) max_decisions=45000 ;;
        3) max_decisions=13000 ;;
        4)
            printf "  Enter max decisions: "
            read -r max_decisions </dev/tty
            ;;
        *) max_decisions=45000 ;;
    esac

    # Get bouncer API key
    msg ""
    msg "  Enter Sidecar Bouncer API Key"
    msg "  ${DIM}(from: docker exec crowdsec cscli bouncers add crowdsec-sidecar)${NC}"
    printf "  > "
    read -r sidecar_key </dev/tty

    if [ -z "$sidecar_key" ]; then
        warn "No API key — using placeholder. Edit .env after install."
        sidecar_key="YOUR_BOUNCER_KEY"
    fi

    # Download compose & config
    local install_dir="${CROWDSEC_SUITE_DIR:-/opt/crowdsec-suite}"
    mkdir -p "$install_dir"

    info "Downloading stack configuration to $install_dir..."

    curl -sSL "${GITHUB_RAW}/crowdsec-unifi-suite/main/docker-compose.yml" -o "$install_dir/docker-compose.yml" && \
    curl -sSL "${GITHUB_RAW}/crowdsec-unifi-suite/main/sidecar-config.yaml" -o "$install_dir/sidecar-config.yaml" && \
    curl -sSL "${GITHUB_RAW}/crowdsec-unifi-suite/main/.env.example" -o "$install_dir/.env"

    # Patch max_decisions in sidecar config
    sed -i "s/max_decisions:.*/max_decisions: $max_decisions/" "$install_dir/sidecar-config.yaml"

    # Patch bouncer key in sidecar config
    sed -i "s/upstream_lapi_key:.*/upstream_lapi_key: \"$sidecar_key\"/" "$install_dir/sidecar-config.yaml"

    # Patch .env
    sed -i "s/BOUNCER_API_KEY=.*/BOUNCER_API_KEY=$sidecar_key/" "$install_dir/.env"

    # Start only sidecar (user may already have crowdsec running)
    msg ""
    msg "  ${DIM}Starting sidecar...${NC}"
    if (cd "$install_dir" && docker compose up -d crowdsec-sidecar) >> "$LOG_FILE" 2>&1; then
        ok "Sidecar Proxy running on port 8084"
        ok "Max decisions: $max_decisions"
        HAS_SIDECAR=true
        return 0
    else
        return 1
    fi
}

# ─────────────────────────────────────────────────────────────────────────────
# Install: Blocklist Import (Docker)
# ─────────────────────────────────────────────────────────────────────────────
install_blocklist() {
    if [ "$HAS_BLOCKLIST" = true ]; then
        ok "Blocklist Import already installed"
        return 0
    fi

    if [ "$HAS_DOCKER" != true ]; then
        err "Docker required for Blocklist Import"
        return 1
    fi

    info "Installing Blocklist Import..."

    # Check if we already have the compose file (from sidecar install)
    local install_dir="${CROWDSEC_SUITE_DIR:-/opt/crowdsec-suite}"
    if [ ! -f "$install_dir/docker-compose.yml" ]; then
        mkdir -p "$install_dir"
        curl -sSL "${GITHUB_RAW}/crowdsec-unifi-suite/main/docker-compose.yml" -o "$install_dir/docker-compose.yml"
        curl -sSL "${GITHUB_RAW}/crowdsec-unifi-suite/main/.env.example" -o "$install_dir/.env"
    fi

    # Machine credentials
    msg ""
    msg "  ${BOLD}Blocklist Import Credentials${NC}"
    msg ""
    msg "  Machine password for blocklist-import"
    msg "  ${DIM}(from: cscli machines add blocklist-import --password 'xxx')${NC}"
    printf "  > "
    read -r bl_password </dev/tty

    msg ""
    msg "  Bouncer key for deduplication"
    msg "  ${DIM}(from: cscli bouncers add blocklist-import)${NC}"
    printf "  > "
    read -r bl_bouncer_key </dev/tty

    [ -n "$bl_password" ] && sed -i "s/BLOCKLIST_MACHINE_PASSWORD=.*/BLOCKLIST_MACHINE_PASSWORD=$bl_password/" "$install_dir/.env"
    [ -n "$bl_bouncer_key" ] && sed -i "s/BLOCKLIST_BOUNCER_KEY=.*/BLOCKLIST_BOUNCER_KEY=$bl_bouncer_key/" "$install_dir/.env"

    if (cd "$install_dir" && docker compose up -d blocklist-import) >> "$LOG_FILE" 2>&1; then
        ok "Blocklist Import running (hourly refresh)"
        HAS_BLOCKLIST=true
        return 0
    else
        return 1
    fi
}

# ─────────────────────────────────────────────────────────────────────────────
# Install: AbuseIPDB Reporter (toggle on sidecar)
# ─────────────────────────────────────────────────────────────────────────────
install_abuseipdb() {
    if [ "$HAS_ABUSEIPDB" = true ]; then
        ok "AbuseIPDB reporting already enabled"
        return 0
    fi

    if [ "$HAS_SIDECAR" != true ]; then
        err "Sidecar Proxy required — install it first"
        return 1
    fi

    msg ""
    msg "  Enter AbuseIPDB API Key"
    msg "  ${DIM}(free at https://www.abuseipdb.com/)${NC}"
    printf "  > "
    read -r abuse_key </dev/tty

    if [ -z "$abuse_key" ]; then
        warn "No API key provided — skipping"
        return 1
    fi

    local install_dir="${CROWDSEC_SUITE_DIR:-/opt/crowdsec-suite}"
    if [ -f "$install_dir/.env" ]; then
        sed -i "s/ABUSEIPDB_API_KEY=.*/ABUSEIPDB_API_KEY=$abuse_key/" "$install_dir/.env"
        sed -i "s/ABUSEIPDB_REPORT_ENABLED=.*/ABUSEIPDB_REPORT_ENABLED=true/" "$install_dir/.env"

        if (cd "$install_dir" && docker compose up -d crowdsec-sidecar) >> "$LOG_FILE" 2>&1; then
            ok "AbuseIPDB reporting enabled"
            HAS_ABUSEIPDB=true
            return 0
        else
            return 1
        fi
    else
        err "Suite .env not found — install sidecar first"
        return 1
    fi
}

# ─────────────────────────────────────────────────────────────────────────────
# Install orchestrator — run with retry/skip/abort
# ─────────────────────────────────────────────────────────────────────────────
run_install() {
    local func="$1" label="$2"
    while true; do
        if "$func"; then
            return 0
        else
            retry_prompt "$label" || return 1   # skip
            # loop = retry
        fi
    done
}

# ─────────────────────────────────────────────────────────────────────────────
# Full Suite Install
# ─────────────────────────────────────────────────────────────────────────────
install_full_suite() {
    banner
    msg "  ${BOLD}Full Suite Installation${NC}"
    msg ""

    if [ "$IS_UNIFI" = true ]; then
        msg "  ${SYM_ARROW} UniFi device detected — installing on-device components"
        msg ""
        run_install install_crowdsec  "CrowdSec Engine"
        run_install install_parser    "UniFi Parser"
        run_install install_bouncer   "UniFi Bouncer"
    else
        msg "  ${SYM_ARROW} Server detected — installing Docker components"
        msg ""
    fi

    if [ "$HAS_DOCKER" = true ]; then
        run_install install_sidecar   "Sidecar Proxy"
        run_install install_blocklist "Blocklist Import"

        msg ""
        msg "  ${DIM}Enable AbuseIPDB reporting? [y/N]${NC}"
        local choice
        readkey choice
        [ "$choice" = "y" ] || [ "$choice" = "Y" ] && run_install install_abuseipdb "AbuseIPDB"
    fi

    msg ""
    draw_line
    msg ""
    msg "  ${GREEN}${BOLD}Installation complete!${NC}"
    msg ""
    detect_all
    show_status_inline
    press_any_key
}

# Compact status (no menu, for post-install)
show_status_inline() {
    msg "  CrowdSec Engine   $(status_icon $HAS_CROWDSEC) ${DIM}${CS_VERSION}${NC}"
    msg "  UniFi Parser      $(status_icon $HAS_PARSER)"
    msg "  UniFi Bouncer     $(status_icon $HAS_BOUNCER)"
    msg "  Sidecar Proxy     $(status_icon $HAS_SIDECAR)"
    msg "  Blocklist Import  $(status_icon $HAS_BLOCKLIST)"
    msg "  AbuseIPDB Report  $(status_icon $HAS_ABUSEIPDB)"
}

# ─────────────────────────────────────────────────────────────────────────────
# Individual Component Menu
# ─────────────────────────────────────────────────────────────────────────────
individual_menu() {
    banner
    msg "  ${BOLD}Install Individual Components${NC}"
    msg ""

    if [ "$IS_UNIFI" = true ]; then
        msg "  ${DIM}On-Device (UniFi):${NC}"
        msg "  ${CYAN}[1]${NC} CrowdSec Engine         $(status_icon $HAS_CROWDSEC)"
        msg "  ${CYAN}[2]${NC} UniFi Parser Collection  $(status_icon $HAS_PARSER)"
        msg "  ${CYAN}[3]${NC} UniFi Bouncer            $(status_icon $HAS_BOUNCER)"
        msg ""
    fi

    if [ "$HAS_DOCKER" = true ]; then
        msg "  ${DIM}Server (Docker):${NC}"
        msg "  ${CYAN}[4]${NC} Sidecar Proxy            $(status_icon $HAS_SIDECAR)"
        msg "  ${CYAN}[5]${NC} Blocklist Import         $(status_icon $HAS_BLOCKLIST)"
        msg "  ${CYAN}[6]${NC} AbuseIPDB Reporter       $(status_icon $HAS_ABUSEIPDB)"
        msg ""
    fi

    msg "  ${DIM}[B] Back${NC}"
    msg ""

    local choice
    readkey choice
    case "$choice" in
        1) run_install install_crowdsec  "CrowdSec Engine";  press_any_key; individual_menu ;;
        2) run_install install_parser    "UniFi Parser";     press_any_key; individual_menu ;;
        3) run_install install_bouncer   "UniFi Bouncer";    press_any_key; individual_menu ;;
        4) run_install install_sidecar   "Sidecar Proxy";    press_any_key; individual_menu ;;
        5) run_install install_blocklist "Blocklist Import"; press_any_key; individual_menu ;;
        6) run_install install_abuseipdb "AbuseIPDB";        press_any_key; individual_menu ;;
        b|B|*) main_menu ;;
    esac
}

# ─────────────────────────────────────────────────────────────────────────────
# Update Components
# ─────────────────────────────────────────────────────────────────────────────
update_menu() {
    banner
    msg "  ${BOLD}Update Components${NC}"
    msg ""

    if [ "$IS_UNIFI" = true ]; then
        msg "  ${CYAN}[1]${NC} Update Bouncer         ${DIM}(re-run bootstrap)${NC}"
        msg "  ${CYAN}[2]${NC} Update Parser          ${DIM}(re-run installer)${NC}"
    fi
    if [ "$HAS_DOCKER" = true ]; then
        msg "  ${CYAN}[3]${NC} Update Docker Stack    ${DIM}(docker compose pull)${NC}"
    fi
    msg "  ${CYAN}[A]${NC} Update All"
    msg ""
    msg "  ${DIM}[B] Back${NC}"
    msg ""

    local choice
    readkey choice
    case "$choice" in
        1)
            info "Updating Bouncer..."
            HAS_BOUNCER=false
            run_install install_bouncer "Bouncer Update"
            press_any_key
            update_menu
            ;;
        2)
            info "Updating Parser..."
            HAS_PARSER=false
            run_install install_parser "Parser Update"
            press_any_key
            update_menu
            ;;
        3)
            update_docker_stack
            press_any_key
            update_menu
            ;;
        a|A)
            info "Updating all components..."
            [ "$IS_UNIFI" = true ] && {
                HAS_BOUNCER=false; run_install install_bouncer "Bouncer"
                HAS_PARSER=false;  run_install install_parser  "Parser"
            }
            [ "$HAS_DOCKER" = true ] && update_docker_stack
            ok "All updates complete"
            press_any_key
            update_menu
            ;;
        b|B|*) main_menu ;;
    esac
}

update_docker_stack() {
    local install_dir="${CROWDSEC_SUITE_DIR:-/opt/crowdsec-suite}"
    if [ ! -f "$install_dir/docker-compose.yml" ]; then
        err "Docker stack not found at $install_dir"
        return 1
    fi

    info "Pulling latest images..."
    if (cd "$install_dir" && docker compose pull && docker compose up -d) >> "$LOG_FILE" 2>&1; then
        ok "Docker stack updated"
        return 0
    else
        err "Docker stack update failed — check $LOG_FILE"
        return 1
    fi
}

# ─────────────────────────────────────────────────────────────────────────────
# Uninstall Components
# ─────────────────────────────────────────────────────────────────────────────
uninstall_menu() {
    banner
    msg "  ${BOLD}Uninstall Components${NC}"
    msg ""
    msg "  ${RED}${BOLD}Warning:${NC} ${DIM}This will remove selected components${NC}"
    msg ""

    msg "  ${CYAN}[1]${NC} Uninstall Bouncer      $(status_icon $HAS_BOUNCER)"
    msg "  ${CYAN}[2]${NC} Uninstall Parser       $(status_icon $HAS_PARSER)"
    if [ "$HAS_DOCKER" = true ]; then
        msg "  ${CYAN}[3]${NC} Uninstall Docker Stack $(status_icon $HAS_SIDECAR)"
    fi
    msg "  ${CYAN}[9]${NC} Uninstall Everything"
    msg ""
    msg "  ${DIM}[B] Back${NC}"
    msg ""

    local choice
    readkey choice
    case "$choice" in
        1) uninstall_bouncer;  press_any_key; uninstall_menu ;;
        2) uninstall_parser;   press_any_key; uninstall_menu ;;
        3) uninstall_docker;   press_any_key; uninstall_menu ;;
        9)
            msg ""
            msg "  ${RED}Uninstall ALL components? [y/N]${NC}"
            local confirm
            readkey confirm
            if [ "$confirm" = "y" ] || [ "$confirm" = "Y" ]; then
                uninstall_bouncer
                uninstall_parser
                [ "$HAS_DOCKER" = true ] && uninstall_docker
                ok "All components removed"
            fi
            press_any_key
            uninstall_menu
            ;;
        b|B|*) main_menu ;;
    esac
}

uninstall_bouncer() {
    if [ "$HAS_BOUNCER" != true ]; then
        warn "Bouncer not installed"
        return 0
    fi

    info "Stopping bouncer service..."

    # Stop service
    if [ -f /etc/init.d/crowdsec-firewall-bouncer ]; then
        /etc/init.d/crowdsec-firewall-bouncer stop 2>/dev/null
    fi

    # Remove binary and config
    rm -f /data/crowdsec-bouncer/crowdsec-firewall-bouncer 2>/dev/null
    rm -f /usr/local/bin/crowdsec-firewall-bouncer 2>/dev/null

    # Destroy ipsets
    for set in crowdsec-blacklists crowdsec6-blacklists; do
        ipset destroy "$set" 2>/dev/null
    done

    # Clean cron
    if [ -f /etc/crontabs/root ]; then
        sed -i '/crowdsec/d' /etc/crontabs/root 2>/dev/null
    fi

    HAS_BOUNCER=false
    ok "Bouncer uninstalled"
}

uninstall_parser() {
    if [ "$HAS_PARSER" != true ]; then
        warn "Parser not installed"
        return 0
    fi

    info "Removing UniFi Parser Collection..."
    if command -v cscli &>/dev/null; then
        cscli collections remove wolffcatskyy/unifi 2>/dev/null || true
    fi
    rm -f /etc/crowdsec/collections/unifi.yaml 2>/dev/null

    HAS_PARSER=false
    ok "Parser collection removed"
}

uninstall_docker() {
    local install_dir="${CROWDSEC_SUITE_DIR:-/opt/crowdsec-suite}"
    if [ ! -f "$install_dir/docker-compose.yml" ]; then
        warn "Docker stack not found"
        return 0
    fi

    info "Stopping Docker stack..."
    (cd "$install_dir" && docker compose down) >> "$LOG_FILE" 2>&1

    msg "  ${DIM}Remove configuration files? [y/N]${NC}"
    local choice
    readkey choice
    if [ "$choice" = "y" ] || [ "$choice" = "Y" ]; then
        rm -rf "$install_dir"
        ok "Configuration removed"
    fi

    HAS_SIDECAR=false
    HAS_BLOCKLIST=false
    HAS_ABUSEIPDB=false
    ok "Docker stack stopped"
}

# ─────────────────────────────────────────────────────────────────────────────
# Main Menu
# ─────────────────────────────────────────────────────────────────────────────
main_menu() {
    banner

    if [ "$IS_UNIFI" = true ]; then
        msg "  ${DIM}UniFi Device: $DEVICE_MODEL ($DEVICE_ARCH)${NC}"
    else
        msg "  ${DIM}Server: $(hostname) ($DEVICE_ARCH)${NC}"
    fi
    msg ""

    msg "  ${CYAN}[1]${NC} Install Full Suite ${DIM}(recommended)${NC}"
    msg "  ${CYAN}[2]${NC} Install Individual Components"
    msg "  ${CYAN}[3]${NC} Check Installation Status"
    msg "  ${CYAN}[4]${NC} Update Components"
    msg "  ${CYAN}[5]${NC} Uninstall Components"
    msg ""
    msg "  ${CYAN}[0]${NC} Exit"
    msg ""
    draw_line
    msg ""

    local choice
    readkey choice
    case "$choice" in
        1) install_full_suite ;;
        2) individual_menu ;;
        3) show_status ;;
        4) update_menu ;;
        5) uninstall_menu ;;
        0) msg "\n  ${DIM}Goodbye.${NC}\n"; exit 0 ;;
        *) main_menu ;;
    esac
}

# ─────────────────────────────────────────────────────────────────────────────
# Entrypoint
# ─────────────────────────────────────────────────────────────────────────────
main() {
    # Initialize log
    echo "=== CrowdSec UniFi Suite Installer v${INSTALLER_VERSION} — $(date) ===" >> "$LOG_FILE"

    # Root check (warn, don't block — some operations work without root)
    if [ "$(id -u)" -ne 0 ]; then
        echo ""
        echo -e "  ${YELLOW}WARN${NC}  Not running as root — some operations may fail"
        echo -e "  ${DIM}Tip: curl -sSL ... | sudo bash${NC}"
        echo ""
        echo -e "  ${DIM}Continue anyway? [y/N]${NC}"
        local choice
        readkey choice
        if [ "$choice" != "y" ] && [ "$choice" != "Y" ]; then
            exit 1
        fi
    fi

    # Detect everything
    detect_all

    # Show menu
    main_menu
}

main "$@"
