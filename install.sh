#!/bin/bash
#
# CrowdSec UniFi Suite - Interactive Installer
# One-command installer for the complete CrowdSec + UniFi security stack
#
# Usage:
#   curl -sSL https://raw.githubusercontent.com/wolffcatskyy/crowdsec-unifi-suite/main/install.sh | bash
#
# Components:
#   ON UNIFI DEVICE:
#     - CrowdSec Engine
#     - UniFi Parser Collection (wolffcatskyy/unifi)
#     - UniFi Bouncer (firewall ipset enforcement)
#
#   ON SERVER (Docker):
#     - Sidecar Proxy (decision prioritization + capping)
#     - Blocklist Import (external threat feed importer)
#     - AbuseIPDB Reporter (optional abuse reporting)
#

# ---------------------------------------------------------------------------
# curl-pipe stdin fix
# When invoked via `curl | bash`, stdin is the curl stream, not the terminal.
# We save the script to a temp file and re-exec with /dev/tty as stdin.
# ---------------------------------------------------------------------------
if [ ! -t 0 ]; then
    SELF_URL="https://raw.githubusercontent.com/wolffcatskyy/crowdsec-unifi-suite/main/install.sh"
    TMPFILE=$(mktemp /tmp/unifi-suite-install.XXXXXX.sh)
    trap 'rm -f "$TMPFILE"' EXIT
    cat > "$TMPFILE"
    exec bash "$TMPFILE" "$@" </dev/tty
fi

# ---------------------------------------------------------------------------
# ANSI Colors & Formatting
# ---------------------------------------------------------------------------
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
CYAN='\033[0;36m'
BOLD='\033[1m'
DIM='\033[2m'
NC='\033[0m'

# ---------------------------------------------------------------------------
# Global Variables
# ---------------------------------------------------------------------------
VERSION="1.0.0"
GITHUB_RAW="https://raw.githubusercontent.com/wolffcatskyy"
GITHUB_BASE="https://github.com/wolffcatskyy"
LOG_FILE="$HOME/.crowdsec-suite-install.log"

# Detection results (populated by detect_environment)
IS_UNIFI=false
IS_DOCKER_HOST=false
DEVICE_MODEL=""
DEVICE_TIER=""
ARCH=""
IPSET_CAPACITY=0

# Component status
CS_INSTALLED=false
PARSER_INSTALLED=false
BOUNCER_INSTALLED=false
SIDECAR_INSTALLED=false
BLOCKLIST_INSTALLED=false
ABUSEIPDB_ENABLED=false

# ---------------------------------------------------------------------------
# Logging
# ---------------------------------------------------------------------------
log_init() {
    mkdir -p "$(dirname "$LOG_FILE")" 2>/dev/null
    echo "" >> "$LOG_FILE"
    echo "=======================================" >> "$LOG_FILE"
    echo "Session started: $(date '+%Y-%m-%d %H:%M:%S')" >> "$LOG_FILE"
    echo "=======================================" >> "$LOG_FILE"
}

log() {
    echo "[$(date '+%H:%M:%S')] $1" >> "$LOG_FILE" 2>/dev/null
}

# ---------------------------------------------------------------------------
# Display Helpers
# ---------------------------------------------------------------------------
print_line() {
    echo -e "${DIM}_______________________________________________________________${NC}"
}

print_status() {
    local label="$1"
    local status="$2"
    case "$status" in
        installed)  echo -e "  ${GREEN}+${NC} ${label}  ${GREEN}installed${NC}" ;;
        partial)    echo -e "  ${YELLOW}~${NC} ${label}  ${YELLOW}partial${NC}" ;;
        missing)    echo -e "  ${RED}-${NC} ${label}  ${DIM}not installed${NC}" ;;
        enabled)    echo -e "  ${GREEN}+${NC} ${label}  ${GREEN}enabled${NC}" ;;
        disabled)   echo -e "  ${DIM}-${NC} ${label}  ${DIM}disabled${NC}" ;;
    esac
}

msg_info() {
    echo -e "  ${BLUE}i${NC} $1"
}

msg_ok() {
    echo -e "  ${GREEN}+${NC} $1"
}

msg_warn() {
    echo -e "  ${YELLOW}!${NC} $1"
}

msg_err() {
    echo -e "  ${RED}x${NC} $1"
}

msg_dim() {
    echo -e "  ${DIM}$1${NC}"
}

press_any_key() {
    echo ""
    echo -e "  ${DIM}Press any key to continue...${NC}"
    read -n 1 -s </dev/tty
}

# Show Retry / Skip / Abort prompt on failure
# Returns: 0=retry, 1=skip, 2=abort
error_prompt() {
    local component="$1"
    echo ""
    msg_err "$component installation failed"
    echo ""
    echo -e "  ${BOLD}[R]${NC}etry  ${BOLD}[S]${NC}kip  ${BOLD}[A]${NC}bort"
    echo ""
    while true; do
        read -n 1 -s choice </dev/tty
        case "$choice" in
            r|R) return 0 ;;
            s|S) return 1 ;;
            a|A) return 2 ;;
        esac
    done
}

# ---------------------------------------------------------------------------
# Banner
# ---------------------------------------------------------------------------
show_banner() {
    clear
    echo ""
    echo -e "${CYAN}${BOLD}"
    echo "    ___                     _  ___            "
    echo "   / __\ __ _____      __ | |/ __\ ___  ___  "
    echo "  / / | '__/ _ \ \ /\ / / | / /  / _ \/ __|"
    echo " / /__| | | (_) \ V  V /  | / /__| __|  (__ "
    echo " \____/_|  \___/ \_/\_/ |___|____/\___|\___|"
    echo ""
    echo -e "            ${BLUE}U n i F i   S u i t e${NC}"
    echo ""
    echo -e "  ${DIM}v${VERSION}               Detect -> Decide -> Enforce${NC}"
    print_line
    echo ""
}

# ---------------------------------------------------------------------------
# Environment Detection
# ---------------------------------------------------------------------------
detect_environment() {
    log "Starting environment detection"

    # Architecture
    ARCH=$(uname -m)
    if [ "$ARCH" = "mips64" ]; then
        show_banner
        msg_err "USG devices (mips64) are not supported."
        msg_info "This suite requires UniFi OS 2.x+ (arm64/amd64)."
        echo ""
        exit 1
    fi
    log "Architecture: $ARCH"

    # UniFi device detection
    if [ -f /proc/ubnthal/system.info ] || command -v ubnt-device-info >/dev/null 2>&1 || [ -d /data/unifi-core ]; then
        IS_UNIFI=true
        log "UniFi device detected"
    fi

    # Device model
    if command -v ubnt-device-info >/dev/null 2>&1; then
        DEVICE_MODEL=$(ubnt-device-info model 2>/dev/null)
    elif [ -f /proc/ubnthal/system.info ]; then
        DEVICE_MODEL=$(grep -i shortname /proc/ubnthal/system.info 2>/dev/null | cut -d= -f2 | tr -d ' ')
    fi
    log "Device model: ${DEVICE_MODEL:-unknown}"

    # ipset capacity by model
    case "$DEVICE_MODEL" in
        EFG|UXG-Enterprise)
            IPSET_CAPACITY=80000; DEVICE_TIER="enterprise" ;;
        UDM-SE|UDMSE|UDM-Pro*|UDMPRO*|UDW|UCG-*|UXG-*)
            IPSET_CAPACITY=50000; DEVICE_TIER="pro" ;;
        UDM|UDR|UDR7|UX7)
            IPSET_CAPACITY=15000; DEVICE_TIER="consumer" ;;
        *)
            IPSET_CAPACITY=10000; DEVICE_TIER="unknown" ;;
    esac
    log "Device tier: $DEVICE_TIER, ipset capacity: $IPSET_CAPACITY"

    # Docker host detection
    if command -v docker >/dev/null 2>&1; then
        if docker info >/dev/null 2>&1; then
            IS_DOCKER_HOST=true
            log "Docker available"
        fi
    fi

    # Component detection
    if command -v cscli >/dev/null 2>&1; then
        CS_INSTALLED=true
        log "CrowdSec engine found"
    fi

    if [ -f /etc/crowdsec/hub/collections/wolffcatskyy/unifi.yaml ] || \
       cscli collections list 2>/dev/null | grep -q "wolffcatskyy/unifi"; then
        PARSER_INSTALLED=true
        log "UniFi parser collection found"
    fi

    if [ -f /data/crowdsec-bouncer/crowdsec-firewall-bouncer ]; then
        BOUNCER_INSTALLED=true
        log "UniFi bouncer found"
    fi

    if docker ps 2>/dev/null | grep -q crowdsec-sidecar; then
        SIDECAR_INSTALLED=true
        log "Sidecar proxy running"
    fi

    if docker ps -a 2>/dev/null | grep -q crowdsec-blocklist-import; then
        BLOCKLIST_INSTALLED=true
        log "Blocklist import found"
    fi

    # AbuseIPDB check
    if [ "$SIDECAR_INSTALLED" = true ]; then
        if docker inspect crowdsec-sidecar 2>/dev/null | grep -q '"ABUSEIPDB_REPORT_ENABLED=true"'; then
            ABUSEIPDB_ENABLED=true
            log "AbuseIPDB reporting enabled"
        fi
    fi
}

# ---------------------------------------------------------------------------
# Root Check
# ---------------------------------------------------------------------------
check_root() {
    if [ "$(id -u)" -ne 0 ]; then
        msg_err "This installer must be run as root."
        msg_info "Try: sudo bash install.sh"
        echo ""
        exit 1
    fi
}

# ---------------------------------------------------------------------------
# Main Menu
# ---------------------------------------------------------------------------
show_main_menu() {
    echo -e "  ${BOLD}Main Menu${NC}"
    echo ""
    echo -e "  ${BOLD}[1]${NC}  Install Full Suite  ${DIM}(recommended)${NC}"
    echo -e "  ${BOLD}[2]${NC}  Install Individual Components"
    echo -e "  ${BOLD}[3]${NC}  Check Installation Status"
    echo -e "  ${BOLD}[4]${NC}  Update Components"
    echo -e "  ${BOLD}[5]${NC}  Uninstall Components"
    echo ""
    print_line
    echo -e "  ${BOLD}[0]${NC}  Exit"
    echo ""

    read -n 1 -s choice </dev/tty
    case "$choice" in
        1) install_full_suite ;;
        2) show_components_menu ;;
        3) show_status_screen ;;
        4) show_update_menu ;;
        5) show_uninstall_menu ;;
        0|q) clear; exit 0 ;;
        *) ;;
    esac
}

# ---------------------------------------------------------------------------
# Components Menu (context-aware)
# ---------------------------------------------------------------------------
show_components_menu() {
    show_banner
    echo -e "  ${BOLD}Install Individual Components${NC}"
    echo ""

    if [ "$IS_UNIFI" = true ]; then
        echo -e "  ${DIM}-- UniFi Device Components --${NC}"
        echo -e "  ${BOLD}[1]${NC}  CrowdSec Engine"
        echo -e "  ${BOLD}[2]${NC}  UniFi Parser Collection"
        echo -e "  ${BOLD}[3]${NC}  UniFi Bouncer"
        echo ""
    fi

    if [ "$IS_DOCKER_HOST" = true ]; then
        echo -e "  ${DIM}-- Server Components (Docker) --${NC}"
        echo -e "  ${BOLD}[4]${NC}  Sidecar Proxy"
        echo -e "  ${BOLD}[5]${NC}  Blocklist Import"
        echo -e "  ${BOLD}[6]${NC}  AbuseIPDB Reporter"
        echo ""
    fi

    if [ "$IS_UNIFI" = false ] && [ "$IS_DOCKER_HOST" = false ]; then
        msg_warn "No UniFi device or Docker detected."
        msg_info "Showing all options."
        echo ""
        echo -e "  ${BOLD}[1]${NC}  CrowdSec Engine"
        echo -e "  ${BOLD}[2]${NC}  UniFi Parser Collection"
        echo -e "  ${BOLD}[3]${NC}  UniFi Bouncer"
        echo -e "  ${BOLD}[4]${NC}  Sidecar Proxy"
        echo -e "  ${BOLD}[5]${NC}  Blocklist Import"
        echo -e "  ${BOLD}[6]${NC}  AbuseIPDB Reporter"
        echo ""
    fi

    print_line
    echo -e "  ${BOLD}[B]${NC}  Back to main menu"
    echo ""

    read -n 1 -s choice </dev/tty
    case "$choice" in
        1) run_install install_crowdsec "CrowdSec Engine" ;;
        2) run_install install_parser "UniFi Parser" ;;
        3) run_install install_bouncer "UniFi Bouncer" ;;
        4) run_install install_sidecar "Sidecar Proxy" ;;
        5) run_install install_blocklist "Blocklist Import" ;;
        6) run_install configure_abuseipdb "AbuseIPDB Reporter" ;;
        b|B) return ;;
        *) show_components_menu ;;
    esac
}

# ---------------------------------------------------------------------------
# Status Screen
# ---------------------------------------------------------------------------
show_status_screen() {
    # Re-detect before showing status
    detect_environment

    show_banner
    echo -e "  ${BOLD}Installation Status${NC}"
    echo ""

    echo -e "  ${DIM}-- Device Info --${NC}"
    if [ "$IS_UNIFI" = true ]; then
        msg_info "Device:      ${DEVICE_MODEL:-Unknown UniFi}"
        msg_info "Tier:        ${DEVICE_TIER}"
        msg_info "ipset cap:   ${IPSET_CAPACITY}"
    else
        msg_info "Device:      Non-UniFi host"
    fi
    msg_info "Arch:        ${ARCH}"
    msg_info "Docker:      $([ "$IS_DOCKER_HOST" = true ] && echo "available" || echo "not found")"
    echo ""

    echo -e "  ${DIM}-- Components --${NC}"
    [ "$CS_INSTALLED" = true ]        && print_status "CrowdSec Engine       " "installed" \
                                      || print_status "CrowdSec Engine       " "missing"
    [ "$PARSER_INSTALLED" = true ]    && print_status "UniFi Parser          " "installed" \
                                      || print_status "UniFi Parser          " "missing"
    [ "$BOUNCER_INSTALLED" = true ]   && print_status "UniFi Bouncer         " "installed" \
                                      || print_status "UniFi Bouncer         " "missing"
    [ "$SIDECAR_INSTALLED" = true ]   && print_status "Sidecar Proxy         " "installed" \
                                      || print_status "Sidecar Proxy         " "missing"
    [ "$BLOCKLIST_INSTALLED" = true ] && print_status "Blocklist Import      " "installed" \
                                      || print_status "Blocklist Import      " "missing"
    [ "$ABUSEIPDB_ENABLED" = true ]   && print_status "AbuseIPDB Reporter    " "enabled" \
                                      || print_status "AbuseIPDB Reporter    " "disabled"
    echo ""

    # Show bouncer service status if installed
    if [ "$BOUNCER_INSTALLED" = true ]; then
        echo -e "  ${DIM}-- Bouncer Service --${NC}"
        if systemctl is-active crowdsec-firewall-bouncer >/dev/null 2>&1; then
            msg_ok "Service: running"
        else
            msg_warn "Service: stopped"
        fi
        local ipset_count
        ipset_count=$(ipset list crowdsec-blacklists 2>/dev/null | grep -c "^[0-9]" || echo "0")
        msg_info "Blocked IPs: ${ipset_count}"
        echo ""
    fi

    print_line
    echo -e "  ${BOLD}[R]${NC}  Refresh    ${BOLD}[B]${NC}  Back"
    echo ""

    read -n 1 -s choice </dev/tty
    case "$choice" in
        r|R) show_status_screen ;;
        b|B) return ;;
        *) return ;;
    esac
}

# ---------------------------------------------------------------------------
# Install Runner (wraps install functions with error handling)
# ---------------------------------------------------------------------------
run_install() {
    local func="$1"
    local name="$2"

    show_banner
    echo -e "  ${BOLD}Installing: ${name}${NC}"
    echo ""

    while true; do
        if "$func"; then
            echo ""
            msg_ok "${name} installed successfully."
            log "${name} installed successfully"
            press_any_key
            return 0
        else
            error_prompt "$name"
            local result=$?
            if [ $result -eq 0 ]; then
                # Retry
                show_banner
                echo -e "  ${BOLD}Retrying: ${name}${NC}"
                echo ""
                continue
            elif [ $result -eq 1 ]; then
                # Skip
                msg_warn "Skipping ${name}."
                log "${name} skipped by user"
                press_any_key
                return 1
            else
                # Abort
                msg_err "Installation aborted."
                log "Installation aborted during ${name}"
                press_any_key
                return 2
            fi
        fi
    done
}

# ---------------------------------------------------------------------------
# Install: Full Suite
# ---------------------------------------------------------------------------
install_full_suite() {
    show_banner
    echo -e "  ${BOLD}Full Suite Installation${NC}"
    echo ""
    msg_info "This will install all components appropriate for your device."
    echo ""

    if [ "$IS_UNIFI" = true ]; then
        msg_info "Detected UniFi device. Installing:"
        msg_dim "  1. CrowdSec Engine"
        msg_dim "  2. UniFi Parser Collection"
        msg_dim "  3. UniFi Bouncer"
    elif [ "$IS_DOCKER_HOST" = true ]; then
        msg_info "Detected Docker host. Installing:"
        msg_dim "  1. CrowdSec Engine (Docker)"
        msg_dim "  2. Sidecar Proxy"
        msg_dim "  3. Blocklist Import"
    else
        msg_info "Installing all available components:"
        msg_dim "  1. CrowdSec Engine"
        msg_dim "  2. UniFi Parser Collection"
        msg_dim "  3. UniFi Bouncer"
    fi

    echo ""
    echo -e "  ${BOLD}Proceed? [Y/n]${NC} "
    read -n 1 -s confirm </dev/tty
    echo ""
    if [ "$confirm" = "n" ] || [ "$confirm" = "N" ]; then
        return
    fi

    local abort=false

    if [ "$IS_UNIFI" = true ]; then
        # UniFi device: engine + parser + bouncer
        if [ "$CS_INSTALLED" = false ]; then
            run_install install_crowdsec "CrowdSec Engine" || { [ $? -eq 2 ] && abort=true; }
        else
            msg_ok "CrowdSec Engine already installed, skipping."
        fi

        if [ "$abort" = false ] && [ "$PARSER_INSTALLED" = false ]; then
            run_install install_parser "UniFi Parser" || { [ $? -eq 2 ] && abort=true; }
        elif [ "$abort" = false ]; then
            msg_ok "UniFi Parser already installed, skipping."
        fi

        if [ "$abort" = false ] && [ "$BOUNCER_INSTALLED" = false ]; then
            run_install install_bouncer "UniFi Bouncer" || { [ $? -eq 2 ] && abort=true; }
        elif [ "$abort" = false ]; then
            msg_ok "UniFi Bouncer already installed, skipping."
        fi

    elif [ "$IS_DOCKER_HOST" = true ]; then
        # Docker host: engine (docker) + sidecar + blocklist
        if [ "$CS_INSTALLED" = false ]; then
            run_install install_crowdsec "CrowdSec Engine" || { [ $? -eq 2 ] && abort=true; }
        else
            msg_ok "CrowdSec Engine already installed, skipping."
        fi

        if [ "$abort" = false ] && [ "$SIDECAR_INSTALLED" = false ]; then
            run_install install_sidecar "Sidecar Proxy" || { [ $? -eq 2 ] && abort=true; }
        elif [ "$abort" = false ]; then
            msg_ok "Sidecar Proxy already installed, skipping."
        fi

        if [ "$abort" = false ] && [ "$BLOCKLIST_INSTALLED" = false ]; then
            run_install install_blocklist "Blocklist Import" || { [ $? -eq 2 ] && abort=true; }
        elif [ "$abort" = false ]; then
            msg_ok "Blocklist Import already installed, skipping."
        fi

    else
        # Unknown device: try engine + parser + bouncer
        if [ "$CS_INSTALLED" = false ]; then
            run_install install_crowdsec "CrowdSec Engine" || { [ $? -eq 2 ] && abort=true; }
        else
            msg_ok "CrowdSec Engine already installed, skipping."
        fi

        if [ "$abort" = false ] && [ "$PARSER_INSTALLED" = false ]; then
            run_install install_parser "UniFi Parser" || { [ $? -eq 2 ] && abort=true; }
        elif [ "$abort" = false ]; then
            msg_ok "UniFi Parser already installed, skipping."
        fi

        if [ "$abort" = false ] && [ "$BOUNCER_INSTALLED" = false ]; then
            run_install install_bouncer "UniFi Bouncer" || { [ $? -eq 2 ] && abort=true; }
        elif [ "$abort" = false ]; then
            msg_ok "UniFi Bouncer already installed, skipping."
        fi
    fi

    if [ "$abort" = false ]; then
        # Refresh detection
        detect_environment

        show_banner
        echo -e "  ${BOLD}${GREEN}Installation Complete${NC}"
        echo ""
        show_post_install_summary
    fi

    press_any_key
}

# ---------------------------------------------------------------------------
# Post-Install Summary
# ---------------------------------------------------------------------------
show_post_install_summary() {
    echo -e "  ${DIM}-- Installed Components --${NC}"
    [ "$CS_INSTALLED" = true ]        && msg_ok "CrowdSec Engine"
    [ "$PARSER_INSTALLED" = true ]    && msg_ok "UniFi Parser Collection"
    [ "$BOUNCER_INSTALLED" = true ]   && msg_ok "UniFi Bouncer"
    [ "$SIDECAR_INSTALLED" = true ]   && msg_ok "Sidecar Proxy"
    [ "$BLOCKLIST_INSTALLED" = true ] && msg_ok "Blocklist Import"
    [ "$ABUSEIPDB_ENABLED" = true ]   && msg_ok "AbuseIPDB Reporter"
    echo ""

    if [ "$BOUNCER_INSTALLED" = true ]; then
        echo -e "  ${DIM}-- Next Steps --${NC}"
        msg_info "1. Verify bouncer config:"
        msg_dim "   cat /data/crowdsec-bouncer/crowdsec-firewall-bouncer.yaml"
        msg_info "2. Check bouncer status:"
        msg_dim "   systemctl status crowdsec-firewall-bouncer"
        msg_info "3. View blocked IPs:"
        msg_dim "   ipset list crowdsec-blacklists | head -20"
        echo ""
    fi

    if [ "$SIDECAR_INSTALLED" = true ]; then
        echo -e "  ${DIM}-- Sidecar Info --${NC}"
        msg_info "Bouncer connects to sidecar on port 8084"
        msg_info "Set api_url in bouncer config to:"
        msg_dim "   http://$(hostname -I 2>/dev/null | awk '{print $1}'):8084/"
        echo ""
    fi

    echo -e "  ${DIM}Documentation: ${GITHUB_BASE}/crowdsec-unifi-suite${NC}"
    echo ""
}

# ---------------------------------------------------------------------------
# Install: CrowdSec Engine
# ---------------------------------------------------------------------------
install_crowdsec() {
    if [ "$CS_INSTALLED" = true ]; then
        msg_ok "CrowdSec is already installed."
        local cs_ver
        cs_ver=$(cscli version 2>/dev/null | grep -oP 'version:\s*\Kv[\d.]+' || echo "unknown")
        msg_info "Version: ${cs_ver}"
        return 0
    fi

    msg_info "Installing CrowdSec Engine..."
    log "Installing CrowdSec Engine"

    # Use the official CrowdSec installer
    if ! curl -s https://install.crowdsec.net | bash 2>&1 | tee -a "$LOG_FILE"; then
        msg_err "CrowdSec installation failed."
        log "CrowdSec installation failed"
        return 1
    fi

    # Verify installation
    if ! command -v cscli >/dev/null 2>&1; then
        msg_err "CrowdSec binary not found after installation."
        return 1
    fi

    CS_INSTALLED=true
    msg_ok "CrowdSec Engine installed."

    # Offer console enrollment
    echo ""
    echo -e "  ${BOLD}Enroll in CrowdSec Console? [y/N]${NC} "
    read -n 1 -s enroll </dev/tty
    echo ""

    if [ "$enroll" = "y" ] || [ "$enroll" = "Y" ]; then
        echo -e "  Enter enrollment key from ${CYAN}https://app.crowdsec.net${NC}"
        echo -n "  Key: "
        read -r enroll_key </dev/tty
        if [ -n "$enroll_key" ]; then
            if cscli console enroll "$enroll_key" 2>&1 | tee -a "$LOG_FILE"; then
                msg_ok "Enrolled in CrowdSec Console."
            else
                msg_warn "Enrollment failed. You can enroll later with:"
                msg_dim "  cscli console enroll <key>"
            fi
        fi
    fi

    # Install base collections
    msg_info "Installing base collections..."
    cscli collections install crowdsecurity/linux 2>&1 | tee -a "$LOG_FILE" || true
    cscli collections install crowdsecurity/sshd 2>&1 | tee -a "$LOG_FILE" || true

    return 0
}

# ---------------------------------------------------------------------------
# Install: UniFi Parser Collection
# ---------------------------------------------------------------------------
install_parser() {
    if [ "$PARSER_INSTALLED" = true ]; then
        msg_ok "UniFi Parser Collection is already installed."
        return 0
    fi

    if [ "$CS_INSTALLED" = false ]; then
        msg_err "CrowdSec Engine is required but not installed."
        msg_info "Install CrowdSec first (option 1)."
        return 1
    fi

    msg_info "Installing UniFi Parser Collection..."
    log "Installing UniFi Parser Collection"

    # Try Hub install first
    if cscli collections install wolffcatskyy/unifi 2>&1 | tee -a "$LOG_FILE"; then
        PARSER_INSTALLED=true
        msg_ok "Parser collection installed from CrowdSec Hub."

        # Reload CrowdSec to pick up new parsers
        msg_info "Reloading CrowdSec..."
        systemctl reload crowdsec 2>/dev/null || cscli hub update 2>/dev/null || true
        return 0
    fi

    # Fallback: install from GitHub
    msg_warn "Hub install failed. Trying direct install from GitHub..."
    if curl -sSL "${GITHUB_RAW}/crowdsec-unifi-parser/main/install.sh" | bash 2>&1 | tee -a "$LOG_FILE"; then
        PARSER_INSTALLED=true
        msg_ok "Parser collection installed from GitHub."
        return 0
    fi

    msg_err "Parser collection installation failed."
    return 1
}

# ---------------------------------------------------------------------------
# Install: UniFi Bouncer
# ---------------------------------------------------------------------------
install_bouncer() {
    if [ "$BOUNCER_INSTALLED" = true ]; then
        msg_ok "UniFi Bouncer is already installed."
        return 0
    fi

    msg_info "Installing UniFi Bouncer..."
    log "Installing UniFi Bouncer"

    # Delegate to the bouncer's own bootstrap script
    if ! curl -sSL "${GITHUB_RAW}/crowdsec-unifi-bouncer/main/bootstrap.sh" | bash 2>&1 | tee -a "$LOG_FILE"; then
        msg_err "Bouncer bootstrap failed."
        return 1
    fi

    # Prompt for LAPI configuration
    echo ""
    msg_info "Configure bouncer connection to CrowdSec LAPI."
    echo ""

    local default_api_url="http://192.168.1.1:8080/"
    echo -n "  LAPI URL [${default_api_url}]: "
    read -r api_url </dev/tty
    api_url="${api_url:-$default_api_url}"

    echo ""
    msg_info "Generate a bouncer API key on your CrowdSec host:"
    msg_dim "  cscli bouncers add unifi-bouncer"
    echo ""
    echo -n "  Bouncer API Key: "
    read -r api_key </dev/tty

    if [ -z "$api_key" ]; then
        msg_warn "No API key provided. You must configure it manually:"
        msg_dim "  Edit /data/crowdsec-bouncer/crowdsec-firewall-bouncer.yaml"
        BOUNCER_INSTALLED=true
        return 0
    fi

    # Write configuration
    local config_file="/data/crowdsec-bouncer/crowdsec-firewall-bouncer.yaml"
    if [ -f "${config_file}.example" ] && [ ! -f "$config_file" ]; then
        cp "${config_file}.example" "$config_file"
    fi

    if [ -f "$config_file" ]; then
        sed -i "s|api_url:.*|api_url: ${api_url}|" "$config_file"
        sed -i "s|api_key:.*|api_key: ${api_key}|" "$config_file"
        msg_ok "Configuration written to ${config_file}"
    else
        msg_warn "Config file not found at ${config_file}"
        msg_info "Create it manually with api_url and api_key set."
    fi

    # Enable and start the service
    if systemctl is-enabled crowdsec-firewall-bouncer >/dev/null 2>&1; then
        msg_info "Starting bouncer service..."
        systemctl restart crowdsec-firewall-bouncer 2>&1 | tee -a "$LOG_FILE" || true
    else
        msg_info "Enabling bouncer service..."
        systemctl enable crowdsec-firewall-bouncer 2>&1 | tee -a "$LOG_FILE" || true
        systemctl start crowdsec-firewall-bouncer 2>&1 | tee -a "$LOG_FILE" || true
    fi

    # Verify
    sleep 2
    if systemctl is-active crowdsec-firewall-bouncer >/dev/null 2>&1; then
        msg_ok "Bouncer service is running."
    else
        msg_warn "Bouncer service may not have started. Check with:"
        msg_dim "  systemctl status crowdsec-firewall-bouncer"
    fi

    BOUNCER_INSTALLED=true
    return 0
}

# ---------------------------------------------------------------------------
# Install: Sidecar Proxy
# ---------------------------------------------------------------------------
install_sidecar() {
    if [ "$SIDECAR_INSTALLED" = true ]; then
        msg_ok "Sidecar Proxy is already running."
        return 0
    fi

    if [ "$IS_DOCKER_HOST" = false ]; then
        msg_err "Docker is required for the Sidecar Proxy."
        msg_info "Install Docker first or run this on a Docker-capable host."
        return 1
    fi

    msg_info "Installing Sidecar Proxy..."
    log "Installing Sidecar Proxy"

    local install_dir="/opt/crowdsec-suite"
    mkdir -p "$install_dir"

    # Download compose and config files
    msg_info "Downloading configuration files..."
    local suite_raw="${GITHUB_RAW}/crowdsec-unifi-suite/main"

    if ! curl -sSL "${suite_raw}/docker-compose.yml" -o "${install_dir}/docker-compose.yml"; then
        msg_err "Failed to download docker-compose.yml"
        return 1
    fi

    if ! curl -sSL "${suite_raw}/sidecar-config.yaml" -o "${install_dir}/sidecar-config.yaml"; then
        msg_err "Failed to download sidecar-config.yaml"
        return 1
    fi

    # Prompt for bouncer API key
    echo ""
    msg_info "The sidecar needs a CrowdSec bouncer API key."
    msg_dim "  Generate one with: docker exec crowdsec cscli bouncers add crowdsec-sidecar"
    echo ""
    echo -n "  Sidecar Bouncer API Key: "
    read -r sidecar_key </dev/tty

    if [ -n "$sidecar_key" ]; then
        sed -i "s|upstream_lapi_key:.*|upstream_lapi_key: \"${sidecar_key}\"|" "${install_dir}/sidecar-config.yaml"
    else
        msg_warn "No API key provided. Edit sidecar-config.yaml before starting."
    fi

    # Device tier selection for max_decisions
    echo ""
    msg_info "Select your UniFi device tier for decision capping:"
    echo ""
    echo -e "  ${BOLD}[1]${NC}  Enterprise  ${DIM}(EFG / UXG-Enterprise)${NC}    ${CYAN}80,000${NC}"
    echo -e "  ${BOLD}[2]${NC}  Pro         ${DIM}(UDM-SE / UDM-Pro / UCG)${NC}  ${CYAN}50,000${NC}"
    echo -e "  ${BOLD}[3]${NC}  Consumer    ${DIM}(UDM / UDR)${NC}              ${CYAN}15,000${NC}"
    echo -e "  ${BOLD}[4]${NC}  Custom"
    echo ""

    local max_decisions=45000
    read -n 1 -s tier_choice </dev/tty
    echo ""

    case "$tier_choice" in
        1) max_decisions=75000 ;;
        2) max_decisions=45000 ;;
        3) max_decisions=13000 ;;
        4)
            echo -n "  Enter max decisions: "
            read -r max_decisions </dev/tty
            if ! echo "$max_decisions" | grep -qE '^[0-9]+$'; then
                msg_warn "Invalid number, using default 45000."
                max_decisions=45000
            fi
            ;;
        *) msg_info "Using default: 45000" ;;
    esac

    sed -i "s|max_decisions:.*|max_decisions: ${max_decisions}|" "${install_dir}/sidecar-config.yaml"
    msg_ok "max_decisions set to ${max_decisions}"

    # Create .env file
    if [ ! -f "${install_dir}/.env" ]; then
        cat > "${install_dir}/.env" <<ENVEOF
TZ=America/New_York
CROWDSEC_HOSTNAME=$(hostname)
CROWDSEC_ENROLL_KEY=
ABUSEIPDB_API_KEY=
ABUSEIPDB_REPORT_ENABLED=false
BLOCKLIST_MACHINE_ID=blocklist-import
BLOCKLIST_MACHINE_PASSWORD=
BLOCKLIST_BOUNCER_KEY=
BLOCKLIST_DECISION_DURATION=24h
BLOCKLIST_MAX_DECISIONS=0
ENABLE_IPSUM=true
ENABLE_ABUSE_IPDB=true
ENABLE_SPAMHAUS=true
ENABLE_TOR=false
ENABLE_SCANNERS=false
LOG_LEVEL=INFO
ENVEOF
        msg_info "Created ${install_dir}/.env — edit with your credentials."
    fi

    # Start sidecar only (not the full stack)
    msg_info "Starting Sidecar Proxy..."
    cd "$install_dir"
    if docker compose up -d crowdsec-sidecar 2>&1 | tee -a "$LOG_FILE"; then
        sleep 3
        if docker ps | grep -q crowdsec-sidecar; then
            SIDECAR_INSTALLED=true
            msg_ok "Sidecar Proxy is running on port 8084."
        else
            msg_warn "Container started but may not be healthy yet."
            msg_dim "  Check with: docker logs crowdsec-sidecar"
        fi
    else
        msg_err "Failed to start Sidecar Proxy."
        return 1
    fi

    return 0
}

# ---------------------------------------------------------------------------
# Install: Blocklist Import
# ---------------------------------------------------------------------------
install_blocklist() {
    if [ "$BLOCKLIST_INSTALLED" = true ]; then
        msg_ok "Blocklist Import is already installed."
        return 0
    fi

    msg_info "Installing Blocklist Import..."
    log "Installing Blocklist Import"

    if [ "$IS_DOCKER_HOST" = true ]; then
        # Docker install
        local install_dir="/opt/crowdsec-suite"
        mkdir -p "$install_dir"

        # Make sure compose file exists
        if [ ! -f "${install_dir}/docker-compose.yml" ]; then
            msg_info "Downloading docker-compose.yml..."
            curl -sSL "${GITHUB_RAW}/crowdsec-unifi-suite/main/docker-compose.yml" \
                -o "${install_dir}/docker-compose.yml" || {
                msg_err "Failed to download docker-compose.yml"
                return 1
            }
        fi

        # Create .env if missing
        if [ ! -f "${install_dir}/.env" ]; then
            msg_warn "No .env file found."
            msg_info "You need CrowdSec machine credentials for blocklist-import."
            echo ""
            echo -n "  Machine ID [blocklist-import]: "
            read -r bl_machine_id </dev/tty
            bl_machine_id="${bl_machine_id:-blocklist-import}"

            echo -n "  Machine Password: "
            read -r bl_machine_pass </dev/tty

            echo -n "  Bouncer API Key (for dedup): "
            read -r bl_bouncer_key </dev/tty

            cat > "${install_dir}/.env" <<ENVEOF
TZ=America/New_York
BLOCKLIST_MACHINE_ID=${bl_machine_id}
BLOCKLIST_MACHINE_PASSWORD=${bl_machine_pass}
BLOCKLIST_BOUNCER_KEY=${bl_bouncer_key}
BLOCKLIST_DECISION_DURATION=24h
BLOCKLIST_MAX_DECISIONS=0
ENABLE_IPSUM=true
ENABLE_ABUSE_IPDB=true
ENABLE_SPAMHAUS=true
ENABLE_TOR=false
ENABLE_SCANNERS=false
LOG_LEVEL=INFO
ENVEOF
        fi

        msg_info "Starting Blocklist Import container..."
        cd "$install_dir"
        if docker compose up -d blocklist-import 2>&1 | tee -a "$LOG_FILE"; then
            sleep 3
            if docker ps -a | grep -q crowdsec-blocklist-import; then
                BLOCKLIST_INSTALLED=true
                msg_ok "Blocklist Import container started."
            else
                msg_warn "Container may not have started correctly."
                msg_dim "  Check with: docker logs crowdsec-blocklist-import"
            fi
        else
            msg_err "Failed to start Blocklist Import."
            return 1
        fi
    else
        # Non-Docker: use the standalone installer
        msg_info "Installing via standalone installer..."
        if curl -sSL "${GITHUB_RAW}/crowdsec-blocklist-import/main/install.sh" | bash 2>&1 | tee -a "$LOG_FILE"; then
            BLOCKLIST_INSTALLED=true
            msg_ok "Blocklist Import installed."
        else
            msg_err "Blocklist Import installation failed."
            return 1
        fi
    fi

    return 0
}

# ---------------------------------------------------------------------------
# Configure: AbuseIPDB Reporter
# ---------------------------------------------------------------------------
configure_abuseipdb() {
    if [ "$SIDECAR_INSTALLED" = false ]; then
        msg_err "Sidecar Proxy must be installed first."
        msg_info "AbuseIPDB reporting is a feature of the Sidecar Proxy."
        return 1
    fi

    msg_info "Configuring AbuseIPDB Reporter..."
    log "Configuring AbuseIPDB"

    echo ""
    msg_info "Get a free API key at: ${CYAN}https://www.abuseipdb.com/account/api${NC}"
    msg_dim "  Free tier: 100 reports/day"
    echo ""
    echo -n "  AbuseIPDB API Key: "
    read -r abuse_key </dev/tty

    if [ -z "$abuse_key" ]; then
        msg_warn "No API key provided. AbuseIPDB not configured."
        return 1
    fi

    local install_dir="/opt/crowdsec-suite"
    if [ -f "${install_dir}/.env" ]; then
        sed -i "s|ABUSEIPDB_API_KEY=.*|ABUSEIPDB_API_KEY=${abuse_key}|" "${install_dir}/.env"
        sed -i "s|ABUSEIPDB_REPORT_ENABLED=.*|ABUSEIPDB_REPORT_ENABLED=true|" "${install_dir}/.env"
    else
        msg_err ".env file not found at ${install_dir}/.env"
        return 1
    fi

    # Recreate sidecar container with new env
    msg_info "Restarting Sidecar Proxy with AbuseIPDB enabled..."
    cd "$install_dir"
    if docker compose up -d crowdsec-sidecar 2>&1 | tee -a "$LOG_FILE"; then
        ABUSEIPDB_ENABLED=true
        msg_ok "AbuseIPDB Reporter enabled."
        msg_info "Reports will be sent for locally-detected malicious IPs."
    else
        msg_err "Failed to restart Sidecar Proxy."
        return 1
    fi

    return 0
}

# ---------------------------------------------------------------------------
# Update Menu
# ---------------------------------------------------------------------------
show_update_menu() {
    show_banner
    echo -e "  ${BOLD}Update Components${NC}"
    echo ""

    if [ "$CS_INSTALLED" = true ]; then
        echo -e "  ${BOLD}[1]${NC}  CrowdSec Engine  ${DIM}(apt/package manager)${NC}"
    fi
    if [ "$PARSER_INSTALLED" = true ]; then
        echo -e "  ${BOLD}[2]${NC}  UniFi Parser Collection  ${DIM}(cscli upgrade)${NC}"
    fi
    if [ "$BOUNCER_INSTALLED" = true ]; then
        echo -e "  ${BOLD}[3]${NC}  UniFi Bouncer  ${DIM}(re-run bootstrap)${NC}"
    fi
    if [ "$SIDECAR_INSTALLED" = true ]; then
        echo -e "  ${BOLD}[4]${NC}  Sidecar Proxy  ${DIM}(docker pull)${NC}"
    fi
    if [ "$BLOCKLIST_INSTALLED" = true ]; then
        echo -e "  ${BOLD}[5]${NC}  Blocklist Import  ${DIM}(docker pull)${NC}"
    fi
    echo ""
    echo -e "  ${BOLD}[A]${NC}  Update All"
    print_line
    echo -e "  ${BOLD}[B]${NC}  Back to main menu"
    echo ""

    read -n 1 -s choice </dev/tty
    case "$choice" in
        1) update_crowdsec; press_any_key ;;
        2) update_parser; press_any_key ;;
        3) update_bouncer; press_any_key ;;
        4) update_sidecar; press_any_key ;;
        5) update_blocklist; press_any_key ;;
        a|A) update_all; press_any_key ;;
        b|B) return ;;
        *) show_update_menu ;;
    esac
}

update_crowdsec() {
    msg_info "Updating CrowdSec Engine..."
    if command -v apt-get >/dev/null 2>&1; then
        apt-get update -qq && apt-get install --only-upgrade -y crowdsec 2>&1 | tee -a "$LOG_FILE"
    elif command -v yum >/dev/null 2>&1; then
        yum update -y crowdsec 2>&1 | tee -a "$LOG_FILE"
    else
        msg_warn "Unknown package manager. Update CrowdSec manually."
        return 1
    fi
    cscli hub update 2>&1 | tee -a "$LOG_FILE" || true
    msg_ok "CrowdSec Engine updated."
}

update_parser() {
    msg_info "Updating UniFi Parser Collection..."
    if cscli collections upgrade wolffcatskyy/unifi 2>&1 | tee -a "$LOG_FILE"; then
        systemctl reload crowdsec 2>/dev/null || true
        msg_ok "Parser collection updated."
    else
        msg_warn "Update failed. Trying fresh install..."
        cscli collections install wolffcatskyy/unifi --force 2>&1 | tee -a "$LOG_FILE" || true
    fi
}

update_bouncer() {
    msg_info "Updating UniFi Bouncer..."
    msg_info "Re-running bootstrap installer..."
    if curl -sSL "${GITHUB_RAW}/crowdsec-unifi-bouncer/main/bootstrap.sh" | bash 2>&1 | tee -a "$LOG_FILE"; then
        systemctl restart crowdsec-firewall-bouncer 2>/dev/null || true
        msg_ok "Bouncer updated."
    else
        msg_err "Bouncer update failed."
        return 1
    fi
}

update_sidecar() {
    msg_info "Updating Sidecar Proxy..."
    local install_dir="/opt/crowdsec-suite"
    if [ -f "${install_dir}/docker-compose.yml" ]; then
        cd "$install_dir"
        docker compose pull crowdsec-sidecar 2>&1 | tee -a "$LOG_FILE"
        docker compose up -d crowdsec-sidecar 2>&1 | tee -a "$LOG_FILE"
        msg_ok "Sidecar Proxy updated."
    else
        msg_err "Compose file not found at ${install_dir}/docker-compose.yml"
        return 1
    fi
}

update_blocklist() {
    msg_info "Updating Blocklist Import..."
    local install_dir="/opt/crowdsec-suite"
    if [ -f "${install_dir}/docker-compose.yml" ]; then
        cd "$install_dir"
        docker compose pull blocklist-import 2>&1 | tee -a "$LOG_FILE"
        docker compose up -d blocklist-import 2>&1 | tee -a "$LOG_FILE"
        msg_ok "Blocklist Import updated."
    else
        msg_err "Compose file not found at ${install_dir}/docker-compose.yml"
        return 1
    fi
}

update_all() {
    show_banner
    echo -e "  ${BOLD}Updating All Components${NC}"
    echo ""
    [ "$CS_INSTALLED" = true ] && update_crowdsec
    echo ""
    [ "$PARSER_INSTALLED" = true ] && update_parser
    echo ""
    [ "$BOUNCER_INSTALLED" = true ] && update_bouncer
    echo ""
    [ "$SIDECAR_INSTALLED" = true ] && update_sidecar
    echo ""
    [ "$BLOCKLIST_INSTALLED" = true ] && update_blocklist
    echo ""
    msg_ok "All components updated."
}

# ---------------------------------------------------------------------------
# Uninstall Menu
# ---------------------------------------------------------------------------
show_uninstall_menu() {
    show_banner
    echo -e "  ${BOLD}Uninstall Components${NC}"
    echo ""
    echo -e "  ${RED}These actions are destructive and cannot be undone.${NC}"
    echo ""

    if [ "$BLOCKLIST_INSTALLED" = true ]; then
        echo -e "  ${BOLD}[5]${NC}  Blocklist Import"
    fi
    if [ "$SIDECAR_INSTALLED" = true ]; then
        echo -e "  ${BOLD}[4]${NC}  Sidecar Proxy"
    fi
    if [ "$BOUNCER_INSTALLED" = true ]; then
        echo -e "  ${BOLD}[3]${NC}  UniFi Bouncer"
    fi
    if [ "$PARSER_INSTALLED" = true ]; then
        echo -e "  ${BOLD}[2]${NC}  UniFi Parser Collection"
    fi
    if [ "$CS_INSTALLED" = true ]; then
        echo -e "  ${BOLD}[1]${NC}  CrowdSec Engine"
    fi
    echo ""
    echo -e "  ${BOLD}[A]${NC}  ${RED}Uninstall Everything${NC}"
    print_line
    echo -e "  ${BOLD}[B]${NC}  Back to main menu"
    echo ""

    read -n 1 -s choice </dev/tty
    case "$choice" in
        1) confirm_and_run uninstall_crowdsec "CrowdSec Engine" ;;
        2) confirm_and_run uninstall_parser "UniFi Parser Collection" ;;
        3) confirm_and_run uninstall_bouncer "UniFi Bouncer" ;;
        4) confirm_and_run uninstall_sidecar "Sidecar Proxy" ;;
        5) confirm_and_run uninstall_blocklist "Blocklist Import" ;;
        a|A) confirm_and_run uninstall_all "ALL components" ;;
        b|B) return ;;
        *) show_uninstall_menu ;;
    esac
}

confirm_and_run() {
    local func="$1"
    local name="$2"

    echo ""
    echo -e "  ${RED}${BOLD}Uninstall ${name}? This cannot be undone.${NC}"
    echo -e "  ${BOLD}Type 'yes' to confirm:${NC} "
    read -r confirm </dev/tty
    if [ "$confirm" = "yes" ]; then
        "$func"
        detect_environment
        press_any_key
    else
        msg_info "Cancelled."
        press_any_key
    fi
}

uninstall_crowdsec() {
    msg_info "Uninstalling CrowdSec Engine..."
    log "Uninstalling CrowdSec Engine"

    # Stop service first
    systemctl stop crowdsec 2>/dev/null || true
    systemctl disable crowdsec 2>/dev/null || true

    if command -v apt-get >/dev/null 2>&1; then
        apt-get remove -y crowdsec 2>&1 | tee -a "$LOG_FILE" || true
    elif command -v yum >/dev/null 2>&1; then
        yum remove -y crowdsec 2>&1 | tee -a "$LOG_FILE" || true
    elif command -v apk >/dev/null 2>&1; then
        apk del crowdsec 2>&1 | tee -a "$LOG_FILE" || true
    else
        msg_warn "Unknown package manager. Remove CrowdSec packages manually."
    fi

    CS_INSTALLED=false
    PARSER_INSTALLED=false
    msg_ok "CrowdSec Engine uninstalled."
}

uninstall_parser() {
    msg_info "Uninstalling UniFi Parser Collection..."
    log "Uninstalling parser collection"

    if command -v cscli >/dev/null 2>&1; then
        cscli collections remove wolffcatskyy/unifi --force 2>&1 | tee -a "$LOG_FILE" || true
        systemctl reload crowdsec 2>/dev/null || true
    fi

    PARSER_INSTALLED=false
    msg_ok "UniFi Parser Collection removed."
}

uninstall_bouncer() {
    msg_info "Uninstalling UniFi Bouncer..."
    log "Uninstalling bouncer"

    # Stop service
    systemctl stop crowdsec-firewall-bouncer 2>/dev/null || true
    systemctl disable crowdsec-firewall-bouncer 2>/dev/null || true

    # Remove systemd units
    rm -f /etc/systemd/system/crowdsec-firewall-bouncer.service 2>/dev/null
    rm -f /etc/systemd/system/crowdsec-unifi-metrics.service 2>/dev/null
    systemctl daemon-reload 2>/dev/null || true

    # Clean ipsets
    msg_info "Cleaning up ipsets..."
    ipset destroy crowdsec-blacklists 2>/dev/null || true
    ipset destroy crowdsec6-blacklists 2>/dev/null || true

    # Clean iptables rules
    iptables -D INPUT -m set --match-set crowdsec-blacklists src -j DROP 2>/dev/null || true
    ip6tables -D INPUT -m set --match-set crowdsec6-blacklists src -j DROP 2>/dev/null || true
    iptables -D FORWARD -m set --match-set crowdsec-blacklists src -j DROP 2>/dev/null || true
    ip6tables -D FORWARD -m set --match-set crowdsec6-blacklists src -j DROP 2>/dev/null || true

    # Remove bouncer directory
    rm -rf /data/crowdsec-bouncer 2>/dev/null

    BOUNCER_INSTALLED=false
    msg_ok "UniFi Bouncer uninstalled and ipsets cleaned."
}

uninstall_sidecar() {
    msg_info "Uninstalling Sidecar Proxy..."
    log "Uninstalling sidecar"

    local install_dir="/opt/crowdsec-suite"
    if [ -f "${install_dir}/docker-compose.yml" ]; then
        cd "$install_dir"
        docker compose down crowdsec-sidecar 2>&1 | tee -a "$LOG_FILE" || true
    else
        docker stop crowdsec-sidecar 2>/dev/null || true
        docker rm crowdsec-sidecar 2>/dev/null || true
    fi

    SIDECAR_INSTALLED=false
    ABUSEIPDB_ENABLED=false
    msg_ok "Sidecar Proxy removed."
}

uninstall_blocklist() {
    msg_info "Uninstalling Blocklist Import..."
    log "Uninstalling blocklist import"

    local install_dir="/opt/crowdsec-suite"
    if [ -f "${install_dir}/docker-compose.yml" ]; then
        cd "$install_dir"
        docker compose down blocklist-import 2>&1 | tee -a "$LOG_FILE" || true
    else
        docker stop crowdsec-blocklist-import 2>/dev/null || true
        docker rm crowdsec-blocklist-import 2>/dev/null || true
    fi

    BLOCKLIST_INSTALLED=false
    msg_ok "Blocklist Import removed."
}

uninstall_all() {
    msg_info "Uninstalling all CrowdSec UniFi Suite components..."
    log "Uninstalling all components"

    # Reverse order: dependents first
    [ "$BLOCKLIST_INSTALLED" = true ] && uninstall_blocklist
    [ "$SIDECAR_INSTALLED" = true ] && uninstall_sidecar
    [ "$BOUNCER_INSTALLED" = true ] && uninstall_bouncer
    [ "$PARSER_INSTALLED" = true ] && uninstall_parser
    [ "$CS_INSTALLED" = true ] && uninstall_crowdsec

    # Clean up suite directory
    if [ -d "/opt/crowdsec-suite" ]; then
        echo ""
        echo -e "  ${BOLD}Remove /opt/crowdsec-suite directory? [y/N]${NC} "
        read -n 1 -s rm_dir </dev/tty
        echo ""
        if [ "$rm_dir" = "y" ] || [ "$rm_dir" = "Y" ]; then
            rm -rf /opt/crowdsec-suite
            msg_ok "Removed /opt/crowdsec-suite"
        fi
    fi

    # Remove log file
    rm -f "$LOG_FILE" 2>/dev/null

    echo ""
    msg_ok "All CrowdSec UniFi Suite components have been removed."
}

# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------
main() {
    log_init
    check_root
    detect_environment

    while true; do
        show_banner
        show_main_menu
    done
}

main "$@"
