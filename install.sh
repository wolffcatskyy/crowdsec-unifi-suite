#!/bin/bash
#
# CrowdSec UniFi Suite Installer
# One-command installer for the complete CrowdSec + UniFi security stack
#
# Usage: curl -sSL https://raw.githubusercontent.com/wolffcatskyy/crowdsec-unifi-suite/main/install.sh | bash
#
# Components:
#   - CrowdSec Engine (if not installed)
#   - crowdsec-unifi-parser
#   - crowdsec-unifi-bouncer
#   - crowdsec-blocklist-import (optional)
#

set -e

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

# Version
INSTALLER_VERSION="0.1.0"

# GitHub base URL
GITHUB_BASE="https://github.com/wolffcatskyy"

# -----------------------------------------------------------------------------
# Helper Functions
# -----------------------------------------------------------------------------

log_info() {
    echo -e "${BLUE}[INFO]${NC} $1"
}

log_success() {
    echo -e "${GREEN}[OK]${NC} $1"
}

log_warn() {
    echo -e "${YELLOW}[WARN]${NC} $1"
}

log_error() {
    echo -e "${RED}[ERROR]${NC} $1"
}

print_banner() {
    echo ""
    echo -e "${BLUE}╔════════════════════════════════════════════════════════════╗${NC}"
    echo -e "${BLUE}║${NC}        CrowdSec UniFi Suite Installer v${INSTALLER_VERSION}              ${BLUE}║${NC}"
    echo -e "${BLUE}║${NC}                                                            ${BLUE}║${NC}"
    echo -e "${BLUE}║${NC}  Detect → Decide → Enforce                                 ${BLUE}║${NC}"
    echo -e "${BLUE}╚════════════════════════════════════════════════════════════╝${NC}"
    echo ""
}

# -----------------------------------------------------------------------------
# Safety Checks
# -----------------------------------------------------------------------------

check_root() {
    # Check if running as root
    if [[ $EUID -ne 0 ]]; then
        log_error "This script must be run as root"
        log_info "Try: sudo $0"
        exit 1
    fi
}

check_unifi_device() {
    # TODO: Implement UniFi device detection
    # Check for UniFi-specific paths and markers

    log_info "Checking for UniFi device..."

    # Placeholder: Check for common UniFi markers
    if [[ -f /etc/unifi-os/unifi-os.json ]]; then
        UNIFI_OS_VERSION=$(cat /etc/unifi-os/unifi-os.json 2>/dev/null | grep -o '"version":"[^"]*"' | cut -d'"' -f4)
        log_success "Detected UniFi OS version: ${UNIFI_OS_VERSION:-unknown}"
    elif [[ -d /data/unifi-core ]]; then
        log_success "Detected UniFi device (legacy path)"
    else
        log_warn "UniFi device markers not found"
        log_info "This installer is designed for UniFi OS devices (UDM, UDR, UCG)"

        read -p "Continue anyway? (y/N) " -n 1 -r
        echo
        if [[ ! $REPLY =~ ^[Yy]$ ]]; then
            exit 1
        fi
    fi
}

detect_architecture() {
    # Detect system architecture
    ARCH=$(uname -m)

    case "$ARCH" in
        aarch64|arm64)
            ARCH="arm64"
            log_success "Architecture: arm64"
            ;;
        x86_64|amd64)
            ARCH="amd64"
            log_success "Architecture: amd64"
            ;;
        mips64)
            log_error "Architecture: mips64 (not supported)"
            log_info "USG and USG Pro devices use mips64 and are not supported"
            exit 1
            ;;
        *)
            log_error "Unknown architecture: $ARCH"
            exit 1
            ;;
    esac
}

detect_device_model() {
    # TODO: Implement device model detection
    # Read from UniFi system info

    log_info "Detecting device model..."

    # Placeholder: Try to detect from various sources
    if [[ -f /etc/unifi-os/unifi-os.json ]]; then
        DEVICE_MODEL=$(cat /etc/unifi-os/unifi-os.json 2>/dev/null | grep -o '"model":"[^"]*"' | cut -d'"' -f4)
    elif [[ -f /sys/firmware/devicetree/base/model ]]; then
        DEVICE_MODEL=$(cat /sys/firmware/devicetree/base/model 2>/dev/null | tr -d '\0')
    else
        DEVICE_MODEL="Unknown"
    fi

    log_info "Device model: ${DEVICE_MODEL:-Unknown}"
}

check_dependencies() {
    # Check for required dependencies

    log_info "Checking dependencies..."

    local missing_deps=()

    # Check for curl
    if ! command -v curl &> /dev/null; then
        missing_deps+=("curl")
    fi

    # Check for Python 3
    if ! command -v python3 &> /dev/null; then
        missing_deps+=("python3")
    fi

    # Check for pip
    if ! command -v pip3 &> /dev/null && ! python3 -m pip --version &> /dev/null; then
        missing_deps+=("pip3")
    fi

    if [[ ${#missing_deps[@]} -gt 0 ]]; then
        log_error "Missing dependencies: ${missing_deps[*]}"
        log_info "Please install missing dependencies and re-run the installer"
        exit 1
    fi

    log_success "All dependencies present"
}

check_crowdsec() {
    # Check if CrowdSec is installed

    log_info "Checking for CrowdSec..."

    if command -v cscli &> /dev/null; then
        CS_VERSION=$(cscli version 2>/dev/null | head -1)
        log_success "CrowdSec installed: ${CS_VERSION}"
        CROWDSEC_INSTALLED=true
    else
        log_warn "CrowdSec not found"
        CROWDSEC_INSTALLED=false
    fi
}

# -----------------------------------------------------------------------------
# Component Selection Menu
# -----------------------------------------------------------------------------

show_menu() {
    echo ""
    echo -e "${BLUE}Select components to install:${NC}"
    echo ""
    echo "  1) Full Suite (recommended)"
    echo "     - CrowdSec Engine (if needed)"
    echo "     - UniFi Parser"
    echo "     - UniFi Bouncer"
    echo "     - Blocklist Import"
    echo ""
    echo "  2) Core Only"
    echo "     - CrowdSec Engine (if needed)"
    echo "     - UniFi Parser"
    echo "     - UniFi Bouncer"
    echo ""
    echo "  3) Parser Only"
    echo "     - UniFi Parser"
    echo ""
    echo "  4) Bouncer Only"
    echo "     - UniFi Bouncer"
    echo ""
    echo "  5) Blocklist Import Only"
    echo "     - Blocklist Import utility"
    echo ""
    echo "  6) Custom Selection"
    echo ""
    echo "  0) Exit"
    echo ""

    read -p "Enter selection [1-6, 0 to exit]: " selection

    case $selection in
        1)
            INSTALL_CROWDSEC=true
            INSTALL_PARSER=true
            INSTALL_BOUNCER=true
            INSTALL_BLOCKLIST=true
            ;;
        2)
            INSTALL_CROWDSEC=true
            INSTALL_PARSER=true
            INSTALL_BOUNCER=true
            INSTALL_BLOCKLIST=false
            ;;
        3)
            INSTALL_CROWDSEC=false
            INSTALL_PARSER=true
            INSTALL_BOUNCER=false
            INSTALL_BLOCKLIST=false
            ;;
        4)
            INSTALL_CROWDSEC=false
            INSTALL_PARSER=false
            INSTALL_BOUNCER=true
            INSTALL_BLOCKLIST=false
            ;;
        5)
            INSTALL_CROWDSEC=false
            INSTALL_PARSER=false
            INSTALL_BOUNCER=false
            INSTALL_BLOCKLIST=true
            ;;
        6)
            custom_selection
            ;;
        0)
            log_info "Installation cancelled"
            exit 0
            ;;
        *)
            log_error "Invalid selection"
            show_menu
            ;;
    esac
}

custom_selection() {
    echo ""
    log_info "Custom component selection"
    echo ""

    read -p "Install CrowdSec Engine (if not present)? (Y/n) " -n 1 -r
    echo
    INSTALL_CROWDSEC=$([[ $REPLY =~ ^[Nn]$ ]] && echo false || echo true)

    read -p "Install UniFi Parser? (Y/n) " -n 1 -r
    echo
    INSTALL_PARSER=$([[ $REPLY =~ ^[Nn]$ ]] && echo false || echo true)

    read -p "Install UniFi Bouncer? (Y/n) " -n 1 -r
    echo
    INSTALL_BOUNCER=$([[ $REPLY =~ ^[Nn]$ ]] && echo false || echo true)

    read -p "Install Blocklist Import? (y/N) " -n 1 -r
    echo
    INSTALL_BLOCKLIST=$([[ $REPLY =~ ^[Yy]$ ]] && echo true || echo false)
}

# -----------------------------------------------------------------------------
# Installation Functions (Stubs)
# -----------------------------------------------------------------------------

install_crowdsec() {
    # TODO: Implement CrowdSec installation

    if [[ "$CROWDSEC_INSTALLED" == "true" ]]; then
        log_info "CrowdSec already installed, skipping..."
        return 0
    fi

    log_info "Installing CrowdSec Engine..."

    # Placeholder: CrowdSec installation
    # curl -s https://install.crowdsec.net | bash

    log_warn "CrowdSec installation not yet implemented"
    log_info "Please install CrowdSec manually: https://docs.crowdsec.net/docs/getting_started/install_crowdsec"
}

install_parser() {
    # TODO: Implement parser installation

    log_info "Installing UniFi Parser..."

    # Placeholder: Clone and install parser
    # git clone ${GITHUB_BASE}/crowdsec-unifi-parser.git /tmp/crowdsec-unifi-parser
    # cd /tmp/crowdsec-unifi-parser && ./install.sh

    log_warn "Parser installation not yet implemented"
    log_info "See: ${GITHUB_BASE}/crowdsec-unifi-parser"
}

install_bouncer() {
    # TODO: Implement bouncer installation

    log_info "Installing UniFi Bouncer..."

    # Placeholder: Clone and install bouncer
    # git clone ${GITHUB_BASE}/crowdsec-unifi-bouncer.git /tmp/crowdsec-unifi-bouncer
    # cd /tmp/crowdsec-unifi-bouncer && ./install.sh

    log_warn "Bouncer installation not yet implemented"
    log_info "See: ${GITHUB_BASE}/crowdsec-unifi-bouncer"
}

install_blocklist_import() {
    # TODO: Implement blocklist-import installation

    log_info "Installing Blocklist Import..."

    # Placeholder: Install via pip
    # pip3 install crowdsec-blocklist-import

    log_warn "Blocklist Import installation not yet implemented"
    log_info "See: ${GITHUB_BASE}/crowdsec-blocklist-import"
}

# -----------------------------------------------------------------------------
# Post-Installation
# -----------------------------------------------------------------------------

show_summary() {
    echo ""
    echo -e "${GREEN}╔════════════════════════════════════════════════════════════╗${NC}"
    echo -e "${GREEN}║${NC}                    Installation Summary                     ${GREEN}║${NC}"
    echo -e "${GREEN}╚════════════════════════════════════════════════════════════╝${NC}"
    echo ""

    echo "Components selected:"
    [[ "$INSTALL_CROWDSEC" == "true" ]] && echo "  - CrowdSec Engine: Selected"
    [[ "$INSTALL_PARSER" == "true" ]] && echo "  - UniFi Parser: Selected"
    [[ "$INSTALL_BOUNCER" == "true" ]] && echo "  - UniFi Bouncer: Selected"
    [[ "$INSTALL_BLOCKLIST" == "true" ]] && echo "  - Blocklist Import: Selected"

    echo ""
    echo "Next steps:"
    echo "  1. Configure bouncer: /etc/crowdsec/bouncers/unifi-bouncer.yaml"
    echo "  2. Register bouncer: cscli bouncers add unifi-bouncer"
    echo "  3. Start services: systemctl start crowdsec-unifi-bouncer"
    echo ""
    echo "Documentation:"
    echo "  - ${GITHUB_BASE}/crowdsec-unifi-suite"
    echo ""
}

# -----------------------------------------------------------------------------
# Main
# -----------------------------------------------------------------------------

main() {
    print_banner

    # Safety checks
    check_root
    detect_architecture
    detect_device_model
    check_unifi_device
    check_dependencies
    check_crowdsec

    # Component selection
    show_menu

    # Confirm installation
    echo ""
    log_info "Ready to install selected components"
    read -p "Proceed with installation? (Y/n) " -n 1 -r
    echo
    if [[ $REPLY =~ ^[Nn]$ ]]; then
        log_info "Installation cancelled"
        exit 0
    fi

    # Install selected components
    echo ""
    [[ "$INSTALL_CROWDSEC" == "true" ]] && install_crowdsec
    [[ "$INSTALL_PARSER" == "true" ]] && install_parser
    [[ "$INSTALL_BOUNCER" == "true" ]] && install_bouncer
    [[ "$INSTALL_BLOCKLIST" == "true" ]] && install_blocklist_import

    # Show summary
    show_summary
}

# Run main function
main "$@"
