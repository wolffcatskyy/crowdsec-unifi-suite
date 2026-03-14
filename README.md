# CrowdSec UniFi Suite

**Detect &rarr; Decide &rarr; Enforce**

[![License: MIT](https://img.shields.io/badge/License-MIT-blue.svg)](LICENSE)
[![Version](https://img.shields.io/badge/version-v1.0.0--beta-orange.svg)](https://github.com/wolffcatskyy/crowdsec-unifi-suite/releases)
[![GitHub Stars](https://img.shields.io/github/stars/wolffcatskyy/crowdsec-unifi-suite?style=social)](https://github.com/wolffcatskyy/crowdsec-unifi-suite)
[![CrowdSec](https://img.shields.io/badge/CrowdSec-ecosystem-purple.svg)](https://www.crowdsec.net/)

---

## Overview

CrowdSec UniFi Suite is a unified installer and server-side stack for running [CrowdSec](https://www.crowdsec.net/) on UniFi networks. It orchestrates installation of the CrowdSec engine, UniFi log parser, on-device firewall bouncer, a sidecar proxy that scores and caps decisions to fit device capacity, external threat feed imports via blocklist-import, and optional AbuseIPDB abuse reporting. Run the interactive installer on a UniFi gateway or deploy the Docker stack on any Linux server -- or both.

---

## Architecture

```
                         Internet
                            |
                            v
             +--------------+--------------+
             |     UniFi Gateway           |
             |  (UDM SE / UDM Pro / UDR)   |
             |                             |
             |  crowdsec-firewall-bouncer  |
             |  ipset enforcement (ban)    |
             +-----+---+------------------+
                   |   |
          Logs     |   |  Pulls decisions
          (syslog) |   |  via port 8084
                   v   |
             +-----+---+------------------+
             |     Linux Server (Docker)   |
             |                             |
             |  +------------------------+ |
             |  | CrowdSec Engine (LAPI) | |
             |  | port 8080              | |
             |  +-----------+------------+ |
             |              |              |
             |              | internal     |
             |              v              |
             |  +------------------------+ |
             |  | Sidecar Proxy          | |
             |  | port 8084              | |
             |  | - scores decisions     | |
             |  | - caps to device limit | |
             |  | - AbuseIPDB reporting  | |
             |  +------------------------+ |
             |                             |
             |  +------------------------+ |
             |  | Blocklist Import       | |
             |  | (daemon, hourly)       | |
             |  | AbuseIPDB, Spamhaus,   | |
             |  | IPsum threat feeds     | |
             |  +--------+---------------+ |
             |           |                 |
             |           v                 |
             |     CrowdSec LAPI           |
             |   (writes decisions)        |
             +-----------------------------+
```

### Why the sidecar matters

CrowdSec LAPI accumulates 100K+ decisions from community blocklists. UniFi devices hold 15K-50K ipset entries. Without the sidecar, excess decisions are silently dropped and you have no control over which threats get enforced.

The sidecar scores every decision across 7 factors (scenario severity, origin, TTL, freshness, CIDR size, decision type, recidivism) and returns only the highest-priority threats that fit your device's capacity.

---

## Quick Start

### On a UniFi device

SSH into your gateway and run the interactive installer:

```bash
curl -sSL https://raw.githubusercontent.com/wolffcatskyy/crowdsec-unifi-suite/main/install.sh | bash
```

The installer detects your device model, shows context-aware menus, and walks you through each component.

### On a Docker server

```bash
git clone https://github.com/wolffcatskyy/crowdsec-unifi-suite.git
cd crowdsec-unifi-suite
cp .env.example .env
# Edit .env with your timezone and credentials
docker compose up -d
```

See [Server-Side Stack](#server-side-stack) below for full setup instructions.

---

## Components

| Component | Description | Runs On | Repository |
|-----------|-------------|---------|------------|
| CrowdSec Engine | Log analysis + community blocklists | UniFi / Server | [crowdsecurity/crowdsec](https://github.com/crowdsecurity/crowdsec) |
| UniFi Parser | Parse UniFi firewall/IDS logs for CrowdSec | UniFi / Server | [crowdsec-unifi-parser](https://github.com/wolffcatskyy/crowdsec-unifi-parser) |
| UniFi Bouncer | Firewall enforcement via ipsets | UniFi Device | [crowdsec-unifi-bouncer](https://github.com/wolffcatskyy/crowdsec-unifi-bouncer) |
| Sidecar Proxy | Decision scoring + device capacity capping | Docker Server | [crowdsec-sidecar](https://github.com/wolffcatskyy/crowdsec-unifi-bouncer/tree/main/sidecar) |
| Blocklist Import | External threat feed importer | Docker Server | [crowdsec-blocklist-import](https://github.com/wolffcatskyy/crowdsec-blocklist-import) |
| AbuseIPDB Reporter | Report malicious IPs to AbuseIPDB | Docker Server | Built into Sidecar |

Each component can be installed and used independently.

---

## Device Compatibility

| Tier | Devices | ipset Capacity | Recommended `max_decisions` |
|------|---------|----------------|----------------------------|
| Enterprise | EFG, UXG-Enterprise | ~80,000 | 75,000 |
| Pro | UDM SE, UDM Pro, UDM Pro Max, UCG Ultra, Cloud Gateway Max, UDW | ~50,000 | 45,000 |
| Consumer | UDM, UDR | ~15,000 | 13,000 |

**Not supported:** USG / USG Pro (mips64 architecture), UX, UXG-Lite.

The installer auto-detects your device model and sets appropriate defaults.

---

## Server-Side Stack

The `docker-compose.yml` brings up CrowdSec, the sidecar proxy, and blocklist import on any Linux host with Docker.

### 1. Clone and configure

```bash
git clone https://github.com/wolffcatskyy/crowdsec-unifi-suite.git
cd crowdsec-unifi-suite
cp .env.example .env
```

Edit `.env` with your timezone. Credentials come from step 3.

### 2. Start CrowdSec first

```bash
docker compose up -d crowdsec
```

Wait ~30 seconds for it to become healthy (`docker compose ps`).

### 3. Generate credentials

```bash
# Machine login for blocklist-import
docker exec crowdsec cscli machines add blocklist-import --password 'YourSecurePassword'

# Bouncer key for the sidecar
docker exec crowdsec cscli bouncers add crowdsec-sidecar

# Bouncer key for blocklist-import (deduplication)
docker exec crowdsec cscli bouncers add blocklist-import
```

Copy each value into `.env`:

| Key | `.env` Variable |
|-----|-----------------|
| Sidecar bouncer key | `BOUNCER_API_KEY` |
| Machine password | `BLOCKLIST_MACHINE_PASSWORD` |
| Blocklist bouncer key | `BLOCKLIST_BOUNCER_KEY` |

Also set `upstream_lapi_key` in `sidecar-config.yaml` to the sidecar bouncer key.

### 4. Start the full stack

```bash
docker compose up -d
```

### 5. Connect the bouncer

On your UniFi device, point the bouncer at the sidecar (not LAPI directly):

```yaml
api_url: http://<your-server-ip>:8084/
```

---

## Configuration

### Sidecar (`sidecar-config.yaml`)

The sidecar proxy is configured via `sidecar-config.yaml`, mounted into the container. Key settings:

- **`max_decisions`** -- Set this to match your device's ipset capacity (see compatibility table). The sidecar scores all decisions and returns only the top N.
- **`scoring`** -- Controls which decisions survive when the cap is hit. Higher score = higher priority. Configurable per scenario, origin, TTL, freshness, CIDR size, and recidivism.
- **`cache_ttl`** -- How long to cache LAPI responses (default: 60s).

### Bouncer

The UniFi bouncer is configured at `/data/crowdsec-bouncer/crowdsec-firewall-bouncer.yaml` on the device. The key setting is `api_url`, which should point to the sidecar on port 8084 rather than LAPI on port 8080.

### Blocklist Import

Threat feeds are toggled via environment variables in `.env`:

| Variable | Default | Feed |
|----------|---------|------|
| `ENABLE_IPSUM` | `true` | IPsum aggregated threat intelligence |
| `ENABLE_ABUSE_IPDB` | `true` | AbuseIPDB public mirror |
| `ENABLE_SPAMHAUS` | `true` | Spamhaus DROP/EDROP |
| `ENABLE_TOR` | `false` | Tor exit nodes |
| `ENABLE_SCANNERS` | `false` | Known scanner IPs |

---

## Installer Menus

The interactive installer detects your environment and shows context-aware options.

**Banner:**
```
    ___                     _  ___
   / __\ __ _____      __ | |/ __\ ___  ___
  / / | '__/ _ \ \ /\ / / | / /  / _ \/ __|
 / /__|_| | (_) \ V  V /  | / /__|  __/ (__
 \____/_|  \___/ \_/\_/ |___|____/\___|\___|

            U n i F i   S u i t e

  v1.0.0               Detect -> Decide -> Enforce
_______________________________________________________________
```

**Main Menu:**
```
  Main Menu

  [1]  Install Full Suite  (recommended)
  [2]  Install Individual Components
  [3]  Check Installation Status
  [4]  Update Components
  [5]  Uninstall Components
_______________________________________________________________
  [0]  Exit
```

**Status Screen (example on UDM SE):**
```
  Installation Status

  -- Device Info --
  i Device:      UDM-SE
  i Tier:        pro
  i ipset cap:   50000
  i Arch:        aarch64
  i Docker:      available

  -- Components --
  + CrowdSec Engine         installed
  + UniFi Parser            installed
  + UniFi Bouncer           installed
  + Sidecar Proxy           installed
  + Blocklist Import        installed
  - AbuseIPDB Reporter      disabled
```

---

## Related Projects

| Repository | Description |
|------------|-------------|
| [crowdsec-unifi-bouncer](https://github.com/wolffcatskyy/crowdsec-unifi-bouncer) | Firewall bouncer for UniFi gateways |
| [crowdsec-blocklist-import](https://github.com/wolffcatskyy/crowdsec-blocklist-import) | External threat feed importer for CrowdSec |
| [crowdsec-unifi-parser](https://github.com/wolffcatskyy/crowdsec-unifi-parser) | CrowdSec parser collection for UniFi logs |

---

## Roadmap

See [ROADMAP.md](ROADMAP.md) for planned features including a unified CLI, Grafana dashboards, and multi-device support.

---

## Support

This project is in **beta**. Please [open an issue](https://github.com/wolffcatskyy/crowdsec-unifi-suite/issues) for bug reports, installation problems, device compatibility reports, or feature requests.

### Community

- [CrowdSec Discord](https://discord.gg/crowdsec)
- [UniFi Community](https://community.ui.com/)

---

## License

MIT License -- see [LICENSE](LICENSE) for details.
