# CrowdSec UniFi Suite

Unified server-side stack and device installer for the CrowdSec + UniFi security ecosystem.

## Overview

CrowdSec UniFi Suite brings collaborative threat intelligence to your UniFi network with a defense-in-depth approach:

```
Detect → Decide → Prioritize → Enforce
```

| Stage | Component | Function |
|-------|-----------|----------|
| **Detect** | [crowdsec-unifi-parser](https://github.com/wolffcatskyy/crowdsec-unifi-parser) | Parse UniFi firewall logs for CrowdSec analysis |
| **Decide** | CrowdSec Engine | Apply scenarios, check community blocklists |
| **Prioritize** | [crowdsec-sidecar](https://github.com/wolffcatskyy/crowdsec-unifi-bouncer/tree/main/sidecar) | Score and filter decisions to fit device ipset capacity |
| **Enforce** | [crowdsec-unifi-bouncer](https://github.com/wolffcatskyy/crowdsec-unifi-bouncer) | Push ban decisions to UniFi firewall rules |
| **Augment** | [crowdsec-blocklist-import](https://github.com/wolffcatskyy/crowdsec-blocklist-import) | Import external threat feeds (AbuseIPDB, Spamhaus, IPsum) |

---

## Quick Start: Server-Side Stack

The `docker-compose.yml` in this repo brings up the full server-side stack on any Linux host.

### 1. Clone and configure

```bash
git clone https://github.com/wolffcatskyy/crowdsec-unifi-suite.git
cd crowdsec-unifi-suite
cp .env.example .env
```

Edit `.env` — set your timezone. Come back to fill in credentials after step 2.

### 2. Start CrowdSec first

```bash
docker compose up -d crowdsec
```

Wait for CrowdSec to become healthy (about 30 seconds):

```bash
docker compose ps
```

### 3. Generate credentials

```bash
# Machine login for blocklist-import (read/write decisions)
docker exec crowdsec cscli machines add blocklist-import --password 'YourSecurePassword'

# Bouncer key for the sidecar (reads decisions, applies scoring)
docker exec crowdsec cscli bouncers add crowdsec-sidecar

# Bouncer key for blocklist-import deduplication
docker exec crowdsec cscli bouncers add blocklist-import
```

Copy each key into `.env`:
- Sidecar bouncer key → `BOUNCER_API_KEY`
- Machine password → `BLOCKLIST_MACHINE_PASSWORD`
- Blocklist bouncer key → `BLOCKLIST_BOUNCER_KEY`

Also update `sidecar-config.yaml`:
- Set `upstream_lapi_key` to the sidecar bouncer key
- Set `max_decisions` to match your UniFi device's ipset capacity (see table below)

### 4. Start the full stack

```bash
docker compose up -d
```

### 5. Install the bouncer on your UniFi device

```bash
# SSH to your UDM/UDR
ssh root@<udm-ip>

# Download and run the installer
curl -sSL https://raw.githubusercontent.com/wolffcatskyy/crowdsec-unifi-suite/main/install.sh | bash
```

When prompted, point the bouncer at the sidecar on port 8084 (not LAPI directly):

```
api_url: http://<your-server-ip>:8084/
```

---

## Architecture

```
UniFi Device (UDM/UDR)              Linux Server
┌─────────────────────┐              ┌──────────────────────────────────────┐
│  crowdsec-firewall  │              │  crowdsec (LAPI + agent)             │
│     -bouncer        │              │    port 8080                         │
│  (ipset enforcement)│              │        ▲                             │
└────────┬────────────┘              │        │ (internal)                  │
         │                           │  crowdsec-sidecar                    │
         └──────────────────────────►│    port 8084 (bouncer connects here) │
                        port 8084    │    scores + caps to device capacity  │
                                     │                                      │
                                     │  blocklist-import (daemon, hourly)   │
                                     │    AbuseIPDB, Spamhaus, IPsum feeds  │
                                     └──────────────────────────────────────┘
```

### Why the sidecar matters

CrowdSec LAPI accumulates 100K+ decisions from community blocklists. UniFi devices hold
15K–50K ipset entries. Without the sidecar, LAPI silently drops the excess — you have no
control over which threats get enforced.

The sidecar scores every decision across 7 factors (scenario severity, origin, TTL,
freshness, CIDR size, decision type, recidivism) and returns only the highest-priority
threats that fit your device's capacity.

---

## Device Compatibility

| Device | Architecture | Status | ipset Capacity | Recommended `max_decisions` |
|--------|--------------|--------|----------------|------------------------------|
| UDM Pro | arm64 | Supported | ~50,000 | 45,000 |
| UDM SE | arm64 | Supported | ~50,000 | 45,000 |
| UDM Pro Max | arm64 | Supported | ~50,000 | 45,000 |
| UDR | arm64 | Supported | ~15,000 | 13,000 |
| UCG Ultra | arm64 | Experimental | ~30,000 | 27,000 |
| Cloud Gateway Max | arm64 | Experimental | ~30,000 | 27,000 |
| UDM (base) | arm64 | Supported | ~10,000 | 8,000 |
| USG / USG Pro | mips64 | Not Supported | — | — |

---

## Individual Repositories

Each component can be used standalone — install just the piece you need:

| Component | Repository | Use Case |
|-----------|------------|----------|
| Bouncer | [crowdsec-unifi-bouncer](https://github.com/wolffcatskyy/crowdsec-unifi-bouncer) | Enforce CrowdSec decisions on UniFi |
| Sidecar | [crowdsec-unifi-bouncer/sidecar](https://github.com/wolffcatskyy/crowdsec-unifi-bouncer/tree/main/sidecar) | Decision prioritization for capacity-limited devices |
| Blocklist Import | [crowdsec-blocklist-import](https://github.com/wolffcatskyy/crowdsec-blocklist-import) | Import AbuseIPDB, Spamhaus, IPsum feeds |
| Parser | [crowdsec-unifi-parser](https://github.com/wolffcatskyy/crowdsec-unifi-parser) | Parse UniFi logs with CrowdSec |

---

## Roadmap

See [ROADMAP.md](ROADMAP.md) for planned features including a unified CLI, Grafana dashboards,
CrowdSec CTI enrichment, and multi-device support.

---

## Support

Feel free to open issues for:

- Installation problems
- Device compatibility reports
- Feature requests
- Bug reports

### AI Disclosure

*All responses on this repository are generated by Claude AI assisting the maintainer.*

### Community

- [CrowdSec Discord](https://discord.gg/crowdsec)
- [UniFi Community](https://community.ui.com/)

---

## License

MIT License — see [LICENSE](LICENSE) for details.

