# CrowdSec UniFi Suite

One-command installer for the complete CrowdSec + UniFi security stack.

## Overview

CrowdSec UniFi Suite brings collaborative threat intelligence to your UniFi network with a defense-in-depth approach:

```
Detect → Decide → Enforce
```

| Stage | Component | Function |
|-------|-----------|----------|
| **Detect** | [crowdsec-unifi-parser](https://github.com/wolffcatskyy/crowdsec-unifi-parser) | Parse UniFi firewall logs for CrowdSec analysis |
| **Decide** | CrowdSec Engine | Apply scenarios, check community blocklists |
| **Enforce** | [crowdsec-unifi-bouncer](https://github.com/wolffcatskyy/crowdsec-unifi-bouncer) | Push ban decisions to UniFi firewall rules |
| **Prioritize** | [crowdsec-unifi-bouncer/sidecar](https://github.com/wolffcatskyy/crowdsec-unifi-bouncer/tree/main/sidecar) | Score and filter decisions to fit device capacity |
| **Augment** | [crowdsec-blocklist-import](https://github.com/wolffcatskyy/crowdsec-blocklist-import) | Import external threat intel (AbuseIPDB, Spamhaus, etc.) |

## Quick Install

```bash
curl -sSL https://raw.githubusercontent.com/wolffcatskyy/crowdsec-unifi-suite/main/install.sh | bash
```

Or clone and run locally:

```bash
git clone https://github.com/wolffcatskyy/crowdsec-unifi-suite.git
cd crowdsec-unifi-suite
./install.sh
```

## Device Compatibility

| Device | Architecture | Status | Notes |
|--------|--------------|--------|-------|
| UDM Pro | arm64 | Supported | Primary target |
| UDM SE | arm64 | Supported | Primary target |
| UDM Pro Max | arm64 | Supported | Primary target |
| UDR | arm64 | Supported | Tested |
| UDM (base) | arm64 | Supported | Limited resources |
| UCG Ultra | arm64 | Experimental | Community testing |
| Cloud Gateway Max | arm64 | Experimental | Community testing |
| USG / USG Pro | mips64 | Not Supported | Legacy architecture |

## Defense in Depth

### Why use CrowdSec alongside UniFi IDS/IPS?

UniFi's built-in Threat Management (IDS/IPS) and CrowdSec serve complementary roles:

| Capability | UniFi IDS/IPS | CrowdSec Suite |
|------------|---------------|----------------|
| **Detection Method** | Signature-based (Suricata rules) | Behavior analysis + community intel |
| **Threat Intelligence** | Ubiquiti-curated rules | 200K+ community-shared threat signals |
| **Response Speed** | Real-time inline | Near real-time (bouncer sync) |
| **Custom Scenarios** | Limited | Fully customizable |
| **Log Analysis** | Alerts only | Parse & act on your own logs |
| **External Blocklists** | GeoIP only | Any IP blocklist (AbuseIPDB, Spamhaus, etc.) |
| **Resource Usage** | High (inline inspection) | Low (decision-based) |

**Best practice**: Enable UniFi IDS/IPS for real-time attack mitigation, and CrowdSec for proactive blocking based on global threat intelligence.

## What Gets Installed

### Core Components

1. **CrowdSec Engine** (if not present)
   - Log analyzer and decision engine
   - Community blocklist subscriptions

2. **UniFi Parser**
   - Parses UniFi firewall log format
   - Enables CrowdSec scenarios against UniFi logs

3. **UniFi Bouncer**
   - Syncs CrowdSec decisions to UniFi firewall rules
   - Automatic ban/unban lifecycle management

### Optional Components

4. **Sidecar Proxy** (recommended when LAPI decisions exceed device capacity)
   - Scores decisions across 7 factors (scenario, origin, TTL, freshness, CIDR, recidivism, decision type)
   - Returns only the highest-priority threats that fit your device's ipset
   - Prevents silent overflow when LAPI has 120K+ decisions but your device holds 15K-30K

5. **Blocklist Import**
   - Import external threat intel feeds
   - AbuseIPDB, Spamhaus, and custom lists

## Configuration

After installation, configure each component:

```bash
# Bouncer configuration
nano /etc/crowdsec/bouncers/unifi-bouncer.yaml

# Parser is auto-configured for standard UniFi log locations

# Blocklist import (optional)
nano /etc/crowdsec/blocklist-import.yaml
```

## Requirements

- UniFi OS 3.x+ (UDM/UDR/UCG series)
- SSH access to UniFi device
- CrowdSec Local API (installed automatically if missing)
- Python 3.8+ (for blocklist-import only)

## Individual Repositories

For standalone installation or development:

| Component | Repository | Documentation |
|-----------|------------|---------------|
| Parser | [crowdsec-unifi-parser](https://github.com/wolffcatskyy/crowdsec-unifi-parser) | Parse UniFi logs |
| Bouncer | [crowdsec-unifi-bouncer](https://github.com/wolffcatskyy/crowdsec-unifi-bouncer) | Enforce decisions |
| Sidecar Proxy | [crowdsec-unifi-bouncer/sidecar](https://github.com/wolffcatskyy/crowdsec-unifi-bouncer/tree/main/sidecar) | Prioritize decisions for device capacity |
| Blocklist Import | [crowdsec-blocklist-import](https://github.com/wolffcatskyy/crowdsec-blocklist-import) | Import threat feeds |

## Support

### HAL 9000 Support

> "I'm sorry, Dave. I'm afraid I can't let those IPs through."

This project is maintained with assistance from Claude AI (HAL's more helpful cousin). Feel free to open issues for:

- Installation problems
- Device compatibility reports
- Feature requests
- Bug reports

### Community

- [CrowdSec Discord](https://discord.gg/crowdsec)
- [UniFi Community](https://community.ui.com/)

## License

MIT License - See [LICENSE](LICENSE) for details.

## Acknowledgments

- [CrowdSec](https://www.crowdsec.net/) for the security engine
- [Ubiquiti](https://ui.com/) for UniFi networking
- The open-source security community
