# CyberSecurity-Attack-Defense-Lab
Designed a Purple Team environment to simulate multi-stage attacks, using various security tools to test and refine log aggregation within an implemented SIEM solution.



# Enterprise Security & Adversary Emulation Lab (Purple Team Home Lab)

A custom-built Purple Team home lab that simulates a segmented enterprise network, centralizes endpoint telemetry, and validates detections using automated adversary emulation with a hybrid-cloud C2.

> **Goal:** Build a resilient, observable environment (Defense-in-Depth) and prove detection/visibility using real tactics aligned to **MITRE ATT&CK**.

---

## Table of Contents
- [Lab Goals](#lab-goals)
- [Architecture Overview](#architecture-overview)
- [Network Segmentation](#network-segmentation)
- [PfSense Firewall Rules (Segmentation Enforcement)](#pfsense-firewall-rules)
- [Security Stack](#security-stack)
- [Purple Team Validations](#purple-team-validations)
  - [Windows: Process Discovery (T1057)](#windows-process-discovery-t1057)
  - [Linux: Data Staging + Exfiltration (Multi-Technique)](#linux-data-staging--exfiltration-multi-technique)
- [Key Outcomes](#key-outcomes)
- [Future Optimization](#future-optimization)

---

## Lab Goals
This lab was designed to demonstrate practical security engineering and detection validation:
- **Micro-segmentation** to reduce lateral movement
- **Centralized logging + endpoint visibility** via SIEM/EDR-style telemetry
- **Network inspection at the choke point** (gateway-level IDS)
- **Adversary emulation** using a cloud-hosted C2 to simulate realistic attacker workflows
- Evidence-driven reporting aligned to **MITRE ATT&CK**

---

## Architecture Overview

### High-Level Data Flow
- Endpoints generate host telemetry → **Wazuh** (SIEM/EDR-style manager)
- Network traffic traverses pfSense → **Suricata** inspects traffic at the gateway
- Adversary emulation executes from a cloud VPS → **Caldera** controls agents in the lab

## Network Segmentation (Micro-Segmentation)

The lab is segmented into distinct security zones using pfSense as the central router/firewall. Each subnet represents a separate trust boundary to reduce lateral movement and enforce least-privilege network access.

### Segments (As Implemented)

| Segment | CIDR / Subnet | Gateway | Role | Key Assets |
|--------|----------------|---------|------|------------|
| **WAN** | `192.168.224.0/24` | `192.168.224.138` | External interface for internet connectivity (updates + outbound C2 traffic) | pfSense WAN |
| **CORP-SEG** | `192.168.20.0/24` | `192.168.20.1` | Corporate user tier (attack simulation targets) | Ubuntu Desktop `192.168.20.103`, Windows 10 `192.168.20.106` |
| **SOC-SEG** | `192.168.10.0/24` | `192.168.10.1` | Security operations zone (central telemetry + monitoring tools) | Security Tools Server `192.168.10.100` (Wazuh, Docker/Portainer) |
| **MGMT-SEG** | `192.168.30.0/24` | `192.168.30.1` | Administrative/management tier (controlled cross-segment access) | Monitoring Host `192.168.30.100` |

---

### Segmentation Objectives
- **Contain compromise:** A compromised CORP endpoint should not directly reach SOC systems.
- **Protect security tooling:** SOC-SEG remains isolated and only accepts explicitly required traffic (e.g., Wazuh agents).
- **Centralize control:** All cross-segment and internet-bound traffic routes through **pfSense**, where firewall policy and inspection are enforced.
- **Realistic enterprise model:** Separating CORP, SOC, and MGMT mirrors common real-world architectures.


## pfSense Firewall Rules (Segmentation Enforcement)

pfSense serves as the lab’s central **router + firewall**, enforcing **least privilege** between security zones. Rules are intentionally simple and auditable: explicitly allow only what is required (telemetry, basic connectivity, internet access for updates/C2), block sensitive internal access paths, and rely on a final deny rule to prevent accidental exposure.

### Design Goals
- Allow endpoint telemetry to the **SOC tools server (Wazuh)** while keeping SOC isolated
- Prevent **CORP → SOC** access (reduce lateral movement paths)
- Prevent endpoints from accessing the **pfSense management interface**
- Block access to **Private/Home networks** (safety boundary)
- Permit controlled **internet access** for updates + adversary emulation workflows
- Enforce a **default-deny** baseline

---

### Rule Set (As Implemented)

#### CORP-SEG (LAN) Rules
| Action | Proto | Source | Destination | Dest Port | Purpose |
|-------|-------|--------|-------------|----------|---------|
| ✅ Pass | TCP | LAN subnets | `192.168.10.100` (Wazuh) | `1514–1515` | Allow Wazuh agent communication + enrollment |
| ✅ Pass | ICMP | LAN subnets | LAN address (pfSense) | — | Allow hosts to ping router for connectivity checks |
| ❌ Block | Any | LAN subnets | LAN address (pfSense) | — | Prevent CORP hosts from accessing pfSense (SSH/Web UI) |
| ❌ Block | Any | Any | `Private_IPS` (alias) | — | Block access/pinging to home/private network ranges |
| ✅ Pass | Any | LAN subnets | Any | — | Allow internet access (updates + controlled egress) |
| ❌ Block | Any | Any | Any | — | Default deny (catch-all) |

📌 Evidence:  
- `docs/screenshots/pfsense_rules_corp_lan.png`

---

#### SOC-SEG Rules
| Action | Proto | Source | Destination | Dest Port | Purpose |
|-------|-------|--------|-------------|----------|---------|
| ✅ Pass | ICMP | `SOC_SEG subnets` | SOC_SEG address (pfSense) | — | Allow SOC hosts to ping router/firewall |
| ❌ Block | Any | Any | `Private_IPS` (alias) | — | Block access/pinging to home/private network ranges |
| ✅ Pass | Any | `SOC_SEG subnets` | Any | — | Allow internet access (updates/signature pulls) |
| ❌ Block | Any | Any | Any | — | Default deny (catch-all) |

📌 Evidence:  
- `docs/screenshots/pfsense_rules_soc_seg.png`

---

#### MGMT-SEG Rules
| Action | Proto | Source | Destination | Dest Port | Purpose |
|-------|-------|--------|-------------|----------|---------|
| ✅ Pass | Any | `192.168.30.100` | LAN subnets (CORP) | — | MGMT host can administer/monitor CORP endpoints |
| ✅ Pass | Any | `192.168.30.100` | `SOC_SEG subnets` | — | MGMT host can access SOC segment for tooling/triage |
| ✅ Pass | Any | `192.168.30.100` | This Firewall (self) | — | MGMT host can reach pfSense for administration |
| ❌ Block | Any | Any | `Private_IPS` (alias) | — | Block access/pinging to home/private network ranges |
| ✅ Pass | Any | `MGMT_SEG subnets` | Any | — | Allow internet access (admin tooling + VPS access) |
| ❌ Block | Any | Any | Any | — | Default deny (catch-all) |

📌 Evidence:  
- `docs/screenshots/pfsense_rules_mgmt_seg.png`

---

### Why This Matters (Employer-Friendly Summary)
These rules demonstrate practical enterprise fundamentals: **segmentation**, **least privilege**, and **secure management boundaries**. Even if an endpoint is compromised in CORP, the attacker cannot directly pivot into the SOC network or pfSense management interface, while still allowing the minimum traffic needed for monitoring, updates, and controlled adversary emulation.




