
# Enterprise Security & Adversary Emulation Lab (Purple Team Home Lab)

A custom-built Purple Team home lab that simulates a segmented enterprise network, centralizes endpoint telemetry, and validates detections using automated adversary emulation with a hybrid-cloud C2.

> **Goal:** Build a resilient, observable environment (Defense-in-Depth) and prove detection/visibility using real tactics aligned to **MITRE ATT&CK**.

---

## Table of Contents
- [Lab Goals](#lab-goals)
- [Architecture Overview](#architecture-overview)
- [Network Segmentation](#network-segmentation-micro-segmentation)
- [pfSense Firewall Rules](#pfsense-firewall-rules-segmentation-enforcement)
- [Security Stack](#security-stack)
- [Purple Team Validations](#purple-team-validations)
  - [Windows: Process Discovery (T1057)](#windows-process-discovery-t1057)
  - [Linux: Data Staging + Exfiltration (Multi-Technique)](#linux-data-staging--exfiltration-multi-technique)
- [Key Outcomes](#key-outcomes)
- [Future Optimization](#future-optimization)

---
---

## 🧭 Lab Goals
This lab was designed to demonstrate practical security engineering and detection validation:
- **Micro-segmentation** to reduce lateral movement
- **Centralized logging + endpoint visibility** via SIEM/EDR-style telemetry
- **Network inspection at the choke point** (gateway-level IDS)
- **Adversary emulation** using a cloud-hosted C2 to simulate realistic attacker workflows
- Evidence-driven reporting aligned to **MITRE ATT&CK**

---

## 🛣️ Architecture/Data Flow Overview

### High-Level Data Flow
- Endpoints generate host telemetry → **Wazuh** (SIEM/EDR-style manager)
- Network traffic traverses pfSense → **Suricata** inspects traffic at the gateway
- Adversary emulation executes from a cloud VPS → **Caldera** controls agents in the lab

**Diagram:**
docs/diagrams/lab-architecture.png`

---
---

## 🌐 Network Segmentation (Micro-Segmentation)

![Network Topology](images/diagrams/NetworkTopology.png)

The lab is segmented into distinct security zones using pfSense as the central router/firewall. Each subnet represents a separate trust boundary to reduce lateral movement and enforce least-privilege network access.

## Segments (As Implemented)

### PfSense Virtual Machine Configurations ###
![VM pfSense](images/screenshots/Pfsense_Infrastructure.png)


| Segment | CIDR / Subnet | Gateway | Role | Key Assets |
|--------|----------------|---------|------|------------|
| **WAN** | `192.168.224.0/24` | `192.168.224.138` | External interface for internet connectivity (updates + outbound C2 traffic) | pfSense WAN |
| **CORP-SEG** | `192.168.20.0/24` | `192.168.20.1` | Corporate user tier (attack simulation targets) | Ubuntu Desktop `192.168.20.103`, Windows 10 `192.168.20.106` |
| **SOC-SEG** | `192.168.10.0/24` | `192.168.10.1` | Security operations zone (central telemetry + monitoring tools) | Security Tools Server `192.168.10.100` (Wazuh, Docker/Portainer) |
| **MGMT-SEG** | `192.168.30.0/24` | `192.168.30.1` | Administrative/management tier (controlled cross-segment access) | Monitoring Host `192.168.30.100` |

### Segmentation Objectives
- **Contain compromise:** A compromised CORP endpoint should not directly reach SOC systems.
- **Protect security tooling:** SOC-SEG remains isolated and only accepts explicitly required traffic (e.g., Wazuh agents).
- **Centralize control:** All cross-segment and internet-bound traffic routes through **pfSense**, where firewall policy and inspection are enforced.
- **Realistic enterprise model:** Separating CORP, SOC, and MGMT mirrors common real-world architectures.

---
---

## 🧰 pfSense Firewall Rules (Segmentation Enforcement)

pfSense serves as the lab’s central **router + firewall**, enforcing **least privilege** between security zones. Rules are intentionally simple and auditable: explicitly allow only what is required (telemetry, basic connectivity, internet access for updates/C2), block sensitive internal access paths, and rely on a final deny rule to prevent accidental exposure.

### Design Goals
- Allow endpoint telemetry to the **SOC tools server (Wazuh)** while keeping SOC isolated
- Prevent **CORP → SOC** access (reduce lateral movement paths)
- Prevent endpoints from accessing the **pfSense management interface**
- Block access to **Private/Home networks** (safety boundary)
- Permit controlled **internet access** for updates + adversary emulation workflows
- Enforce a **default-deny** baseline

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
![CORP-SEG pfSense rules](images/screenshots/CORP_LAN_seg_firewall_rules.png)

#### SOC-SEG Rules
| Action | Proto | Source | Destination | Dest Port | Purpose |
|-------|-------|--------|-------------|----------|---------|
| ✅ Pass | ICMP | `SOC_SEG subnets` | SOC_SEG address (pfSense) | — | Allow SOC hosts to ping router/firewall |
| ❌ Block | Any | Any | `Private_IPS` (alias) | — | Block access/pinging to home/private network ranges |
| ✅ Pass | Any | `SOC_SEG subnets` | Any | — | Allow internet access (updates/signature pulls) |
| ❌ Block | Any | Any | Any | — | Default deny (catch-all) |

📌 Evidence:  
![SOC-SEG pfSense rules](images/screenshots/SOC_seg_firewall_rules.png)

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
![MGMT-SEG pfSense rules](images/screenshots/MGMT_firewall_rules.png)

## WAN Rules ##
![WAN pfSense rules](images/screenshots/WAN_firewall_rules.png)


### Why This Matters
These rules demonstrate practical enterprise fundamentals: **segmentation**, **least privilege**, and **secure management boundaries**. Even if an endpoint is compromised in CORP, the attacker cannot directly pivot into the SOC network or pfSense management interface, while still allowing the minimum traffic needed for monitoring, updates, and controlled adversary emulation.

---
---

## 🛡️ Security Stack

### Endpoint Telemetry and Detection (Wazuh)
- Wazuh agents deployed to endpoints for continuous telemetry
- **File Integrity Monitoring (FIM)** enabled on Linux + Windows
- Enhanced Windows auditing for scripting visibility
  - PowerShell logging (including script block events like **Event ID 4104**)

**Proof of Agent Integration**
![Windows: Process Discovery](images/screenshots/MGMT_seg_agents_and_ips.png)

![Windows: Process Discovery](images/screenshots/CORP_seg_linux_host_IP.png)

![Windows: Process Discovery](images/screenshots/Corp_seg_windows_host_IP.png)


### Network IDS at the Choke Point (Suricata on pfSense)
- Suricata runs directly on pfSense to inspect north-south and inter-segment traffic
- **ET Open / Emerging Threats** ruleset enabled for current network signatures

### Adversary Emulation (Caldera on VPS)
- **Cloud-hosted Caldera** on a Linode VPS (hybrid-cloud C2)
- Caldera agents installed on CORP endpoints and configured to beacon over HTTP/HTTPS

---
---

## 🎯 Purple Team Validations

### Windows: Process Discovery (T1057)
- **Objective:** Validate detection and visibility for local reconnaissance on a Windows endpoint.
- **Adversary Technique:** **T1057** – Process Discovery
- **Emulation:** Caldera executed an automated profile on the Windows host to enumerate running processes and query system information.

  ![Windows: Process Discovery](images/screenshots/attack_map_used_on_windows_host.png)


#### Detection Evidence
- **Endpoint Level:** The Wazuh agent successfully captured the execution of obfuscated and clear-text PowerShell scripts.
- **Telemetry Verification:** As seen in the screenshots, Wazuh alerted on Event ID 4104, providing full visibility into the script content, including directory expansion and system variable queries.
- **FIM/integrity alerts** Wazuh triggered alerts for Registry Integrity Checksum changes, identifying the attacker's attempt to modify system persistence or configurations during the enumeration phase.

✅ **Result:** Host-level telemetry provided actionable visibility into discovery activity.

**Predicted Catched Output on Wazuh Dashboard**

📌 Results:  
![Windows: Process Discovery](images/screenshots/Windows_attack_initial.png)
![Windows: Process Discovery](images/screenshots/Windows_attack_proof_final_output.png)


---

### Linux: Data Staging + Exfiltration (Multi-Technique)

**Objective:** Validate network and endpoint visibility against staged collection and exfiltration behavior.

**MITRE ATT&CK Techniques**
- **T1005** – Data from Local System  
- **T1074.001** – Local Data Staging  
- **T1560.001** – Archive via Utility  
- **T1041** – Exfiltration Over C2 Channel

![Linux: Multi-Technique](images/screenshots/attack_map_used_on_linux_host.png)


**Emulation Workflow**
1. Collected local data  
2. Staged it in a hidden directory  
3. Archived it as `staged.tar.gz`  
4. Exfiltrated over the C2 channel to the Caldera VPS  

![Linux: Multi-Technique](images/screenshots/Actually_attack_enumerations_on_linux.png)


#### Detection Evidence
- **Suricata** flagged suspicious C2 communication  
  - Example: `ET MALWARE Golang/Sandcat Plugin Activity (POST)`
  - Outbound connection to VPS IP `172.238.183.44`
- **Wazuh FIM** alerted on archive creation  
  - `/home/x-ra/staged.tar.gz` added  
- Manual verification confirmed staged artifacts on disk

✅ **Result:** Network + endpoint telemetry correlated to confirm the attack chain.

📌 Screenshots:  
![Linux: Multi-Technique](images/screenshots/Linux_file_created_proof_on_host.png)
![Linux: Multi-Technique](images/screenshots/linux_file_created_log_generated_on_wazuh_dashboard.png)
![Linux: Multi-Technique](images/screenshots/Linux_exfiltration_proof_from_suricata_logs.png)

 
---
---

## Key Outcomes
- **Segmentation enforced (Defense-in-Depth):** pfSense micro-segmentation created clear trust boundaries between CORP, SOC, and MGMT to reduce lateral movement risk.
- **Actionable endpoint visibility:** Wazuh provided host-level telemetry (Windows auditing + FIM) to detect discovery and file/registry changes tied to attacker behavior.
- **Network-level detection at the choke point:** Suricata on pfSense detected suspicious outbound C2-style traffic using Emerging Threats signatures.
- **Validated purple team workflow:** Adversary emulation (Caldera) produced repeatable attack chains mapped to **MITRE ATT&CK**, with detections confirmed through log evidence and screenshots.

---

## 🔭 Future Optimization
Next planned enhancement: develop a custom **Wazuh decoder** for **Suricata JSON** ingestion.

**Why:** This moves the lab from multiple consoles to a true **single pane of glass** for correlation and triage.
