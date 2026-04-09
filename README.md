# PingSweep or Asset Sentinel (Lightweight NAC)

## Project Overview

As part of my transition into Cybersecurity Engineering, I developed this custom Node.js application to act as a lightweight **Network Access Control (NAC)** system.

This tool performs automated asset discovery on local networks by directly querying the operating system's Neighbor Discovery Protocol (NDP) and ARP caches, bypassing standard ICMP firewall blocks. It establishes a secure baseline of known devices and alerts administrators in real-time when an unauthorized hardware MAC address is detected.

## Skills Demonstrated

* **Asset Management:** Establishing and monitoring a secure baseline ledger (`known_assets.json`).
* **Network Security:** Understanding TCP/IP, IPv6 Multicast, and MAC-to-IP resolution.
* **Custom Tooling:** Using JavaScript (Node.js) and the `child_process` module to parse raw system logs into structured, actionable JSON data.
* **Operational Security (OPSEC):** Implemented `.gitignore` policies to ensure local network topologies and physical hardware addresses are not leaked to public repositories.

## How It Works

1. **System Query:** The script uses `netsh` (Windows) or `ndp/ip` (Unix) to quietly read the local network cache without triggering IDS/IPS alerts via active pinging.
2. **Data Normalization:** A custom Regular Expression (Regex) parses the raw terminal output, stripping away multicast noise to isolate physical IPv4/IPv6 addresses and their corresponding MAC addresses.
3. **Baseline Comparison:** The live data is compared against an established `known_assets.json` ledger.
4. **Intrusion Alerting:** If a detected MAC address is not found in the ledger, the system flags it as a rogue device.

## Demonstration

*Note: IP and MAC addresses below have been sanitized for OPSEC purposes.*

**Establishing the Baseline:**

```text

[INIT] Scanning network for physical assets...
[!] No baseline found. Establishing new baseline with 4 devices.
[+] Baseline saved to ./known_assets.json.

[INIT] Scanning network for physical assets...
[+] Baseline loaded. Comparing live scan against known assets...

[ALERT] UNAUTHORIZED DEVICE DETECTED!
        IP: fe80::1c4b:abcd:9999:0000
        MAC: a1-b2-c3-x9-y8-z7

[SECURE] 4 live devices are authorized.
