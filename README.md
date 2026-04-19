# PingSweep (Lightweight NAC)

## Project Overview
As part of my transition into Cybersecurity Engineering, I developed this custom Node.js application to act as a lightweight **Network Access Control (NAC)** system.

This tool performs automated asset discovery on local networks by directly querying the operating system's Neighbor Discovery Protocol (NDP) and ARP caches, effectively bypassing standard ICMP firewall blocks. It establishes a secure cryptographic baseline of known devices and alerts administrators in real-time when an unauthorized hardware MAC address is detected on the network.

## Skills Demonstrated
* **Asset Management:** Establishing, validating, and monitoring a secure baseline ledger (`known_assets.json`).
* **Network Security:** Deep understanding of TCP/IP, IPv6 Multicast, and MAC-to-IP resolution protocols.
* **Custom Security Tooling:** Utilizing JavaScript (Node.js) and the `child_process` module to parse and structure raw system logs into actionable threat intelligence.
* **Operational Security (OPSEC):** Implementing strict `.gitignore` policies to ensure local network topologies and physical hardware addresses are never leaked to public repositories.

## Installation & Setup

1. **Clone the repository**
2. 
        npm install ping dotenv 
        npm install -g pm2
3. To receive real-time alerts, you must provide your own Discord Webhook URL.

    Open your Discord server, click the gear icon next to a text channel to Edit Channel.

    Navigate to Integrations -> Webhooks -> New Webhook.

    Name your bot, click Copy Webhook URL, and save changes.

    In the root directory of this project, create a new file named exactly .env.

    Open the .env file and paste your URL in the following format:

    DISCORD_WEBHOOK_URL=[https://discord.com/api/webhooks/YOUR_UNIQUE_URL_HERE](https://discord.com/api/webhooks/YOUR_UNIQUE_URL_HERE)
    Ensure .env is included in your .gitignore to prevent leaking your private server webhook to the public.
### To run the script manually:
4. ```bash
   node scanner.js
   ```
### To run the script in the background with PM2:
5. ```bash
   pm2 start scanner.js --name "Asset-Sentinel" --cron "0 8,20 * * *" --no-autorestart
   ```
   This will keep the script running continuously, automatically restarting it if it crashes or if you make changes to the code.

   save the current PM2 process list and configuration:
   ```bash 
   pm2 save

## Terminal Demonstration
*Note: IP and MAC addresses below have been sanitized for OPSEC purposes.*

**Establishing the Baseline:**
```text
[INIT] Auto-detected local subnet: 192.168.1.0/24
[INIT] Warming up ARP cache...
[+] Cache warmed. Reading ledgers now...

[!] No baseline found. Establishing new baseline with 6 devices.
[+] Baseline saved to ./known_assets.json.

```

```text
[INIT] Auto-detected local subnet: 192.168.1.0/24
[INIT] Warming up ARP cache...
[+] Cache warmed. Reading ledgers now...

[ALERT] UNAUTHORIZED DEVICE DETECTED!
        MAC:  a1-b2-c3-x9-y8-z7
        IPv4: 192.168.1.105
        IPv6: fe80::1c4b:abcd:9999:0000

[+] SOC Alert dispatched to Discord successfully.
