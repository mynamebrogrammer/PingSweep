const { exec } = require('child_process');
const fs = require('fs');
const util = require('util');
const execPromise = util.promisify(exec);
const ping = require('ping'); 
const os = require('os');
const crypto = require('crypto');
require('dotenv').config();

const ledgerFile = './known_assets.json';
const hashFile = './.baseline_hash';

// --- SECURITY: SHA-256 TAMPER DETECTION ---
function generateFileHash(filePath) {
    try {
        const fileBuffer = fs.readFileSync(filePath);
        const hashSum = crypto.createHash('sha256');
        hashSum.update(fileBuffer);
        return hashSum.digest('hex');
    } catch (error) {
        return null;
    }
}

// --- CHATOPS: DISCORD ALERTS ---
async function sendDiscordAlert(device) {
    const webhookUrl = process.env.DISCORD_WEBHOOK_URL;
    
    if (!webhookUrl) return;

    const payload = {
        content: "🚨 **SECURITY ALERT: Unauthorized Asset Detected** 🚨",
        embeds: [{
            title: "Rogue Device Details",
            color: 16711680, 
            fields: [
                { name: "MAC Address", value: device.MAC_Address, inline: true },
                { name: "IPv4 Address", value: device.IPv4, inline: true },
                { name: "IPv6 Address", value: device.IPv6, inline: true }
            ],
            footer: { text: "Authorized Asset Sentinel - Phase 1" },
            timestamp: new Date().toISOString()
        }]
    };

    try {
        await fetch(webhookUrl, {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify(payload)
        });
        console.log(`[+] SOC Alert dispatched to Discord successfully.`);
    } catch (error) {
        console.error(`[ERROR] Failed to send ChatOps alert: ${error.message}`);
    }
}

// --- CHATOPS: DISCORD HEARTBEAT ---
async function sendDiscordHeartbeat(deviceCount) {
    const webhookUrl = process.env.DISCORD_WEBHOOK_URL;
    
    if (!webhookUrl) return;

    const payload = {
        content: "✅ **SOC Update: Scheduled Scan Complete**",
        embeds: [{
            title: "Network Status: SECURE",
            color: 3066993, 
            description: `All **${deviceCount}** active devices match the authorized baseline. No anomalies detected.`,
            footer: { text: "Authorized Asset Sentinel - Phase 1" },
            timestamp: new Date().toISOString()
        }]
    };

    try {
        await fetch(webhookUrl, {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify(payload)
        });
        console.log(`[+] SOC Heartbeat dispatched to Discord successfully.`);
    } catch (error) {
        console.error(`[ERROR] Failed to send ChatOps heartbeat: ${error.message}`);
    }
}

// --- NETWORK CORE: SUBNET DISCOVERY ---
function getSubnetBase() {
    const interfaces = os.networkInterfaces();
    
    for (const name of Object.keys(interfaces)) {
        for (const iface of interfaces[name]) {
            if (iface.family === 'IPv4' && !iface.internal) {
                const ipParts = iface.address.split('.');
                return `${ipParts[0]}.${ipParts[1]}.${ipParts[2]}.`;
            }
        }
    }
    return '192.168.1.'; // Default fallback
}

// --- NETWORK CORE: CACHE WARMING ---
async function warmCache() {
    const subnetBase = getSubnetBase();
    console.log(`[INIT] Warming up ARP cache on ${subnetBase}0/24...`);
    let pingPromises = [];
    
    for (let i = 1; i < 255; i++) {
        pingPromises.push(ping.promise.probe(subnetBase + i, { timeout: 1 }));
    }
    
    await Promise.all(pingPromises);
    console.log(`[+] Cache warmed. Reading ledgers now...\n`);
}

// --- MAIN EXECUTION: DUAL-STACK SCAN ---
async function scanDualStackNetwork() {
    try {
        await warmCache();

        const [arpResult, ndpResult] = await Promise.all([
            execPromise('arp -a'),
            execPromise('netsh interface ipv6 show neighbors')
        ]);

        const deviceMap = new Map(); 

        // Parse IPv4
        const arpLines = arpResult.stdout.split('\n');
        const arpRegex = /\s*([0-9\.]+)\s+([a-fA-F0-9-]{17})\s+/; 
        
        arpLines.forEach(line => {
            const match = line.match(arpRegex);
            if (match) {
                const ip = match[1];
                const mac = match[2].toLowerCase();
                if (!ip.startsWith('224.') && !ip.startsWith('239.') && ip !== '255.255.255.255') {
                    deviceMap.set(mac, { MAC_Address: mac, IPv4: ip, IPv6: "None" });
                }
            }
        });

        // Parse IPv6
        const ndpLines = ndpResult.stdout.split('\n');
        const ndpRegex = /^\s*([a-fA-F0-9:]+)\s+([a-fA-F0-9-]{17})\s+(Reachable|Stale|Delay|Probe)/;
        
        ndpLines.forEach(line => {
            const match = line.match(ndpRegex);
            if (match) {
                const ip = match[1];
                const mac = match[2].toLowerCase();
                if (!ip.toLowerCase().startsWith('ff')) {
                    if (deviceMap.has(mac)) {
                        deviceMap.get(mac).IPv6 = ip;
                    } else {
                        deviceMap.set(mac, { MAC_Address: mac, IPv4: "None", IPv6: ip });
                    }
                }
            }
        });

        const liveDevices = Array.from(deviceMap.values());

        // --- SECURITY CORE: BASELINE COMPARISON ---
        if (!fs.existsSync(ledgerFile)) {
            console.log(`[!] No baseline found. Establishing new baseline with ${liveDevices.length} devices.`);
            fs.writeFileSync(ledgerFile, JSON.stringify(liveDevices, null, 4));
            
            // SEAL THE BASELINE
            const baselineHash = generateFileHash(ledgerFile);
            if (baselineHash) {
                fs.writeFileSync(hashFile, baselineHash);
                console.log(`[+] Baseline sealed with SHA-256 Hash: ${baselineHash.substring(0, 8)}...`);
            }
        } else {
            // TAMPER CHECK
            const currentHash = generateFileHash(ledgerFile);
            let savedHash = '';
            
            try {
                savedHash = fs.readFileSync(hashFile, 'utf8');
            } catch (err) {
                console.error(`[CRITICAL] Missing .baseline_hash file! Delete known_assets.json to rebuild the baseline safely.`);
                process.exit(1);
            }

            if (currentHash !== savedHash) {
                console.error(`\n[CRITICAL] TAMPER DETECTED! The known_assets.json file has been modified outside the script!`);
                console.error(`Expected: ${savedHash}`);
                console.error(`Found:    ${currentHash}\n`);
                process.exit(1);
            }

            console.log(`[+] Integrity Check Passed. Baseline is secure.`);

            // INTRUSION DETECTION
            const rawData = fs.readFileSync(ledgerFile);
            const knownAssets = JSON.parse(rawData);
            const knownMacs = knownAssets.map(asset => asset.MAC_Address);

            let rogueFound = false;
            for (const device of liveDevices) {
                if (!knownMacs.includes(device.MAC_Address)) {
                    console.log(`[ALERT] UNAUTHORIZED DEVICE DETECTED!`);
                    console.log(`        MAC:  ${device.MAC_Address}`);
                    console.log(`        IPv4: ${device.IPv4}`);
                    console.log(`        IPv6: ${device.IPv6}\n`);

                    await sendDiscordAlert(device);
                    rogueFound = true;
                }
            }

            if (!rogueFound) {
                console.log(`[SECURE] All ${liveDevices.length} live devices are authorized.`);
                console.table(liveDevices);
                await sendDiscordHeartbeat(liveDevices.length);
            }
        }
    } catch (error) {
        console.error(`[ERROR] Script failed: ${error.message}`);
    }
}

// Ignite the Sentinel
scanDualStackNetwork();