const { exec } = require('child_process');
const fs = require('fs');
const util = require('util');
const execPromise = util.promisify(exec);
const ping = require('ping'); 
const os = require('os');
require('dotenv').config();

const ledgerFile = './known_assets.json';

// --- NEW CHATOPS ALERTING LOGIC ---
async function sendDiscordAlert(device) {
    const webhookUrl = process.env.DISCORD_WEBHOOK_URL;
    
    // Safety check: if you didn't set up the URL in the .env file, skip the alert
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
            footer: { text: "Authorized Asset Sentinel" },
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
async function sendDiscordHeartbeat(deviceCount) {
    const webhookUrl = process.env.DISCORD_WEBHOOK_URL;
    
    if (!webhookUrl) return;

    const payload = {
        content: "✅ **SOC Update: Scheduled Scan Complete**",
        embeds: [{
            title: "Network Status: SECURE",
            color: 3066993, // Hex code for Green
            description: `All **${deviceCount}** active devices match the authorized baseline. No anomalies detected.`,
            footer: { text: "Authorized Asset Sentinel" },
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
    return '192.168.1.'; 
}

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

async function scanDualStackNetwork() {
    try {
        await warmCache();

        const [arpResult, ndpResult] = await Promise.all([
            execPromise('arp -a'),
            execPromise('netsh interface ipv6 show neighbors')
        ]);

        const deviceMap = new Map(); 

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

        if (!fs.existsSync(ledgerFile)) {
            console.log(`[!] No baseline found. Establishing new baseline with ${liveDevices.length} devices.`);
            fs.writeFileSync(ledgerFile, JSON.stringify(liveDevices, null, 4));
        } else {
            const rawData = fs.readFileSync(ledgerFile);
            const knownAssets = JSON.parse(rawData);
            const knownMacs = knownAssets.map(asset => asset.MAC_Address);

            let rogueFound = false;
            liveDevices.forEach(device => {
                if (!knownMacs.includes(device.MAC_Address)) {
                    console.log(`[ALERT] UNAUTHORIZED DEVICE DETECTED!`);
                    console.log(`        MAC:  ${device.MAC_Address}`);
                    console.log(`        IPv4: ${device.IPv4}`);
                    console.log(`        IPv6: ${device.IPv6}\n`);
                    
                    // --- TRIGGER DISCORD ALERT ---
                    await sendDiscordAlert(device);
                    
                    rogueFound = true;
                }
            });

            if (!rogueFound) {
                console.log(`[SECURE] All ${liveDevices.length} live devices are authorized.`);
                console.table(liveDevices);

                // --- TRIGGER DISCORD HEARTBEAT ---
                await sendDiscordHeartbeat(liveDevices.length);
            }
        }
    } catch (error) {
        console.error(`[ERROR] Script failed: ${error.message}`);
    }
}

scanDualStackNetwork();