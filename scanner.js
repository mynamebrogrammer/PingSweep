const { exec } = require('child_process');
const fs = require('fs');
const util = require('util');
const execPromise = util.promisify(exec);
const ping = require('ping'); 
const os = require('os');

const ledgerFile = './known_assets.json';

function getSubnetBase() {
    const interfaces = os.networkInterfaces();
    
    for (const name of Object.keys(interfaces)) {
        for (const iface of interfaces[name]) {
            // We want an IPv4 address that is NOT the localhost (127.0.0.1)
            if (iface.family === 'IPv4' && !iface.internal) {
                // If your IP is 192.168.1.45, split it into [192, 168, 1, 45]
                const ipParts = iface.address.split('.');
                // Recombine the first three parts and add a dot: "192.168.1."
                return `${ipParts[0]}.${ipParts[1]}.${ipParts[2]}.`;
            }
        }
    }
    return '192.168.1.'; // Fallback just in case
}

async function warmCache() {
    const subnetBase = getSubnetBase();
    console.log(`[INIT] Warming up ARP cache on ${subnetBase}0/24...`);
    let pingPromises = [];
    
    // Ping 1-254 very quickly (1 second timeout) just to force a cache update
    for (let i = 1; i < 255; i++) {
        pingPromises.push(ping.promise.probe(subnetBase + i, { timeout: 1 }));
    }
    
    await Promise.all(pingPromises);
    console.log(`[+] Cache warmed. Reading ledgers now...\n`);
}

async function scanDualStackNetwork() {
    try {
        // Step 1: Wake up the network so the cache is full
        await warmCache();

        // Step 2: Read the freshly populated caches
        const [arpResult, ndpResult] = await Promise.all([
            execPromise('arp -a'),
            execPromise('netsh interface ipv6 show neighbors')
        ]);

        const deviceMap = new Map(); 

        // Parse IPv4 (ARP)
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

        // Parse IPv6 (NDP)
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

        // Step 3: Compare against Ledger
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
                    rogueFound = true;
                }
            });

            if (!rogueFound) {
                console.log(`[SECURE] All ${liveDevices.length} live devices are authorized.`);
                console.table(liveDevices);
            }
        }
    } catch (error) {
        console.error(`[ERROR] Script failed: ${error.message}`);
    }
}

scanDualStackNetwork();