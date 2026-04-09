
const { exec } = require('child_process');
const fs = require('fs');

const command = 'netsh interface ipv6 show neighbors';
const ledgerFile = './known_assets.json';

console.log(`[INIT] Scanning network for physical assets...\n`);


exec(command, (error, stdout, stderr) => {
    if (error) {
        console.error(`[ERROR] ${error.message}`);
        return;
    }

    const lines = stdout.split('\n');
    const liveDevices = [];
    const regex = /^\s*([a-fA-F0-9:]+)\s+([a-fA-F0-9-]{17})\s+(Reachable|Stale|Delay|Probe)/;

    // Parse the live data
    lines.forEach(line => {
        const match = line.match(regex);
        if (match) {
            const ip = match[1];
            const mac = match[2];
            if (!ip.toLowerCase().startsWith('ff')) {
                liveDevices.push({ IP_Address: ip, MAC_Address: mac });
            }
        }
    });

    // Check if we have a baseline ledger
    if (!fs.existsSync(ledgerFile)) {
        console.log(`[!] No baseline found. Establishing new baseline with ${liveDevices.length} devices.`);
        
        // Create the JSON ledger
        fs.writeFileSync(ledgerFile, JSON.stringify(liveDevices, null, 4));
        console.log(`[+] Baseline saved to ${ledgerFile}.`);
        console.log(`[ACTION] Please open ${ledgerFile} and add a "Device_Name" to each entry.`);
    } else {
        // Load the existing ledger
        const rawData = fs.readFileSync(ledgerFile);
        const knownAssets = JSON.parse(rawData);
        const knownMacs = knownAssets.map(asset => asset.MAC_Address);

        console.log(`[+] Baseline loaded. Comparing live scan against known assets...\n`);
        
        let rogueFound = false;

        liveDevices.forEach(device => {
            if (!knownMacs.includes(device.MAC_Address)) {
                console.log(`[ALERT] UNAUTHORIZED DEVICE DETECTED!`);
                console.log(`        IP: ${device.IP_Address}`);
                console.log(`        MAC: ${device.MAC_Address}\n`);
                rogueFound = true;
            }
        });

        if (!rogueFound) {
            console.log(`[SECURE] All ${liveDevices.length} live devices are authorized.`);
        }
    }
});
