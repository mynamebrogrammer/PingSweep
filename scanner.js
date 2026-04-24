const { exec } = require("child_process");
const fs = require("fs");
const util = require("util");
const execPromise = util.promisify(exec);
const ping = require("ping");
const os = require("os");
const crypto = require("crypto");
const net = require("net");

const TARGET_PORTS = [21, 22, 23, 50, 54, 80, 443, 445, 3389];

require("dotenv").config();

const ledgerFile = "./known_assets.json";
const hashFile = "./.baseline_hash";

// SECURITY: SHA-256 TAMPER DETECTION
function generateFileHash(filePath) {
  try {
    const fileBuffer = fs.readFileSync(filePath);
    const hashSum = crypto.createHash("sha256");
    hashSum.update(fileBuffer);
    return hashSum.digest("hex");
  } catch (error) {
    return null;
  }
}
// --- LAYER 4: PORT AUDITING ---
async function checkPort(ip, port) {
  return new Promise((resolve) => {
    const socket = new net.Socket();
    socket.setTimeout(1000);

    socket.on("connect", () => {
      socket.destroy();
      resolve(port); // Return the port number if OPEN
    });

    socket.on("timeout", () => {
      socket.destroy();
      resolve(null); // Return null if closed/filtered
    });

    socket.on("error", () => {
      socket.destroy();
      resolve(null); // Return null if closed
    });

    socket.connect(port, ip);
  });
}

async function scanDevicePorts(ip) {
  if (!ip || ip === "None") return [];

  // Scan all target ports simultaneously for speed
  const results = await Promise.all(
    TARGET_PORTS.map((port) => checkPort(ip, port)),
  );

  // Filter out the nulls, leaving only the open ports
  return results.filter((port) => port !== null);
}

// DISCORD ALERTS
async function sendDiscordAlert(device) {
  const webhookUrl = process.env.DISCORD_WEBHOOK_URL;

  if (!webhookUrl) return;

  const payload = {
    content: " **SECURITY ALERT: Unauthorized Asset Detected**",
    embeds: [
      {
        title: "Rogue Device Details",
        color: 16711680,
        fields: [
          { name: "MAC Address", value: device.MAC_Address, inline: true },
          { name: "IPv4 Address", value: device.IPv4, inline: true },
          { name: "IPv6 Address", value: device.IPv6, inline: true },
        ],
        footer: { text: "Authorized Asset Sentinel - Phase 1" },
        timestamp: new Date().toISOString(),
      },
    ],
  };

  try {
    await fetch(webhookUrl, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify(payload),
    });
    console.log(`[+] SOC Alert dispatched to Discord successfully.`);
  } catch (error) {
    console.error(`[ERROR] Failed to send ChatOps alert: ${error.message}`);
  }
}

// DISCORD HEARTBEAT
async function sendDiscordHeartbeat(deviceCount) {
  const webhookUrl = process.env.DISCORD_WEBHOOK_URL;

  if (!webhookUrl) return;

  const payload = {
    content: "✅ **SOC Update: Scheduled Scan Complete**",
    embeds: [
      {
        title: "Network Status: SECURE",
        color: 3066993,
        description: `All **${deviceCount}** active devices match the authorized baseline. No anomalies detected.`,
        footer: { text: "Authorized Asset Sentinel - Phase 1" },
        timestamp: new Date().toISOString(),
      },
    ],
  };

  try {
    await fetch(webhookUrl, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify(payload),
    });
    console.log(`[+] SOC Heartbeat dispatched to Discord successfully.`);
  } catch (error) {
    console.error(`[ERROR] Failed to send ChatOps heartbeat: ${error.message}`);
  }
}

// SUBNET DISCOVERY
function getSubnetBase() {
  const interfaces = os.networkInterfaces();

  for (const name of Object.keys(interfaces)) {
    for (const iface of interfaces[name]) {
      if (iface.family === "IPv4" && !iface.internal) {
        const ipParts = iface.address.split(".");
        return `${ipParts[0]}.${ipParts[1]}.${ipParts[2]}.`;
      }
    }
  }
  return "192.168.1."; // Default fallback
}

// CACHE WARMING
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
      execPromise("arp -a"),
      execPromise("netsh interface ipv6 show neighbors"),
    ]);

    const deviceMap = new Map();

    // Parse IPv4
    const arpLines = arpResult.stdout.split("\n");
    const arpRegex = /\s*([0-9\.]+)\s+([a-fA-F0-9-]{17})\s+/;

    arpLines.forEach((line) => {
      const match = line.match(arpRegex);
      if (match) {
        const ip = match[1];
        const mac = match[2].toLowerCase();
        if (
          !ip.startsWith("224.") &&
          !ip.startsWith("239.") &&
          ip !== "255.255.255.255"
        ) {
          deviceMap.set(mac, { MAC_Address: mac, IPv4: ip, IPv6: "None" });
        }
      }
    });

    // Parse IPv6
    const ndpLines = ndpResult.stdout.split("\n");
    const ndpRegex =
      /^\s*([a-fA-F0-9:]+)\s+([a-fA-F0-9-]{17})\s+(Reachable|Stale|Delay|Probe)/;

    ndpLines.forEach((line) => {
      const match = line.match(ndpRegex);
      if (match) {
        const ip = match[1];
        const mac = match[2].toLowerCase();
        if (!ip.toLowerCase().startsWith("ff")) {
          if (deviceMap.has(mac)) {
            deviceMap.get(mac).IPv6 = ip;
          } else {
            deviceMap.set(mac, { MAC_Address: mac, IPv4: "None", IPv6: ip });
          }
        }
      }
    });

    const rawDevices = Array.from(deviceMap.values());

    console.log(`[🔎] Auditing TCP ports on discovered devices...`);
    const liveDevicesPromises = rawDevices.map(async (device) => {
      const openPorts = await scanDevicePorts(device.IPv4);
      return {
        ...device,
        Open_Ports: openPorts,
      };
    });
    const liveDevices = await Promise.all(liveDevicesPromises);

    //  BASELINE COMPARISON
    if (!fs.existsSync(ledgerFile)) {
      console.log(
        `[!] No baseline found. Establishing new baseline with ${liveDevices.length} devices.`,
      );
      fs.writeFileSync(ledgerFile, JSON.stringify(liveDevices, null, 4));

      const baselineHash = generateFileHash(ledgerFile);
      if (baselineHash) {
        fs.writeFileSync(hashFile, baselineHash);
        console.log(
          `[+] Baseline sealed with SHA-256 Hash: ${baselineHash.substring(0, 8)}...`,
        );
      }
    } else {
      // TAMPER CHECK
      const currentHash = generateFileHash(ledgerFile);
      let savedHash = "";

      try {
        savedHash = fs.readFileSync(hashFile, "utf8");
      } catch (err) {
        console.error(
          `[CRITICAL] Missing .baseline_hash file! Delete known_assets.json to rebuild the baseline safely.`,
        );
        process.exit(1);
      }

      if (currentHash !== savedHash) {
        console.error(
          `\n[CRITICAL] TAMPER DETECTED! The known_assets.json file has been modified outside the script!`,
        );
        console.error(`Expected: ${savedHash}`);
        console.error(`Found:    ${currentHash}\n`);
        process.exit(1);
      }

      console.log(`[+] Integrity Check Passed. Baseline is secure.`);

      // INTRUSION DETECTION
      const rawData = fs.readFileSync(ledgerFile);
      const knownAssets = JSON.parse(rawData);
      const knownMacs = knownAssets.map((asset) => asset.MAC_Address);

      let rogueFound = false;
      for (const device of liveDevices) {
        const knownAsset = knownAssets.find(
          (asset) => asset.MAC_Address === device.MAC_Address,
        );

        if (!knownAsset) {
          console.log(`[ALERT] UNAUTHORIZED DEVICE DETECTED!`);
          console.log(`        MAC:  ${device.MAC_Address}`);
          console.log(`        IPv4: ${device.IPv4}`);
          console.log(`        IPv6: ${device.IPv6}\n`);

          await sendDiscordAlert(device);
          rogueFound = true;
        } else {
          const baselinePorts = knownAsset.Open_Ports || [];
          const suspiciousPorts = device.Open_Ports.filter(
            (port) => !baselinePorts.includes(port),
          );

          if (suspiciousPorts.length > 0) {
            console.log(
              `[warning] SUSPICIOUS PORT ACTIVITY DETECTED on ${device.MAC_Address}!`,
            );
            console.log(
              `          Baseline Open Ports: ${baselinePorts.length > 0 ? baselinePorts.join(", ") : "None"}`,
            );
            console.log(
              `          Current Open Ports:  ${device.Open_Ports.length > 0 ? device.Open_Ports.join(", ") : "None"}`,
            );
            console.log(
              `          New Suspicious Ports: ${suspiciousPorts.join(", ")}\n`,
            );

            // --- ADD THESE TWO LINES ---
            await sendDiscordAlert(device);
            rogueFound = true;
          }
          // Optional: Compare IP addresses and open ports for known devices to detect changes
          if (
            knownAsset.IPv4 !== device.IPv4 ||
            knownAsset.IPv6 !== device.IPv6
          ) {
            console.log(
              `[WARNING] Known device ${device.MAC_Address} has changed IP address!`,
            );
            console.log(
              `          Previous IPv4: ${knownAsset.IPv4}, Current IPv4: ${device.IPv4}`,
            );
            console.log(
              `          Previous IPv6: ${knownAsset.IPv6}, Current IPv6: ${device.IPv6}\n`,
            );
          }
        }
      }

      if (!rogueFound) {
        console.log(
          `[SECURE] All ${liveDevices.length} live devices are authorized.`,
        );
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
