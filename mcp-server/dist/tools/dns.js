import { Resolver } from "dns/promises";
import { execFile } from "child_process";
import { promisify } from "util";
import { validateTarget } from "../utils/sanitization.js";
import os from "os";
import net from "net";
const execFilePromise = promisify(execFile);
// Helper to query a specific resolver
async function queryResolver(dnsServer, hostname, recordType) {
    const resolver = new Resolver();
    if (dnsServer) {
        resolver.setServers([dnsServer]);
    }
    try {
        switch (recordType.toUpperCase()) {
            case "A":
                return await resolver.resolve4(hostname);
            case "AAAA":
                return await resolver.resolve6(hostname);
            case "CNAME":
                return await resolver.resolveCname(hostname);
            case "MX":
                return await resolver.resolveMx(hostname);
            case "TXT":
                return await resolver.resolveTxt(hostname);
            case "NS":
                return await resolver.resolveNs(hostname);
            default:
                return await resolver.resolve(hostname, recordType);
        }
    }
    catch (err) {
        return { error: err.code || err.message };
    }
}
/**
 * 1. dns_propagation_check
 */
export async function dnsPropagationCheck(hostname, recordType = "A") {
    const cleanHost = validateTarget(hostname);
    const type = recordType.toUpperCase();
    const allowedTypes = ["A", "AAAA", "CNAME", "MX", "TXT", "NS"];
    if (!allowedTypes.includes(type)) {
        throw new Error(`Unsupported record type: ${recordType}. Supported: ${allowedTypes.join(", ")}`);
    }
    const servers = {
        Google: "8.8.8.8",
        Cloudflare: "1.1.1.1",
        Quad9: "9.9.9.9",
        Local: null // Uses VPS default resolver
    };
    const results = {};
    await Promise.all(Object.entries(servers).map(async ([name, ip]) => {
        results[name] = await queryResolver(ip, cleanHost, type);
    }));
    return {
        hostname: cleanHost,
        record_type: type,
        resolvers: results
    };
}
/**
 * 2. icmp_ping
 */
export async function icmpPing(target, count = 4) {
    const cleanTarget = validateTarget(target);
    const pingCount = Math.min(Math.max(1, count), 20); // Clamp count between 1 and 20
    const isWin = os.platform() === "win32";
    const cmd = isWin ? "ping" : "ping";
    // On Windows, -n specifies count. On Linux/macOS, it's -c.
    const args = isWin ? ["-n", pingCount.toString(), cleanTarget] : ["-c", pingCount.toString(), cleanTarget];
    try {
        const { stdout } = await execFilePromise(cmd, args, { timeout: 10000 });
        return parsePingOutput(stdout, cleanTarget);
    }
    catch (error) {
        // Ping returns non-zero code on complete/partial packet loss
        if (error.stdout) {
            return parsePingOutput(error.stdout, cleanTarget);
        }
        return {
            target: cleanTarget,
            success: false,
            error: error.message || "Failed to execute ping"
        };
    }
}
function parsePingOutput(stdout, target) {
    // Parse packet loss
    const lossMatch = stdout.match(/(\d+)% packet loss/i) || stdout.match(/loss = (\d+)%/i);
    const lossPercentage = lossMatch ? parseInt(lossMatch[1], 10) : 100;
    // Parse RTT (Min/Avg/Max/Mdev)
    // Linux: rtt min/avg/max/mdev = 1.121/1.432/1.890/0.312 ms
    // macOS: round-trip min/avg/max/stddev = 1.121/1.432/1.890/0.312 ms
    // Windows: Minimum = 1ms, Maximum = 2ms, Average = 1ms
    let rtt = null;
    const rttMatchLinux = stdout.match(/(rtt|round-trip) min\/avg\/max\/(mdev|stddev) = ([0-9.]+)\/([0-9.]+)\/([0-9.]+)\/([0-9.]+)/i);
    if (rttMatchLinux) {
        rtt = {
            min_ms: parseFloat(rttMatchLinux[3]),
            avg_ms: parseFloat(rttMatchLinux[4]),
            max_ms: parseFloat(rttMatchLinux[5]),
            mdev_ms: parseFloat(rttMatchLinux[6])
        };
    }
    else {
        const minWin = stdout.match(/Minimum = (\d+)ms/i);
        const maxWin = stdout.match(/Maximum = (\d+)ms/i);
        const avgWin = stdout.match(/Average = (\d+)ms/i);
        if (minWin && maxWin && avgWin) {
            rtt = {
                min_ms: parseFloat(minWin[1]),
                avg_ms: parseFloat(avgWin[1]),
                max_ms: parseFloat(maxWin[1]),
                mdev_ms: 0
            };
        }
    }
    return {
        target,
        success: lossPercentage < 100,
        packet_loss_percentage: lossPercentage,
        rtt,
        raw_output: stdout.trim()
    };
}
/**
 * 3. mtu_path_discovery
 */
export async function mtuPathDiscovery(target, startSize = 1500) {
    const cleanTarget = validateTarget(target);
    let size = Math.min(Math.max(576, startSize), 9000);
    const platform = os.platform();
    const isLinux = platform === "linux";
    const isMac = platform === "darwin";
    if (!isLinux && !isMac) {
        return {
            target: cleanTarget,
            success: false,
            error: `MTU Path Discovery via DF flag is not supported on this platform: ${platform}`
        };
    }
    // Quick check function for a specific payload size
    // Note: Payload size = MTU - 28 (IPv4) or 48 (IPv6)
    const isV6 = net.isIPv6(cleanTarget);
    const headerOverhead = isV6 ? 48 : 28;
    const probePayloadSize = async (payloadSize) => {
        const pingCmd = (isMac && isV6) ? "ping6" : "ping";
        const args = isLinux
            ? ["-M", "do", "-s", payloadSize.toString(), "-c", "1", "-W", "1", cleanTarget]
            : ["-D", "-s", payloadSize.toString(), "-c", "1", "-t", "1", cleanTarget];
        try {
            await execFilePromise(pingCmd, args, { timeout: 2000 });
            return true;
        }
        catch {
            return false;
        }
    };
    // Perform binary search to find maximum payload size
    let low = Math.max(0, 576 - headerOverhead);
    let high = size - headerOverhead; // Max payload size for starting size
    let maxWorkingPayload = 0;
    let reachedHighLimit = false;
    // First check if high limit works
    if (await probePayloadSize(high)) {
        maxWorkingPayload = high;
        reachedHighLimit = true;
    }
    else {
        // Binary search between low and high
        while (low <= high) {
            const mid = Math.floor((low + high) / 2);
            if (await probePayloadSize(mid)) {
                maxWorkingPayload = mid;
                low = mid + 1; // Try larger
            }
            else {
                high = mid - 1; // Try smaller
            }
        }
    }
    if (maxWorkingPayload === 0) {
        return {
            target: cleanTarget,
            success: false,
            error: "Unable to find working MTU. Path might block all ICMP or standard sweeps failed."
        };
    }
    const finalMtu = maxWorkingPayload + headerOverhead;
    return {
        target: cleanTarget,
        success: true,
        maximum_mtu: finalMtu,
        icmp_payload_size: maxWorkingPayload,
        reached_starting_limit: reachedHighLimit,
        platform_detected: platform
    };
}
/**
 * 4. trace_route
 */
export async function traceRoute(target) {
    const cleanTarget = validateTarget(target);
    // Check if we can use mtr (My Traceroute) in report mode, fallback to traceroute
    try {
        // Try mtr: 'mtr -r -c 3 -n <target>' (-r report mode, -c 3 cycles, -n numeric IPs)
        const { stdout } = await execFilePromise("mtr", ["-r", "-c", "3", "-n", cleanTarget], { timeout: 15000 });
        return {
            target: cleanTarget,
            tool_used: "mtr",
            output: stdout.trim()
        };
    }
    catch {
        // Fallback to traceroute
        try {
            // Linux/macOS traceroute: traceroute -n -w 2 -q 1 <target>
            const args = os.platform() === "win32"
                ? ["d", cleanTarget] // tracert
                : ["-n", "-w", "2", "-q", "1", cleanTarget];
            const cmd = os.platform() === "win32" ? "tracert" : "traceroute";
            const { stdout } = await execFilePromise(cmd, args, { timeout: 20000 });
            return {
                target: cleanTarget,
                tool_used: cmd,
                output: stdout.trim()
            };
        }
        catch (fallbackError) {
            return {
                target: cleanTarget,
                success: false,
                error: fallbackError.message || "Failed to execute mtr or traceroute"
            };
        }
    }
}
/**
 * 5. whois_domain_lookup
 */
export async function whoisDomainLookup(domain) {
    const cleanDomain = validateTarget(domain);
    try {
        const { stdout } = await execFilePromise("whois", [cleanDomain], { timeout: 15000 });
        return {
            domain: cleanDomain,
            success: true,
            raw_output: stdout.trim()
        };
    }
    catch (error) {
        return {
            domain: cleanDomain,
            success: false,
            error: error.message || "Failed to execute whois"
        };
    }
}
/**
 * 6. bgp_asn_lookup
 */
export async function bgpAsnLookup(ip) {
    const cleanIp = validateTarget(ip);
    if (net.isIP(cleanIp) === 0) {
        throw new Error("Target must be a valid IP address");
    }
    try {
        let reverseIp = "";
        let lookupZone = "";
        if (net.isIPv4(cleanIp)) {
            reverseIp = cleanIp.split(".").reverse().join(".");
            lookupZone = "origin.asn.cymru.com";
        }
        else {
            // IPv6 reverse mapping for Cymru
            const expanded = expandIPv6(cleanIp);
            reverseIp = expanded.split("").reverse().join(".");
            lookupZone = "origin6.asn.cymru.com";
        }
        const queryTarget = `${reverseIp}.${lookupZone}`;
        const resolver = new Resolver();
        const records = await resolver.resolveTxt(queryTarget);
        return {
            ip: cleanIp,
            success: true,
            cymru_records: records.map(r => r.join(""))
        };
    }
    catch (error) {
        return {
            ip: cleanIp,
            success: false,
            error: error.message || "Failed to lookup ASN via Cymru"
        };
    }
}
function expandIPv6(ip) {
    const segments = ip.split(":");
    if (segments.length === 8 && !ip.includes("::")) {
        return segments.map(s => s.padStart(4, "0")).join("");
    }
    const emptyIndex = segments.indexOf("");
    if (emptyIndex !== -1) {
        const missing = 8 - (segments.length - 1);
        const fillers = Array(missing).fill("0000");
        segments.splice(emptyIndex, 1, ...fillers);
    }
    return segments.map(s => s === "" ? "0000" : s.padStart(4, "0")).join("");
}
