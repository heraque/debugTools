import net from "net";
import dgram from "dgram";
import { validateTarget, validatePort } from "../utils/sanitization.js";

/**
 * 1. tcp_port_probe
 */
export async function tcpPortProbe(ip: string, port: number, timeoutMs = 2000): Promise<any> {
  const cleanIp = validateTarget(ip);
  const cleanPort = validatePort(port);
  const timeout = Math.min(Math.max(100, timeoutMs), 15000); // Clamp between 100ms and 15s

  return new Promise((resolve) => {
    const startTime = process.hrtime.bigint();
    const socket = new net.Socket();

    let resolved = false;

    const cleanupAndResolve = (status: "open" | "closed" | "filtered" | "timeout", errorDetails?: string) => {
      if (resolved) return;
      resolved = true;
      socket.destroy();
      const endTime = process.hrtime.bigint();
      const durationMs = Number(endTime - startTime) / 1e6;

      resolve({
        target_ip: cleanIp,
        port: cleanPort,
        status,
        duration_ms: parseFloat(durationMs.toFixed(2)),
        error: errorDetails
      });
    };

    socket.setTimeout(timeout);

    socket.connect(cleanPort, cleanIp, () => {
      cleanupAndResolve("open");
    });

    socket.on("error", (err: any) => {
      let status: "closed" | "filtered" = "closed";
      // Commonly, ETIMEDOUT or EHOSTUNREACH indicate firewall/filtered
      if (err.code === "ETIMEDOUT" || err.code === "EHOSTUNREACH" || err.code === "ENETUNREACH") {
        status = "filtered";
      }
      cleanupAndResolve(status, err.message || err.code);
    });

    socket.on("timeout", () => {
      cleanupAndResolve("timeout", "Connection timed out");
    });
  });
}

/**
 * 2. udp_port_probe
 * Probes a UDP port by sending a zero-byte payload.
 * If we receive ICMP Destination Unreachable / Port Unreachable (ECONNREFUSED in Node), it is closed.
 * If we receive no response after a timeout, it is either open or filtered (common for UDP).
 */
export async function udpPortProbe(ip: string, port: number, timeoutMs = 1500): Promise<any> {
  const cleanIp = validateTarget(ip);
  const cleanPort = validatePort(port);
  const timeout = Math.min(Math.max(500, timeoutMs), 5000);

  return new Promise((resolve) => {
    const socketType = net.isIPv6(cleanIp) ? "udp6" : "udp4";
    const socket = dgram.createSocket(socketType);
    let resolved = false;

    const cleanupAndResolve = (status: "open_or_filtered" | "closed", errorDetails?: string) => {
      if (resolved) return;
      resolved = true;
      socket.close();
      resolve({
        target_ip: cleanIp,
        port: cleanPort,
        status,
        error: errorDetails
      });
    };

    socket.on("error", (err: any) => {
      if (err.code === "ECONNREFUSED" || err.code === "ENETUNREACH" || err.code === "EHOSTUNREACH") {
        cleanupAndResolve("closed", `ICMP host/port unreachable received: ${err.code}`);
      } else {
        cleanupAndResolve("open_or_filtered", err.message || err.code);
      }
    });

    // Node.js dgram sockets, when connected, will pass ICMP Port Unreachable events as ECONNREFUSED
    socket.connect(cleanPort, cleanIp, () => {
      const message = Buffer.alloc(0); // Send empty payload
      socket.send(message, (err) => {
        if (err) {
          if (err.message.includes("ECONNREFUSED")) {
            cleanupAndResolve("closed", "ICMP port unreachable");
          } else {
            cleanupAndResolve("open_or_filtered", err.message);
          }
          return;
        }

        // Wait for ICMP response, if none arrives, assume open_or_filtered
        setTimeout(() => {
          cleanupAndResolve("open_or_filtered", "No ICMP unreachable response received (port may be open or filtered)");
        }, timeout);
      });
    });
  });
}
