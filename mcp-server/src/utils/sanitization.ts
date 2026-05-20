import { URL } from "url";
import net from "net";

/**
 * Validates that a target is a valid and safe hostname or IP address.
 * Safely supports IPv4, IPv6, and strict hostnames.
 */
export function validateTarget(target: string): string {
  if (!target || typeof target !== "string") {
    throw new Error("Target is required and must be a string");
  }

  const cleanTarget = target.trim();

  // Enforce reasonable length
  if (cleanTarget.length < 1 || cleanTarget.length > 253) {
    throw new Error("Target length must be between 1 and 253 characters");
  }

  // If it's a valid IP (IPv4 or IPv6), it is inherently safe from command injection.
  // We remove brackets just in case it's an IPv6 parsed from a URL hostname (e.g. "[::1]")
  const ipCheckString = cleanTarget.replace(/^\[/, "").replace(/\]$/, "");
  if (net.isIP(ipCheckString) !== 0) {
    return cleanTarget; // Safe IP
  }

  // Regex enforcing only alphanumeric, dots, and hyphens for hostnames
  const safeRegex = /^[a-zA-Z0-9.-]+$/;
  if (!safeRegex.test(cleanTarget)) {
    throw new Error("Target contains invalid characters. Only alphanumeric, '.' and '-' are allowed.");
  }

  // Additional sanitary checks for hostname structure
  if (cleanTarget.startsWith(".") || cleanTarget.endsWith(".")) {
    throw new Error("Target cannot start or end with '.'");
  }
  if (cleanTarget.startsWith("-") || cleanTarget.endsWith("-")) {
    throw new Error("Target cannot start or end with '-'");
  }
  if (cleanTarget.includes("..")) {
    throw new Error("Target cannot contain consecutive dots");
  }

  return cleanTarget;
}

/**
 * Validates a TCP/UDP port number.
 */
export function validatePort(port: number): number {
  if (port === undefined || port === null) {
    throw new Error("Port is required");
  }

  const portNum = Number(port);
  if (!Number.isInteger(portNum) || portNum < 1 || portNum > 65535) {
    throw new Error("Port must be an integer between 1 and 65535");
  }

  return portNum;
}

/**
 * Validates a URL and ensures its hostname is also safe from command injection.
 */
export function validateUrl(urlString: string, allowedProtocols = ["http:", "https:", "ws:", "wss:"]): URL {
  if (!urlString || typeof urlString !== "string") {
    throw new Error("URL is required and must be a string");
  }

  try {
    const parsedUrl = new URL(urlString.trim());

    if (!allowedProtocols.includes(parsedUrl.protocol)) {
      throw new Error(`Invalid protocol. Allowed: ${allowedProtocols.join(", ")}`);
    }

    // Verify the hostname part of the URL is also safe
    validateTarget(parsedUrl.hostname);

    return parsedUrl;
  } catch (error: any) {
    throw new Error(`Invalid URL: ${error.message}`);
  }
}
