import tls from "tls";
import https from "https";
import { validateTarget, validatePort } from "../utils/sanitization.js";
/**
 * Helper to test connection with specific TLS options
 */
function testTlsVersion(hostname, port, version) {
    return new Promise((resolve) => {
        let socket;
        try {
            socket = tls.connect({
                host: hostname,
                port: port,
                servername: hostname,
                minVersion: version,
                maxVersion: version,
                rejectUnauthorized: false // We check support, not validity
            }, () => {
                const cipher = socket.getCipher();
                socket.end();
                resolve({ supported: true, cipher: `${cipher.name} (${cipher.version})` });
            });
        }
        catch (err) {
            resolve({ supported: false, error: err.message });
            return;
        }
        socket.setTimeout(2500);
        socket.on("error", (err) => {
            resolve({ supported: false, error: err.message });
            socket.destroy();
        });
        socket.on("timeout", () => {
            resolve({ supported: false, error: "Connection timeout" });
            socket.destroy();
        });
    });
}
/**
 * 1. tls_cipher_audit
 */
export async function tlsCipherAudit(hostname, port = 443) {
    const cleanHost = validateTarget(hostname);
    const cleanPort = validatePort(port);
    const versions = {
        "TLSv1": "TLS 1.0",
        "TLSv1.1": "TLS 1.1",
        "TLSv1.2": "TLS 1.2",
        "TLSv1.3": "TLS 1.3"
    };
    const results = {};
    // Note: SSLv3 is completely deprecated and removed in modern Node.js runtimes. We explicitly report it.
    results["SSLv3"] = { supported: false, error: "SSLv3 is deprecated and not supported by the Node.js runtime" };
    await Promise.all(Object.entries(versions).map(async ([verKey, verName]) => {
        results[verName] = await testTlsVersion(cleanHost, cleanPort, verKey);
    }));
    return {
        hostname: cleanHost,
        port: cleanPort,
        audit_results: results
    };
}
/**
 * 2. ssl_certificate_check
 */
export async function sslCertificateCheck(hostname, port = 443) {
    const cleanHost = validateTarget(hostname);
    const cleanPort = validatePort(port);
    return new Promise((resolve) => {
        let socket;
        try {
            socket = tls.connect({
                host: cleanHost,
                port: cleanPort,
                servername: cleanHost,
                rejectUnauthorized: false
            }, () => {
                const cert = socket.getPeerCertificate(true); // Fetch complete chain
                const isAuthorized = socket.authorized;
                const authError = socket.authorizationError;
                socket.end();
                if (!cert || Object.keys(cert).length === 0) {
                    resolve({
                        hostname: cleanHost,
                        port: cleanPort,
                        success: false,
                        error: "No certificate returned by the server"
                    });
                    return;
                }
                // Parse expiration
                const validFrom = cert.valid_from;
                const validTo = cert.valid_to;
                const daysRemaining = Math.max(0, Math.round((new Date(validTo).getTime() - Date.now()) / (1000 * 60 * 60 * 24)));
                resolve({
                    hostname: cleanHost,
                    port: cleanPort,
                    authorized: isAuthorized,
                    authorization_error: authError || null,
                    subject: cert.subject,
                    issuer: cert.issuer,
                    valid_from: validFrom,
                    valid_to: validTo,
                    days_remaining: daysRemaining,
                    fingerprint: cert.fingerprint,
                    fingerprint256: cert.fingerprint256,
                    serial_number: cert.serialNumber,
                    sans: cert.subjectaltname ? cert.subjectaltname.split(", ").map(s => s.replace("DNS:", "")) : [],
                    certificate_chain_length: getChainLength(cert)
                });
            });
        }
        catch (err) {
            resolve({
                hostname: cleanHost,
                port: cleanPort,
                success: false,
                error: err.message
            });
            return;
        }
        socket.setTimeout(5000);
        socket.on("error", (err) => {
            resolve({
                hostname: cleanHost,
                port: cleanPort,
                success: false,
                error: err.message
            });
            socket.destroy();
        });
        socket.on("timeout", () => {
            resolve({
                hostname: cleanHost,
                port: cleanPort,
                success: false,
                error: "Connection timeout while fetching SSL certificate"
            });
            socket.destroy();
        });
    });
}
function getChainLength(cert) {
    let depth = 1;
    let current = cert;
    while (current.issuerCertificate && current.issuerCertificate !== current) {
        depth++;
        current = current.issuerCertificate;
    }
    return depth;
}
/**
 * 3. cdn_bypass_probe
 */
export async function cdnBypassProbe(originIp, domain, port = 443) {
    const cleanIp = validateTarget(originIp);
    const cleanDomain = validateTarget(domain);
    const cleanPort = validatePort(port);
    return new Promise((resolve) => {
        const startTime = process.hrtime.bigint();
        const options = {
            hostname: cleanIp,
            port: cleanPort,
            path: "/",
            method: "GET",
            servername: cleanDomain, // Sets the correct SNI TLS header
            headers: {
                "Host": cleanDomain, // Sets the correct HTTP Host header
                "User-Agent": "MCP-SRE-Agent-Hermes-Bypass-Probe/1.0"
            },
            rejectUnauthorized: false, // Bypass certificate validation checks
            timeout: 4000
        };
        const req = https.request(options, (res) => {
            const endTime = process.hrtime.bigint();
            const durationMs = Number(endTime - startTime) / 1e6;
            const responseHeaders = {};
            for (const [key, value] of Object.entries(res.headers)) {
                if (value) {
                    responseHeaders[key] = Array.isArray(value) ? value.join(", ") : value;
                }
            }
            resolve({
                origin_ip: cleanIp,
                domain: cleanDomain,
                port: cleanPort,
                status_code: res.statusCode,
                status_message: res.statusMessage,
                duration_ms: parseFloat(durationMs.toFixed(2)),
                headers: responseHeaders
            });
        });
        req.on("error", (err) => {
            const endTime = process.hrtime.bigint();
            const durationMs = Number(endTime - startTime) / 1e6;
            resolve({
                origin_ip: cleanIp,
                domain: cleanDomain,
                port: cleanPort,
                success: false,
                duration_ms: parseFloat(durationMs.toFixed(2)),
                error: err.message
            });
        });
        req.on("timeout", () => {
            req.destroy();
            resolve({
                origin_ip: cleanIp,
                domain: cleanDomain,
                port: cleanPort,
                success: false,
                error: "Connection timeout while probing origin IP"
            });
        });
        req.end();
    });
}
