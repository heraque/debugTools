import http from "http";
import https from "https";
import http2 from "http2";
import { execFile } from "child_process";
import { promisify } from "util";
import { WebSocket } from "ws";
import * as grpc from "@grpc/grpc-js";
import * as protoLoader from "@grpc/proto-loader";
import { fileURLToPath } from "url";
import path from "path";
import { validateUrl, validateTarget, validatePort } from "../utils/sanitization.js";
const execFilePromise = promisify(execFile);
const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);
const PROTO_PATH = path.resolve(__dirname, "../utils/health.proto");
/**
 * 1. http_detailed_probe
 */
export async function httpDetailedProbe(urlString, method = "GET", protocolVersion = "http1", headers = {}, userAgent) {
    const cleanUrl = validateUrl(urlString);
    const cleanMethod = method.toUpperCase();
    const allowedProtocols = ["http1", "http2", "http3"];
    if (!allowedProtocols.includes(protocolVersion)) {
        throw new Error(`Unsupported protocol version: ${protocolVersion}. Supported: ${allowedProtocols.join(", ")}`);
    }
    const customHeaders = {
        "User-Agent": userAgent || "MCP-SRE-Agent-Hermes-Protocol-Probe/1.0",
        ...headers
    };
    // If HTTP/3 is selected, we invoke curl via execFile
    if (protocolVersion === "http3") {
        return runHttp3ProbeWithCurl(cleanUrl.toString(), cleanMethod, customHeaders);
    }
    // If HTTP/2 is selected, we use Node's native http2 module
    if (protocolVersion === "http2") {
        return runHttp2Probe(cleanUrl, cleanMethod, customHeaders);
    }
    // Fallback to HTTP/1.1
    return runHttp11Probe(cleanUrl, cleanMethod, customHeaders);
}
// HTTP/1.1 Precision Probe
function runHttp11Probe(url, method, headers) {
    return new Promise((resolve) => {
        const isHttps = url.protocol === "https:";
        const lib = isHttps ? https : http;
        const timings = {
            dns_lookup_ms: -1,
            tcp_handshake_ms: -1,
            tls_handshake_ms: -1,
            ttfb_ms: -1,
            total_ms: -1
        };
        const startTime = process.hrtime.bigint();
        let dnsTime = startTime;
        let tcpTime = startTime;
        let tlsTime = startTime;
        let ttfbTime = startTime;
        const options = {
            method,
            headers,
            rejectUnauthorized: false,
            timeout: 10000
        };
        const req = lib.request(url, options, (res) => {
            res.once("data", () => {
                ttfbTime = process.hrtime.bigint();
                timings.ttfb_ms = Number(ttfbTime - (isHttps ? tlsTime : tcpTime)) / 1e6;
            });
            res.on("data", () => { }); // Drain stream
            res.on("end", () => {
                const endTime = process.hrtime.bigint();
                timings.total_ms = Number(endTime - startTime) / 1e6;
                resolve({
                    url: url.toString(),
                    protocol: "HTTP/1.1",
                    status_code: res.statusCode,
                    status_message: res.statusMessage,
                    timings_ms: {
                        dns_lookup: parseFloat(timings.dns_lookup_ms.toFixed(2)),
                        tcp_handshake: parseFloat(timings.tcp_handshake_ms.toFixed(2)),
                        tls_handshake: isHttps ? parseFloat(timings.tls_handshake_ms.toFixed(2)) : null,
                        ttfb: parseFloat(timings.ttfb_ms.toFixed(2)),
                        total: parseFloat(timings.total_ms.toFixed(2))
                    },
                    headers: res.headers
                });
            });
        });
        req.on("socket", (socket) => {
            socket.on("lookup", () => {
                dnsTime = process.hrtime.bigint();
                timings.dns_lookup_ms = Number(dnsTime - startTime) / 1e6;
            });
            socket.on("connect", () => {
                tcpTime = process.hrtime.bigint();
                timings.tcp_handshake_ms = Number(tcpTime - (timings.dns_lookup_ms > 0 ? dnsTime : startTime)) / 1e6;
            });
            if (isHttps) {
                socket.on("secureConnect", () => {
                    tlsTime = process.hrtime.bigint();
                    timings.tls_handshake_ms = Number(tlsTime - tcpTime) / 1e6;
                });
            }
        });
        req.on("error", (err) => {
            resolve({
                url: url.toString(),
                success: false,
                error: err.message
            });
        });
        req.on("timeout", () => {
            req.destroy();
            resolve({
                url: url.toString(),
                success: false,
                error: "HTTP/1.1 request timed out after 10 seconds"
            });
        });
        req.end();
    });
}
// HTTP/2 Precision Probe
function runHttp2Probe(url, method, headers) {
    return new Promise((resolve) => {
        const isHttps = url.protocol === "https:";
        if (!isHttps) {
            resolve({
                url: url.toString(),
                success: false,
                error: "HTTP/2 is only supported over HTTPS"
            });
            return;
        }
        const timings = {
            dns_lookup_ms: -1,
            tcp_handshake_ms: -1,
            tls_handshake_ms: -1,
            ttfb_ms: -1,
            total_ms: -1
        };
        const startTime = process.hrtime.bigint();
        let dnsTime = startTime;
        let tcpTime = startTime;
        let tlsTime = startTime;
        let ttfbTime = startTime;
        const client = http2.connect(url.origin, {
            rejectUnauthorized: false
        });
        client.on("socketError", (err) => {
            client.destroy();
            resolve({
                url: url.toString(),
                success: false,
                error: err.message
            });
        });
        client.on("error", (err) => {
            client.destroy();
            resolve({
                url: url.toString(),
                success: false,
                error: err.message
            });
        });
        // Capture standard socket connection lifecycle
        // Since http2.connect handles sockets under the hood, we can hook the socket event
        client.once("connect", () => {
            // Connect fires when the HTTP/2 session is ready
            tlsTime = process.hrtime.bigint();
            timings.tls_handshake_ms = Number(tlsTime - startTime) / 1e6; // combined DNS + TCP + TLS in HTTP/2 helper
        });
        const req = client.request({
            ":method": method,
            ":path": url.pathname + url.search,
            ...headers
        });
        let statusCode = 200;
        let responseHeaders = {};
        req.on("response", (headers) => {
            const statusHeader = headers[":status"];
            statusCode = statusHeader ? parseInt(Array.isArray(statusHeader) ? statusHeader[0] : String(statusHeader), 10) : 200;
            responseHeaders = headers;
            ttfbTime = process.hrtime.bigint();
            timings.ttfb_ms = Number(ttfbTime - tlsTime) / 1e6;
        });
        req.on("data", () => { }); // Drain response
        req.on("end", () => {
            const endTime = process.hrtime.bigint();
            timings.total_ms = Number(endTime - startTime) / 1e6;
            client.close();
            resolve({
                url: url.toString(),
                protocol: "HTTP/2",
                status_code: statusCode,
                timings_ms: {
                    session_connect: parseFloat(timings.tls_handshake_ms.toFixed(2)), // Combined session ready time
                    ttfb: parseFloat(timings.ttfb_ms.toFixed(2)),
                    total: parseFloat(timings.total_ms.toFixed(2))
                },
                headers: responseHeaders
            });
        });
        req.on("error", (err) => {
            client.destroy();
            resolve({
                url: url.toString(),
                success: false,
                error: err.message
            });
        });
        req.end();
    });
}
// HTTP/3 Probe utilizing system curl
async function runHttp3ProbeWithCurl(url, method, headers) {
    // Format headers for curl: -H "Name: Value"
    const curlArgs = ["-o", "/dev/null", "-s", "-w", "%{time_namelookup}:%{time_connect}:%{time_appconnect}:%{time_starttransfer}:%{time_total}:%{http_code}", "--http3", "-X", method];
    for (const [key, value] of Object.entries(headers)) {
        curlArgs.push("-H", `${key}: ${value}`);
    }
    curlArgs.push(url);
    try {
        const { stdout } = await execFilePromise("curl", curlArgs, { timeout: 10000 });
        const parts = stdout.trim().split(":");
        if (parts.length < 6) {
            throw new Error(`Invalid curl response format: ${stdout}`);
        }
        const dns = parseFloat(parts[0]) * 1000;
        const connect = parseFloat(parts[1]) * 1000;
        const tls = parseFloat(parts[2]) * 1000;
        const ttfb = parseFloat(parts[3]) * 1000;
        const total = parseFloat(parts[4]) * 1000;
        const code = parseInt(parts[5], 10);
        return {
            url,
            protocol: "HTTP/3",
            status_code: code,
            timings_ms: {
                dns_lookup: parseFloat(dns.toFixed(2)),
                tcp_handshake: parseFloat(connect.toFixed(2)),
                tls_handshake: parseFloat(tls.toFixed(2)),
                ttfb: parseFloat(ttfb.toFixed(2)),
                total: parseFloat(total.toFixed(2))
            }
        };
    }
    catch (error) {
        return {
            url,
            success: false,
            error: `HTTP/3 Probe failed. Note: Ensure system 'curl' supports '--http3'. Error: ${error.message}`
        };
    }
}
/**
 * 2. websocket_handshake_test
 */
export async function websocketHandshakeTest(urlString, headers = {}) {
    const cleanUrl = validateUrl(urlString, ["ws:", "wss:"]);
    return new Promise((resolve) => {
        const startTime = process.hrtime.bigint();
        const ws = new WebSocket(cleanUrl.toString(), {
            headers,
            rejectUnauthorized: false,
            handshakeTimeout: 5000
        });
        ws.on("open", () => {
            const handshakeTime = process.hrtime.bigint();
            const handshakeDurationMs = Number(handshakeTime - startTime) / 1e6;
            let pingTimeout;
            // Send a test ping frame to ensure two-way communication
            ws.ping();
            pingTimeout = setTimeout(() => {
                ws.terminate();
                resolve({
                    url: cleanUrl.toString(),
                    success: false,
                    handshake_duration_ms: parseFloat(handshakeDurationMs.toFixed(2)),
                    error: "WebSocket pong response timeout (Ping dropped or blocked)"
                });
            }, 3000);
            ws.on("pong", () => {
                clearTimeout(pingTimeout);
                const pingTime = process.hrtime.bigint();
                const rttMs = Number(pingTime - handshakeTime) / 1e6;
                ws.close();
                resolve({
                    url: cleanUrl.toString(),
                    success: true,
                    handshake_duration_ms: parseFloat(handshakeDurationMs.toFixed(2)),
                    ping_rtt_ms: parseFloat(rttMs.toFixed(2))
                });
            });
        });
        ws.on("error", (err) => {
            resolve({
                url: cleanUrl.toString(),
                success: false,
                error: err.message
            });
        });
    });
}
/**
 * 3. grpc_health_check
 */
export async function grpcHealthCheck(target, serviceName = "") {
    // Validate target host:port
    const parts = target.split(":");
    if (parts.length !== 2) {
        throw new Error("Target must be in host:port format");
    }
    validateTarget(parts[0]);
    validatePort(parseInt(parts[1], 10));
    return new Promise((resolve) => {
        try {
            const packageDefinition = protoLoader.loadSync(PROTO_PATH, {
                keepCase: true,
                longs: String,
                enums: String,
                defaults: true,
                oneofs: true
            });
            const grpcObject = grpc.loadPackageDefinition(packageDefinition);
            const HealthClient = grpcObject.grpc.health.v1.Health;
            // Create insecure channel client
            const client = new HealthClient(target, grpc.credentials.createInsecure());
            const startTime = process.hrtime.bigint();
            client.Check({ service: serviceName }, { deadline: Date.now() + 4000 }, (err, response) => {
                const endTime = process.hrtime.bigint();
                const durationMs = Number(endTime - startTime) / 1e6;
                client.close();
                if (err) {
                    resolve({
                        target,
                        service: serviceName,
                        success: false,
                        duration_ms: parseFloat(durationMs.toFixed(2)),
                        error: err.message,
                        code: err.code
                    });
                }
                else {
                    resolve({
                        target,
                        service: serviceName,
                        success: true,
                        status: response.status,
                        duration_ms: parseFloat(durationMs.toFixed(2))
                    });
                }
            });
        }
        catch (err) {
            resolve({
                target,
                service: serviceName,
                success: false,
                error: `Failed to initiate gRPC client: ${err.message}`
            });
        }
    });
}
/**
 * 4. http_rate_limit_stress
 */
export async function httpRateLimitStress(urlString, requestsCount = 30, concurrency = 5) {
    const cleanUrl = validateUrl(urlString);
    const count = Math.min(Math.max(1, requestsCount), 100);
    const concurrent = Math.min(Math.max(1, concurrency), 20);
    const startTime = process.hrtime.bigint();
    const statusCodes = {};
    const latencies = [];
    let failures = 0;
    const queue = Array.from({ length: count }, (_, i) => i);
    const sendRequest = () => {
        return new Promise((resolve) => {
            const reqStart = process.hrtime.bigint();
            const isHttps = cleanUrl.protocol === "https:";
            const lib = isHttps ? https : http;
            const req = lib.request(cleanUrl, { method: "GET", rejectUnauthorized: false, timeout: 5000 }, (res) => {
                const reqEnd = process.hrtime.bigint();
                const latency = Number(reqEnd - reqStart) / 1e6;
                latencies.push(latency);
                const code = res.statusCode || 0;
                statusCodes[code] = (statusCodes[code] || 0) + 1;
                res.on("data", () => { }); // drain
                res.on("end", () => resolve());
            });
            req.on("error", () => {
                failures++;
                resolve();
            });
            req.on("timeout", () => {
                req.destroy();
                failures++;
                resolve();
            });
            req.end();
        });
    };
    // Process queue with concurrency limit
    const workers = Array.from({ length: concurrent }, async () => {
        while (queue.length > 0) {
            queue.shift();
            await sendRequest();
        }
    });
    await Promise.all(workers);
    const endTime = process.hrtime.bigint();
    const totalDurationMs = Number(endTime - startTime) / 1e6;
    // Calculate percentiles
    latencies.sort((a, b) => a - b);
    const p50 = latencies[Math.floor(latencies.length * 0.5)] || 0;
    const p90 = latencies[Math.floor(latencies.length * 0.9)] || 0;
    const p99 = latencies[Math.floor(latencies.length * 0.99)] || 0;
    return {
        url: cleanUrl.toString(),
        total_requests_sent: count,
        concurrency_level: concurrent,
        total_duration_ms: parseFloat(totalDurationMs.toFixed(2)),
        failures_count: failures,
        status_codes_distribution: statusCodes,
        latencies_percentiles_ms: {
            p50: parseFloat(p50.toFixed(2)),
            p90: parseFloat(p90.toFixed(2)),
            p99: parseFloat(p99.toFixed(2))
        },
        rate_limited_429s_detected: (statusCodes[429] || 0) > 0,
        rate_limited_429s_count: statusCodes[429] || 0
    };
}
