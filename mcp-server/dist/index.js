import express from "express";
import { Server } from "@modelcontextprotocol/sdk/server/index.js";
import { SSEServerTransport } from "@modelcontextprotocol/sdk/server/sse.js";
import { CallToolRequestSchema, ListToolsRequestSchema } from "@modelcontextprotocol/sdk/types.js";
// Import all tools
import { dnsPropagationCheck, icmpPing, mtuPathDiscovery, traceRoute, whoisDomainLookup, bgpAsnLookup } from "./tools/dns.js";
import { tcpPortProbe, udpPortProbe } from "./tools/ports.js";
import { tlsCipherAudit, sslCertificateCheck, cdnBypassProbe } from "./tools/security.js";
import { httpDetailedProbe, websocketHandshakeTest, grpcHealthCheck, httpRateLimitStress } from "./tools/protocols.js";
const PORT = process.env.PORT || 3000;
// Initialize Express
const app = express();
// Initialize the MCP Server
const server = new Server({
    name: "debugtools-mcp-diagnostics",
    version: "1.0.0"
}, {
    capabilities: {
        tools: {}
    }
});
// Map to track active SSE sessions
const transports = {};
// Bearer Token Authentication Middleware
app.use((req, res, next) => {
    const expectedKey = process.env.MCP_API_KEY;
    if (!expectedKey) {
        console.error("CRITICAL: MCP_API_KEY environment variable is not defined!");
        res.status(500).json({ error: "Internal Server Error: Server authentication is misconfigured." });
        return;
    }
    if (req.method === "OPTIONS") {
        next();
        return;
    }
    const authHeader = req.headers.authorization;
    if (!authHeader || !authHeader.startsWith("Bearer ")) {
        res.status(401).json({ error: "Unauthorized: Missing or invalid Authorization header structure." });
        return;
    }
    const token = authHeader.substring(7).trim();
    if (token !== expectedKey) {
        res.status(401).json({ error: "Unauthorized: Invalid API Key." });
        return;
    }
    next();
});
// Setup tool listings
server.setRequestHandler(ListToolsRequestSchema, async () => {
    return {
        tools: [
            // L3: DNS & Roteamento
            {
                name: "whois_domain_lookup",
                description: "Consulta informações de registro Whois de um domínio (nameservers, expiração, contato).",
                inputSchema: {
                    type: "object",
                    properties: {
                        domain: { type: "string", description: "Nome de domínio (ex: google.com)" }
                    },
                    required: ["domain"]
                }
            },
            {
                name: "bgp_asn_lookup",
                description: "Busca o ASN (Autonomous System Number) e informações de roteamento BGP de um endereço IP via Cymru.",
                inputSchema: {
                    type: "object",
                    properties: {
                        ip: { type: "string", description: "Endereço IP público (IPv4 ou IPv6)" }
                    },
                    required: ["ip"]
                }
            },
            {
                name: "dns_propagation_check",
                description: "Consulta o domínio informado contra múltiplos resolvers DNS (Google, Cloudflare, Quad9, e o resolver local da VPS) para mapear discrepâncias de resolução IP.",
                inputSchema: {
                    type: "object",
                    properties: {
                        hostname: { type: "string", description: "Nome de domínio para resolver (ex: google.com)" },
                        record_type: { type: "string", description: "Tipo de registro DNS (A, AAAA, CNAME, MX, TXT, NS). Padrão: A", default: "A" }
                    },
                    required: ["hostname"]
                }
            },
            {
                name: "icmp_ping",
                description: "Envia pacotes ICMP e retorna latência e perda de pacotes.",
                inputSchema: {
                    type: "object",
                    properties: {
                        target: { type: "string", description: "IP ou Hostname de destino" },
                        count: { type: "number", description: "Número de pings a enviar. Padrão: 4. Máximo: 20", default: 4 }
                    },
                    required: ["target"]
                }
            },
            {
                name: "mtu_path_discovery",
                description: "Descobre o MTU máximo do caminho sem fragmentação enviando pings ICMP com a flag DF (Don't Fragment) ativa.",
                inputSchema: {
                    type: "object",
                    properties: {
                        target: { type: "string", description: "IP ou Hostname de destino" },
                        start_size: { type: "number", description: "Tamanho de MTU inicial a testar. Padrão: 1500", default: 1500 }
                    },
                    required: ["target"]
                }
            },
            {
                name: "trace_route",
                description: "Executa um traceroute ou mtr detalhado para listar os saltos de rede entre a VPS e o destino.",
                inputSchema: {
                    type: "object",
                    properties: {
                        target: { type: "string", description: "IP ou Hostname de destino" }
                    },
                    required: ["target"]
                }
            },
            // L4: Port Connectivity
            {
                name: "tcp_port_probe",
                description: "Tenta estabelecer um handshake TCP básico em uma porta específica para validar se ela está aberta, fechada ou filtrada por Firewall de borda.",
                inputSchema: {
                    type: "object",
                    properties: {
                        ip: { type: "string", description: "IP ou Hostname de destino" },
                        port: { type: "number", description: "Porta TCP a sondar (1 - 65535)" },
                        timeout_ms: { type: "number", description: "Tempo limite da conexão em milissegundos. Padrão: 2000", default: 2000 }
                    },
                    required: ["ip", "port"]
                }
            },
            {
                name: "udp_port_probe",
                description: "Tenta sondar portas UDP enviando payloads vazios e escutando por respostas ICMP de erro.",
                inputSchema: {
                    type: "object",
                    properties: {
                        ip: { type: "string", description: "IP ou Hostname de destino" },
                        port: { type: "number", description: "Porta UDP a sondar (1 - 65535)" }
                    },
                    required: ["ip", "port"]
                }
            },
            // L5/L6: Criptografia & Segurança
            {
                name: "tls_cipher_audit",
                description: "Valida as versões TLS aceitas pelo servidor (SSLv3, TLS 1.0, 1.1, 1.2, 1.3) e audita as Cipher Suites suportadas para expor ciphers fracos ou incompatibilidades.",
                inputSchema: {
                    type: "object",
                    properties: {
                        hostname: { type: "string", description: "Nome de domínio a testar" },
                        port: { type: "number", description: "Porta TLS. Padrão: 443", default: 443 }
                    },
                    required: ["hostname"]
                }
            },
            {
                name: "ssl_certificate_check",
                description: "Retorna a validade temporal, emissor e cadeia completa de certificação SSL de um domínio.",
                inputSchema: {
                    type: "object",
                    properties: {
                        hostname: { type: "string", description: "Nome de domínio" }
                    },
                    required: ["hostname"]
                }
            },
            {
                name: "cdn_bypass_probe",
                description: "Tenta contornar a CDN fazendo uma requisição HTTPS direta para o IP público do LoadBalancer de origem, mas injetando o header Host correto.",
                inputSchema: {
                    type: "object",
                    properties: {
                        origin_ip: { type: "string", description: "IP público real da origem ou load balancer" },
                        domain: { type: "string", description: "Nome de domínio/Host original" },
                        port: { type: "number", description: "Porta. Padrão: 443", default: 443 }
                    },
                    required: ["origin_ip", "domain"]
                }
            },
            // L7: Protocolos de Aplicação
            {
                name: "http_detailed_probe",
                description: "Efetua uma requisição HTTP customizada de alta fidelidade com coleta detalhada de tempos de resposta (DNS, TCP Handshake, TLS Handshake, TTFB). Suporta especificação de protocolo HTTP/1.1, HTTP/2 ou HTTP/3.",
                inputSchema: {
                    type: "object",
                    properties: {
                        url: { type: "string", description: "URL completa (http:// ou https://)" },
                        method: { type: "string", description: "Método HTTP (GET, POST, HEAD, etc.). Padrão: GET", default: "GET" },
                        protocol_version: { type: "string", description: "Versão do protocolo: http1, http2, http3. Padrão: http1", default: "http1" },
                        headers: { type: "object", description: "Headers HTTP customizados (opcional)" },
                        user_agent: { type: "string", description: "User Agent customizado (opcional)" }
                    },
                    required: ["url"]
                }
            },
            {
                name: "websocket_handshake_test",
                description: "Tenta estabelecer uma conexão ws/wss de longa duração na borda, realiza o handshake de upgrade e envia/recebe um frame de teste.",
                inputSchema: {
                    type: "object",
                    properties: {
                        url: { type: "string", description: "URL WebSocket (ws:// ou wss://)" },
                        headers: { type: "object", description: "Headers HTTP customizados (opcional)" }
                    },
                    required: ["url"]
                }
            },
            {
                name: "grpc_health_check",
                description: "Testa a saúde de um serviço gRPC exposto externamente enviando uma chamada de Health Check padrão (grpc.health.v1.Health).",
                inputSchema: {
                    type: "object",
                    properties: {
                        target: { type: "string", description: "Alvo no formato host:port" },
                        service_name: { type: "string", description: "Nome do serviço específico (opcional)", default: "" }
                    },
                    required: ["target"]
                }
            },
            {
                name: "http_rate_limit_stress",
                description: "Envia uma rajada curta e rápida de requisições HTTP para testar se as barreiras de Rate Limit da borda (WAF ou Ingress) estão ativas e gerando respostas HTTP 429.",
                inputSchema: {
                    type: "object",
                    properties: {
                        url: { type: "string", description: "URL HTTP completa" },
                        requests_count: { type: "number", description: "Total de requisições. Padrão: 30. Máximo: 100", default: 30 },
                        concurrency: { type: "number", description: "Número de requisições paralelas simultâneas. Padrão: 5. Máximo: 20", default: 5 }
                    },
                    required: ["url"]
                }
            }
        ]
    };
});
// Setup tool execution handler
server.setRequestHandler(CallToolRequestSchema, async (request) => {
    const { name, arguments: args } = request.params;
    try {
        switch (name) {
            // L3: DNS
            case "whois_domain_lookup": {
                const { domain } = args;
                const result = await whoisDomainLookup(domain);
                return { content: [{ type: "text", text: JSON.stringify(result, null, 2) }] };
            }
            case "bgp_asn_lookup": {
                const { ip } = args;
                const result = await bgpAsnLookup(ip);
                return { content: [{ type: "text", text: JSON.stringify(result, null, 2) }] };
            }
            case "dns_propagation_check": {
                const { hostname, record_type } = args;
                const result = await dnsPropagationCheck(hostname, record_type);
                return { content: [{ type: "text", text: JSON.stringify(result, null, 2) }] };
            }
            case "icmp_ping": {
                const { target, count } = args;
                const result = await icmpPing(target, count);
                return { content: [{ type: "text", text: JSON.stringify(result, null, 2) }] };
            }
            case "mtu_path_discovery": {
                const { target, start_size } = args;
                const result = await mtuPathDiscovery(target, start_size);
                return { content: [{ type: "text", text: JSON.stringify(result, null, 2) }] };
            }
            case "trace_route": {
                const { target } = args;
                const result = await traceRoute(target);
                return { content: [{ type: "text", text: JSON.stringify(result, null, 2) }] };
            }
            // L4: Ports
            case "tcp_port_probe": {
                const { ip, port, timeout_ms } = args;
                const result = await tcpPortProbe(ip, port, timeout_ms);
                return { content: [{ type: "text", text: JSON.stringify(result, null, 2) }] };
            }
            case "udp_port_probe": {
                const { ip, port } = args;
                const result = await udpPortProbe(ip, port);
                return { content: [{ type: "text", text: JSON.stringify(result, null, 2) }] };
            }
            // L5/L6: Security
            case "tls_cipher_audit": {
                const { hostname, port } = args;
                const result = await tlsCipherAudit(hostname, port);
                return { content: [{ type: "text", text: JSON.stringify(result, null, 2) }] };
            }
            case "ssl_certificate_check": {
                const { hostname } = args;
                const result = await sslCertificateCheck(hostname);
                return { content: [{ type: "text", text: JSON.stringify(result, null, 2) }] };
            }
            case "cdn_bypass_probe": {
                const { origin_ip, domain, port } = args;
                const result = await cdnBypassProbe(origin_ip, domain, port);
                return { content: [{ type: "text", text: JSON.stringify(result, null, 2) }] };
            }
            // L7: Protocols
            case "http_detailed_probe": {
                const { url, method, protocol_version, headers, user_agent } = args;
                const result = await httpDetailedProbe(url, method, protocol_version, headers, user_agent);
                return { content: [{ type: "text", text: JSON.stringify(result, null, 2) }] };
            }
            case "websocket_handshake_test": {
                const { url, headers } = args;
                const result = await websocketHandshakeTest(url, headers);
                return { content: [{ type: "text", text: JSON.stringify(result, null, 2) }] };
            }
            case "grpc_health_check": {
                const { target, service_name } = args;
                const result = await grpcHealthCheck(target, service_name);
                return { content: [{ type: "text", text: JSON.stringify(result, null, 2) }] };
            }
            case "http_rate_limit_stress": {
                const { url, requests_count, concurrency } = args;
                const result = await httpRateLimitStress(url, requests_count, concurrency);
                return { content: [{ type: "text", text: JSON.stringify(result, null, 2) }] };
            }
            default:
                throw new Error(`Tool not found: ${name}`);
        }
    }
    catch (error) {
        return {
            content: [{ type: "text", text: JSON.stringify({ success: false, error: error.message || String(error) }, null, 2) }],
            isError: true
        };
    }
});
// GET /sse endpoint: initiates the SSE connection
app.get("/sse", async (req, res) => {
    console.log("Establishing remote Hermes SSE session...");
    // Instantiate SSE transport for this client connection
    const transport = new SSEServerTransport("/messages", res);
    const sessionId = transport.sessionId;
    // Track session
    transports[sessionId] = transport;
    // Connect server to transport
    await server.connect(transport);
    console.log(`Hermes SSE session established successfully. SessionId: ${sessionId}`);
    // Cleanup session on socket disconnect
    res.on("close", () => {
        console.log(`Cleaning up Hermes SSE session: ${sessionId}`);
        delete transports[sessionId];
        transport.close();
    });
});
// POST /messages endpoint: receives RPC commands for active SSE sessions
app.post("/messages", express.json(), async (req, res) => {
    const sessionId = req.query.sessionId;
    if (!sessionId) {
        res.status(400).json({ error: "Missing sessionId query parameter" });
        return;
    }
    const transport = transports[sessionId];
    if (!transport) {
        res.status(404).json({ error: "Active session not found. Please establish a fresh SSE link at /sse." });
        return;
    }
    // Delegate processing to the official transport handler
    await transport.handlePostMessage(req, res);
});
// Start Express server
app.listen(PORT, () => {
    console.log(`=============================================================`);
    console.log(`🚀 MCP Diagnostics Server listening on port ${PORT}`);
    console.log(`🔌 Establish Hermes SSE transport link at: GET http://localhost:${PORT}/sse`);
    console.log(`📥 Post RPC commands to: POST http://localhost:${PORT}/messages?sessionId=<session_id>`);
    console.log(`=============================================================`);
});
