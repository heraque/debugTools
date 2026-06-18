# Servidor MCP de Diagnósticos de Rede Externos ("de fora para dentro")

Este é um servidor **Model Context Protocol (MCP)** altamente especializado em diagnósticos de rede externos. Ele roda exposto à internet (ex: VPS Oracle Cloud) e permite que agentes SRE internos (como o **Hermes**, rodando em clusters Kubernetes privados) executem testes de rede sob a perspectiva de um usuário externo, eliminando pontos cegos causados por CDNs, Firewalls de borda, WAFs e resoluções DNS públicas.

---

## 🛠️ Canivete Suíço de Ferramentas (Tools)

O servidor expõe as seguintes ferramentas para o MCP:

### 🌐 Categoria: DNS & Roteamento (L3)
*   `dns_propagation_check`: Consulta o domínio informado contra múltiplos resolvers DNS (Google `8.8.8.8`, Cloudflare `1.1.1.1`, Quad9 `9.9.9.9` e o resolver local da VPS) para mapear discrepâncias de resolução IP.
    *   *Argumentos:* `hostname: string`, `record_type: string` (padrão: "A").
*   `icmp_ping`: Envia pacotes ICMP e retorna latência (min/avg/max/stddev) e perda de pacotes.
    *   *Argumentos:* `target: string` (IP/Hostname), `count: number` (padrão: 4).
*   `mtu_path_discovery`: Descobre o MTU máximo do caminho sem fragmentação enviando pings ICMP com a flag DF (*Don't Fragment*) ativa.
    *   *Argumentos:* `target: string`, `start_size: number` (padrão: 1500).
*   `trace_route`: Executa um traceroute ou mtr detalhado para listar os saltos de rede entre a VPS e o destino.
    *   *Argumentos:* `target: string`.

### 🔌 Categoria: Conectividade de Portas (L4)
*   `tcp_port_probe`: Tenta estabelecer um handshake TCP básico em uma porta específica para validar se ela está aberta, fechada ou filtrada por Firewall de borda.
    *   *Argumentos:* `ip: string`, `port: number`, `timeout_ms: number` (padrão: 2000).
*   `udp_port_probe`: Tenta sondar portas UDP enviando payloads vazios e escutando por respostas ICMP de erro.
    *   *Argumentos:* `ip: string`, `port: number`.

### 🔐 Categoria: Criptografia & Segurança (L5/L6)
*   `tls_cipher_audit`: Valida as versões TLS aceitas pelo servidor (SSLv3, TLS 1.0, 1.1, 1.2, 1.3) e audita as Cipher Suites suportadas para expor ciphers fracos ou incompatibilidades.
    *   *Argumentos:* `hostname: string`, `port: number` (padrão: 443).
*   `ssl_certificate_check`: Retorna a validade temporal, emissor, SANs e cadeia completa de certificação SSL de um domínio.
    *   *Argumentos:* `hostname: string`.
*   `cdn_bypass_probe`: Tenta contornar a CDN fazendo uma requisição HTTPS direta para o IP público do LoadBalancer de origem, mas injetando o header `Host` correto.
    *   *Argumentos:* `origin_ip: string`, `domain: string`, `port: number` (padrão: 443).

### 🚀 Categoria: Protocolos de Aplicação (L7)
*   `http_detailed_probe`: Efetua uma requisição HTTP customizada de alta fidelidade com coleta detalhada de tempos de resposta (DNS, TCP Handshake, TLS Handshake, TTFB). Suporta especificação de protocolo HTTP/1.1, HTTP/2 ou HTTP/3.
    *   *Argumentos:* `url: string`, `method: string` (GET, POST, etc.), `protocol_version: string` (http1, http2, http3), `headers: object` (opcional), `user_agent: string` (opcional).
*   `websocket_handshake_test`: Tenta estabelecer uma conexão ws/wss de longa duração na borda, realiza o handshake de upgrade e envia/recebe um frame de teste.
    *   *Argumentos:* `url: string`, `headers: object` (opcional).
*   `grpc_health_check`: Testa a saúde de um serviço gRPC exposto externamente enviando uma chamada de Health Check padrão (`grpc.health.v1.Health`).
    *   *Argumentos:* `target: string` (host:port), `service_name: string` (opcional).
*   `http_rate_limit_stress`: Envia uma rajada curta e rápida de requisições HTTP para testar se as barreiras de Rate Limit da borda (WAF ou Ingress) estão ativas e gerando respostas HTTP 429.
    *   *Argumentos:* `url: string`, `requests_count: number` (padrão: 30), `concurrency: number` (padrão: 5).

---

## 🔒 Segurança e Sanitização contra Injeção

Como o servidor executa ferramentas do sistema (`ping`, `traceroute`, `mtr`, `curl`), ele possui proteção rígida contra **Command Injection**:
1.  **Validação por Regex:** Todos os IPs/Hostnames fornecidos como parâmetros passam pela regex `^[a-zA-Z0-9.-]+$`. Qualquer caractere suspeito (como `;`, `&`, `|`, `$`, `\n`) resulta em rejeição imediata do payload com HTTP 400.
2.  **Parâmetros Isolados:** Executamos subprocessos via `child_process.execFile` em vez de `exec`. Isso evita que os argumentos passem por um shell interpretador, impedindo qualquer chance de injeção de parâmetros adicionais.
3.  **Segurança HTTP:** Toda a comunicação é protegida por um Bearer Token (`MCP_API_KEY`) passado no header `Authorization`.

---

## 🚀 Como Iniciar e Compilar (Localmente)

### 1. Instalar as dependências
```bash
npm install
```

### 2. Configurar a chave de segurança no ambiente
```bash
export MCP_API_KEY="uma-chave-secreta-e-longa-aqui"
```

### 3. Rodar em modo de desenvolvimento
```bash
npm run dev
```

### 4. Compilar e Rodar em produção
```bash
npm run build
npm start
```

O servidor escutará na porta `3000` (ou na porta definida na variável de ambiente `PORT`).

---

## 🐳 Construindo e Executando via Docker

O Dockerfile utiliza build multi-estágio para manter a imagem leve e segura, e roda as ferramentas sob o usuário não-root `node`.

### Build da Imagem
```bash
docker build -t ghcr.io/heraque/debugtools-mcp:v1.0.2 .
```

Para publicar a imagem com suporte a nós Kubernetes `amd64` e `arm64`, use `buildx`:

```bash
docker buildx build \
  --platform linux/amd64,linux/arm64 \
  -t ghcr.io/heraque/debugtools-mcp:v1.0.2 \
  -t ghcr.io/heraque/debugtools-mcp:latest \
  --push .
```

Valide o manifest publicado antes de aplicar no Kubernetes:

```bash
docker buildx imagetools inspect ghcr.io/heraque/debugtools-mcp:v1.0.2
```

### Executar Localmente via Container
```bash
docker run -d \
  -p 3000:3000 \
  -e MCP_API_KEY="sua-chave-secreta" \
  --cap-add=NET_RAW \
  ghcr.io/heraque/debugtools-mcp:v1.0.2
```

> [!NOTE]
> A permissão `--cap-add=NET_RAW` é opcional, mas recomendada para que os comandos de `ping` e `mtu_path_discovery` executados dentro do container Linux tenham permissão para abrir sockets ICMP diretamente.

---

## ☸️ Implantação no Kubernetes (VPS Oracle Cloud)

Os manifestos estão disponíveis na pasta `./k8s`. Eles sobem o servidor de forma isolada e o expõem na internet por meio de um serviço com `LoadBalancer` (que aloca um IP público na Oracle Cloud).

### 1. Criar a Secret com o Token de API
Substitua pelo seu token secreto:
```bash
kubectl create secret generic debugtools-mcp-secret \
  --from-literal=api-key="sua-chave-secreta-hermes-mcp"
```

### 2. Aplicar os Manifestos
```bash
kubectl apply -f k8s/deployment.yaml
kubectl apply -f k8s/service.yaml
```

---

## 🤝 Integração do Agente SRE "Hermes" (Cliente MCP)

Como o Hermes está rodando dentro de um cluster Kubernetes privado e precisa se conectar à VPS remota, ele fará o transporte via **Server-Sent Events (SSE)**.

Aqui está um exemplo completo de como o agente Hermes pode se conectar ao servidor MCP remoto usando o SDK oficial do MCP em TypeScript/Node.js:

```typescript
import { Client } from "@modelcontextprotocol/sdk/client/index.js";
import { SSEClientTransport } from "@modelcontextprotocol/sdk/client/sse.js";

async function connectHermesToMcp() {
  const vpsServerUrl = "https://seu-mcp-vps.sua-oracle-vps.com"; // IP público ou domínio da VPS
  const apiKey = "sua-chave-secreta-hermes-mcp"; // A mesma definida na Secret

  console.log("Iniciando transporte SSE com o MCP Diagnostics Server...");

  // Configura a conexão SSE apontando para a rota de handshake (/sse)
  // Passamos o cabeçalho de autenticação via headers personalizados
  const transport = new SSEClientTransport(
    new URL(`${vpsServerUrl}/sse`),
    {
      requestInit: {
        headers: {
          "Authorization": `Bearer ${apiKey}`
        }
      }
    }
  );

  const client = new Client(
    {
      name: "hermes-sre-agent",
      version: "1.0.0"
    },
    {
      capabilities: {
        tools: {}
      }
    }
  );

  // Conecta o cliente Hermes ao servidor remoto
  await client.connect(transport);
  console.log("Hermes conectado com sucesso ao servidor MCP de diagnósticos!");

  // Listar ferramentas de rede disponíveis na VPS
  const tools = await client.listTools();
  console.log("Ferramentas disponíveis para o Hermes:", tools);

  // Exemplo de execução: Testar conectividade de porta de fora para dentro
  const probeResponse = await client.callTool({
    name: "tcp_port_probe",
    arguments: {
      ip: "185.190.140.1",
      port: 443,
      timeout_ms: 3000
    }
  });

  console.log("Resultado do teste de porta de fora para dentro:");
  console.log(probeResponse.content[0].text);
}

connectHermesToMcp().catch(console.error);
```
