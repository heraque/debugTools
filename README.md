# debugTools & MCP Diagnostics Server

[![Publish images](https://github.com/heraque/debugTools/actions/workflows/publish.yml/badge.svg)](https://github.com/heraque/debugTools/actions/workflows/publish.yml)

Este repositório fornece duas ferramentas independentes para operações de SRE e troubleshooting em ambientes distribuídos e Kubernetes:

1. **`debugtools`**: Uma imagem de debug clássica (shell-based, não-root) para uso em containers efêmeros (`kubectl debug`).
2. **`debugtools-mcp`**: Um servidor ativo (Model Context Protocol) hospedado em Node.js, focado em expor diagnósticos de rede externos ("de fora para dentro") para serem consumidos por Agentes SRE atuando internamente.

---

## 1. Imagem de Debug Não-Root (`debugtools`)

Imagem de debug segura para uso em containers efêmeros no Kubernetes.

## Objetivo

Esta imagem existe para substituir o uso genérico de `nicolaka/netshoot` em cenários onde o workload alvo exige `runAsNonRoot` e políticas mais rígidas de segurança.

Ela foi desenhada para uso geral em troubleshooting Kubernetes com `kubectl debug`, especialmente quando o caso exige toolbox de rede, DNS e TLS dentro do pod alvo.

## Para que serve

Use esta imagem quando o operador precisar:

- validar DNS, TCP e TLS a partir do namespace/pod real;
- inspecionar resolução de nomes, rotas e sockets;
- fazer `GET`/`HEAD` idempotentes para health checks;
- analisar certificados, cadeias TLS e handshake;
- consultar JSON/YAML/texto com ferramentas simples e previsíveis;
- operar em pods com `runAsNonRoot`, sem depender de imagem root.

## O que esta imagem entrega

Ferramental incluído:

- `bash`
- `bind-tools` (`dig`, `nslookup`)
- `busybox-extras`
- `ca-certificates`
- `coreutils`
- `curl`
- `file`
- `findutils`
- `gawk`
- `grep`
- `iproute2` (`ip`, `ss`)
- `iputils`
- `jq`
- `mtr`
- `netcat-openbsd` (`nc`)
- `openssl`
- `procps`
- `python3`
- `sed`
- `socat`
- `util-linux`
- `wget`
- `yq`

Características operacionais:

- base `alpine:3.23.4`
- usuário numérico fixo `10001:10001`
- `WORKDIR=/workspace`
- imagem pequena o suficiente para uso recorrente, mas completa para diagnóstico de rede/TLS

## O que esta imagem não tenta ser

Esta imagem não tenta virar toolbox universal sem critério.

Ela deliberadamente não inclui por padrão:

- `kubectl`
- `helm`
- `tcpdump`
- clientes específicos de banco (`psql`, `redis-cli`, `mysql`, `mongo`)
- toolchains de build
- Python/Node/Go só para scripting ad hoc

Motivo:

- isso aumenta tamanho, superfície de ataque e drift;
- boa parte desses binários não é necessária para a maioria dos diagnósticos read-only no Kubernetes;
- o objetivo aqui é resolver bem a trilha de conectividade, DNS, TLS, sockets e parsing leve.

Se algum binário extra virar necessidade recorrente e justificada por evidência real, ele deve ser adicionado conscientemente, não por conveniência.

## Como usar

### 1. Clonar o repositório

```bash
git clone git@github.com:heraque/debugTools.git
cd debugTools
```

### 2. Build local

```bash
docker build -t debugtools:test .
```

### 3. Teste local rápido

```bash
docker run --rm debugtools:test sh -lc 'id && dig -v | head -n 1 && openssl version && jq --version'
```

### 4. Uso manual com kubectl debug

Exemplo ilustrativo:

```bash
kubectl debug pod/app-123 \
  -n app-ns \
  --target=app \
  --image=ghcr.io/heraque/debugtools:latest \
  --container=debugger \
  -- bash
```

### 5. Uso como Pod interno temporário

Para subir a imagem como um Pod de diagnóstico dentro do cluster, use o manifest declarativo:

```bash
kubectl apply -f k8s/debugtools-pod.yaml
```

Depois acesse o shell do container:

```bash
kubectl exec -it pod/debugtools -- bash
```

O manifest sobrescreve o comando da imagem com `sleep infinity`. Isso é necessário porque o `CMD ["/bin/bash"]` da imagem é adequado para uso interativo, mas um Pod criado sem TTY pode encerrar imediatamente.

### Arquitetura da imagem

As imagens publicadas devem conter manifests para `linux/amd64` e `linux/arm64`. Antes de usar no Kubernetes, valide a tag:

```bash
docker buildx imagetools inspect ghcr.io/heraque/debugtools:latest
```

Para publicar a imagem de debug com suporte a nós AMD64 e ARM64:

```bash
docker buildx build \
  --platform linux/amd64,linux/arm64 \
  -t ghcr.io/heraque/debugtools:latest \
  --push .
```

## Uso em automações e wrappers

Esta imagem pode ser consumida por wrappers, automações de diagnóstico ou uso manual com `kubectl debug`.

Contrato operacional esperado:

- usar somente em diagnóstico controlado;
- preferir primeiro o runtime nativo do container alvo quando ele já tiver os binários necessários;
- subir para um container efêmero quando:
  - faltarem binários no container alvo;
  - a prova precisar vir do runtime/pod real;
  - o caso exigir toolbox de rede/TLS mais completo.

## Casos típicos de uso

- testar `tcp` e `tls` para `kubernetes.default.svc:443`
- validar SNI e trust chain de um endpoint interno
- confirmar DNS dentro do pod quando a aplicação não tem `dig`/`nslookup`
- analisar `curl -I`/`wget --spider` em endpoints de health
- checar `ss -plant` ou `ip route` durante falha de conectividade
- inspecionar resposta HTTP sem depender de shell livre fora do fluxo de diagnóstico

## Segurança e trade-offs

Pontos de desenho:

- não-root por padrão para compatibilidade com `runAsNonRoot`
- sem privilégio adicional
- sem capabilities extras por padrão
- foco em diagnóstico read-only

Trade-off aceito:

- a imagem não é a menor possível em bytes absolutos;
- ela é pequena o bastante para uso operacional e grande o bastante para evitar fallback tosco durante incidentes reais.

## Quando evoluir esta imagem

Vale mexer nela quando houver evidência recorrente de que falta uma capacidade necessária ao troubleshooting real, por exemplo:

- debugging de DNS/TLS insuficiente;
- parsing estrutural insuficiente;
- incompatibilidade com políticas comuns de segurança de workload.

Não vale mexer nela só porque “pode ser útil algum dia”.

---

## 2. Servidor MCP de Diagnósticos Externos (`debugtools-mcp`)

Enquanto a imagem base é usada "de dentro" do cluster por um humano, o **Servidor MCP** (`debugtools-mcp`) atua como uma sonda ativa na borda (tipicamente instalado em uma VPS exposta à internet), projetado especificamente para ser consumido por um **Agente SRE (Hermes)** de *dentro do cluster*.

Seu objetivo é dar ao Agente a capacidade de enxergar e testar a aplicação exatamente como um usuário na internet enxerga, eliminando pontos cegos causados pelas redes e firewalls internos.

### O que o Servidor MCP entrega (Sondas)

O servidor entrega 14 "tools" (funções) padronizadas via o Model Context Protocol, transportadas sobre um túnel seguro de SSE (Server-Sent Events):

- **L3 (DNS e Rotas):** Checagens de Propagação DNS global, ICMP Pings, descobrimento avançado de Path MTU, Traceroutes (`mtr`), consultas de roteamento BGP ASN (Cymru) e WHOIS de domínio.
- **L4 (Portas):** Probes seguras para portas TCP e UDP, identificando portas fechadas, abertas ou "filtradas" (drop silente).
- **L5/L6 (Segurança e Criptografia):** Auditoria profunda de versões TLS/SSLv3 e Cipher Suites aceitos, parsing de cadeias e validades de certificados, e sondas de "CDN Bypass" realizando Spoofing via IP de origem da borda + Host headers.
- **L7 (Protocolos da Aplicação):** Testes agressivos curtos de "Rate Limit Stress" contra WAFs, sondas avançadas de latência HTTP detalhada (TTFB, DNS, Handshakes), chamadas nativas de gRPC Health Check (`grpc.health.v1`) e sondagens bidirecionais de handshakes em WebSockets de longa duração.

### Segurança Integrada

- Autenticação baseada em `Bearer Token` restrito.
- Todas as validações nativas e regex suportam transparentemente alvos IPv4, IPv6 e Hostnames arbitrários.
- Imune a injeção de comandos (Shell/Bash Inject) via wrappers nativos `execFile` e `net.isIP`.

### Como rodar o MCP Server

**Opção 1: Via Container Docker (Recomendado)**
A imagem publicada herda os binários de L3 da versão "debugtools" base, operando sob usuário e grupo restrito (`10001:10001`).
```bash
docker run -d --name mcp-probe \
  -p 3000:3000 \
  -e MCP_API_KEY="seu_token_secreto" \
  ghcr.io/heraque/debugtools-mcp:v1.0.2
```

Para validar que a tag do MCP Server atende nós AMD64 e ARM64:

```bash
docker buildx imagetools inspect ghcr.io/heraque/debugtools-mcp:v1.0.2
```

**Opção 2: Node.js Local**
```bash
cd mcp-server
npm install
npm run build
MCP_API_KEY="seu_token_secreto" npm start
```

O Agente SRE interno então deverá fechar o túnel SSE conectando-se na VPS em `GET http://<vps-ip>:3000/sse`.
