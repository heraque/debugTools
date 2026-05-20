# Changelog

Todas as mudanças notáveis deste projeto serão documentadas neste arquivo.

O formato baseia-se no [Keep a Changelog](https://keepachangelog.com/pt-BR/1.0.0/), e este projeto adere ao [Versionamento Semântico](https://semver.org/lang/pt-BR/).

## [1.0.2] - 2026-05-20

Nesta release, a imagem da ferramenta de Debug ganha a adição massiva de um novo Servidor MCP, habilitando a execução de diagnósticos de rede e de borda a partir de Agentes autônomos dentro de clusters.

### Added (Adicionado)
- **Servidor MCP de Diagnósticos:** Adição do módulo `mcp-server` Node.js focado em SRE. Fornece ferramentas robustas que habilitam visibilidade L3-L7 ("de fora para dentro").
- **14 Ferramentas Diagnósticas (Tools MCP):** Adicionadas sondas completas para DNS, ICMP, MTU Path Discovery, UDP/TCP probes, TLS/SSL audit, CDN Bypass (Host Spoofing), Handshakes HTTP/1/2/3, WebSockets, gRPC Health Checks e Rate Limit Stress.
- **Whois & BGP Asn Lookup:** Adicionadas as sondas de `whois_domain_lookup` e consulta TXT à base de dados Cymru (`bgp_asn_lookup`) via DNS para mapeamento robusto de tráfego de operadoras.

### Fixed (Corrigido)
- **Sanitização de IPv6:** A regex rígida contra injeção de comandos rejeitava todos os alvos IPv6 devido aos dois-pontos (`:`). A validação foi reescrita utilizando o binding nativo de segurança C++ do Node (`net.isIP`).
- **Crash Síncrono de Ciphers no Node:** Testar o cipher obsoleto `SSLv3` gerava um `TypeError` imediato, derrubando o container por ausência de `try/catch`. 
- **Matemática do MTU Path Discovery:** Ajustado o cálculo dinâmico de `overhead` subtraído das sondas ICMP. Agora a lógica discerne perfeitamente 48 bytes se for IPv6 ou 28 bytes se for IPv4.
- **Hang Timeout do WebSocket:** Ferramenta `websocket_handshake_test` pendurava indefinitivamente na memória se o servidor se recusasse a retornar o payload `pong`. Introduzido threshold de timeout de 3000ms.
- **Build de Dependências gRPC:** O binário não conseguia injetar o `health.proto` nas instâncias compiladas locais. O script de compilação `tsc` foi modificado para suportar o pipeline de assets secundários via filesystem de forma silenciosa.

### Changed (Modificado)
- **CD Pipeline:** Workflow `.github/workflows/publish.yml` atualizado para buildar não apenas a base de `debugtools` mas agora publicar paralelamente o worker ativo `debugtools-mcp`. O hook foi travado para acionar apenas em Releases Oficiais.

### Removed (Removido)
- **Lixo de Rastreamento (Bloat):** Deletado o rastreio acidental da pasta `mcp-server/node_modules/` que estava sobrecarregando os diffs e logs do Git.
- Implementado `.gitignore` robusto na base e pasta interna para prevenir a subida de binários `/dist` e artefatos em Node.
