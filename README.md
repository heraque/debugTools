# debugTools

Imagem de debug não-root para uso em containers efêmeros de diagnóstico no Kubernetes.

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
- `netcat-openbsd` (`nc`)
- `openssl`
- `procps`
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

### 1. Publicar no GHCR

O workflow em `.github/workflows/publish.yml` publica a imagem em:

```text
ghcr.io/heraque/debugtools
```

Fluxo esperado:

1. subir mudanças na branch `main`;
2. deixar o GitHub Actions buildar e publicar;
3. preferir tags versionadas para produção, por exemplo `v0.1.0`;
4. evitar depender de `:main` por muito tempo em ambientes estáveis.

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
  --image=ghcr.io/heraque/debugtools:v0.1.0 \
  --container=debugger \
  -- bash
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

## Versionamento recomendado

Para uso operacional estável:

- publique com tag semântica, por exemplo `v0.1.0`
- fixe o chart/consumer nesse tag
- use `:main` apenas como trilha de desenvolvimento

## Quando evoluir esta imagem

Vale mexer nela quando houver evidência recorrente de que falta uma capacidade necessária ao troubleshooting real, por exemplo:

- debugging de DNS/TLS insuficiente;
- parsing estrutural insuficiente;
- incompatibilidade com políticas comuns de segurança de workload.

Não vale mexer nela só porque “pode ser útil algum dia”.
