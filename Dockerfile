# Usa a release estavel mais nova do Alpine verificada em 19/05/2026.
FROM alpine:3.23.4

# Define shell estrito para falhar cedo durante a montagem da imagem.
SHELL ["/bin/sh", "-euxo", "pipefail", "-c"]

# Instala apenas o ferramental generico que o SRE realmente usa em debug de rede,
# TLS, DNS, processos e leitura de artefatos estruturados.
RUN apk add --no-cache \
    bash \
    bind-tools \
    busybox-extras \
    ca-certificates \
    coreutils \
    curl \
    file \
    findutils \
    gawk \
    grep \
    iproute2 \
    iputils \
    jq \
    netcat-openbsd \
    openssl \
    procps \
    python3 \
    sed \
    socat \
    util-linux \
    wget \
    yq \
  && addgroup -g 10001 -S sre \
  && adduser -u 10001 -S -D -G sre -h /home/sre sre \
  && mkdir -p /home/sre /workspace \
  && chown -R 10001:10001 /home/sre /workspace

# Expõe metadados padrao para rastreabilidade e compatibilidade com tooling OCI.
LABEL org.opencontainers.image.title="debugTools" \
      org.opencontainers.image.description="Imagem enxuta de diagnostico SRE nao-root para containers efemeros no Kubernetes" \
      org.opencontainers.image.source="https://github.com/heraque/debugTools" \
      org.opencontainers.image.licenses="MIT"

# Define ambiente previsivel para shells, certificados e area de trabalho.
ENV HOME=/home/sre \
    TERM=xterm-256color \
    PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin

# Garante compatibilidade com policies runAsNonRoot usando UID/GID numericos.
USER 10001:10001
WORKDIR /workspace

# Mantem a imagem util para execucao interativa e comandos injetados pelo wrapper.
CMD ["/bin/bash"]
