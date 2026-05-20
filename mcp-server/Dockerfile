# =========================================================
# Stage 1: Build the TypeScript server
# =========================================================
FROM node:20-alpine AS builder

WORKDIR /usr/src/app

COPY package*.json tsconfig.json ./
RUN npm ci

COPY src/ ./src
RUN npm run build

# =========================================================
# Stage 2: Clean and secure lightweight production runner
# =========================================================
FROM node:20-alpine

# Set Node environment
ENV NODE_ENV=production

# Install essential system-level networking tools needed by binary probes
# - bind-tools: provides 'dig' and 'nslookup'
# - iputils: provides robust 'ping' supporting -M do (DF flags) and high-resolution timing
# - mtr: provides My Traceroute
# - traceroute: fallback hops mapping
# - curl: L7 detailed client (supports HTTP/1, HTTP/2, and depending on build, HTTP/3)
RUN apk add --no-cache \
    bind-tools \
    iputils \
    mtr \
    traceroute \
    curl

WORKDIR /usr/src/app

COPY package*.json ./
RUN npm ci --only=production

# Copy compiled JavaScript from builder stage
COPY --from=builder /usr/src/app/dist ./dist
COPY src/utils/health.proto ./dist/utils/health.proto

# Ensure system ping has setuid permission so non-root 'node' user can execute ICMP probes safely
RUN chmod u+s /bin/ping || true

# Switch to standard non-privileged node user for high security
USER node

# Expose SSE listener port
EXPOSE 3000

ENV PORT=3000

CMD ["node", "dist/index.js"]
