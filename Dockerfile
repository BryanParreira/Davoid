# Build Stage
FROM golang:1.25-bookworm AS builder
WORKDIR /app
COPY . .
RUN go build -ldflags "-s -w" -o davoid ./cmd/davoid/

# Runtime Stage
FROM debian:bookworm-slim

RUN apt-get update && apt-get install -y \
    nmap \
    tcpdump \
    dsniff \
    curl \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /app
COPY --from=builder /app/davoid /usr/local/bin/davoid

# Persistent data directories
RUN mkdir -p /root/.davoid /app/logs /app/payloads /app/reports

VOLUME ["/root/.davoid"]

ENTRYPOINT ["davoid"]
