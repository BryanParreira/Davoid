# Build Stage
FROM golang:1.24-bookworm AS builder
WORKDIR /app
COPY . .
RUN go build -ldflags "-s -w" -o davoid ./cmd/davoid/

# Runtime Stage
FROM debian:bookworm-slim

# Install optional operational tools used by Davoid
RUN apt-get update && apt-get install -y \
    nmap \
    tcpdump \
    dsniff \
    curl \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /app
COPY --from=builder /app/davoid /usr/local/bin/davoid

RUN mkdir -p logs payloads plugins reports

# Set entrypoint to run the compiled binary
ENTRYPOINT ["davoid"]