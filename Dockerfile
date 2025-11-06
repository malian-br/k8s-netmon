# Multi-stage build for minimal attack surface
FROM golang:1.23-alpine AS builder

# Install build dependencies
RUN apk add --no-cache \
    clang \
    llvm \
    libbpf-dev \
    linux-headers \
    make \
    gcc \
    musl-dev

WORKDIR /build

# Copy go mod files
COPY go.mod go.sum ./
RUN go mod download

# Copy source
COPY . .

# Generate eBPF bytecode
RUN go generate ./...

# Build static binary
RUN CGO_ENABLED=0 GOOS=linux GOARCH=amd64 go build \
    -ldflags="-w -s" \
    -a -installsuffix cgo \
    -o netmon .

# Final minimal image
FROM alpine:3.20

# Install only runtime dependencies
RUN apk add --no-cache \
    ca-certificates \
    libbpf

# Create non-root user
RUN addgroup -g 1000 netmon && \
    adduser -D -u 1000 -G netmon netmon

WORKDIR /app

# Copy binary from builder
COPY --from=builder /build/netmon /app/

# Run as non-root user (will need privileged for eBPF)
USER netmon

ENTRYPOINT ["/app/netmon"]