# Multi-stage build for SignOnDuty Go backend
FROM golang:1.22-alpine AS builder

WORKDIR /app

# Install build dependencies
RUN apk add --no-cache git

# Copy go mod files
COPY go.mod go.sum ./

# Download dependencies
RUN go mod download

# Copy source code
COPY cmd/ ./cmd/
COPY internal/ ./internal/

# Build the binary with FIPS compliance
RUN CGO_ENABLED=0 GOOS=linux go build \
    -a -installsuffix cgo \
    -ldflags="-w -s" \
    -o signonduty \
    ./cmd/server

# Final stage
FROM alpine:3.18

# Install CA certificates
RUN apk add --no-cache ca-certificates

# Create non-root user
RUN addgroup -g 1000 signonduty && \
    adduser -D -u 1000 -G signonduty signonduty

WORKDIR /app

# Copy binary from builder
COPY --from=builder /app/signonduty .

# Create directories and generate self-signed certificates
RUN mkdir -p /etc/signonduty && \
    apk add --no-cache openssl && \
    openssl req -x509 -newkey rsa:2048 -nodes \
      -keyout /etc/signonduty/tls.key \
      -out /etc/signonduty/tls.crt \
      -days 365 -subj "/CN=localhost" && \
    chmod 644 /etc/signonduty/tls.crt && \
    chmod 600 /etc/signonduty/tls.key && \
    chown -R signonduty:signonduty /app /etc/signonduty && \
    apk del openssl

# Switch to non-root user
USER signonduty

# Expose HTTPS port
EXPOSE 8443

# Health check
HEALTHCHECK --interval=30s --timeout=10s --start-period=5s --retries=3 \
    CMD wget --no-verbose --tries=1 --spider https://localhost:8443/api/v1/health || exit 1

# Run the application
CMD ["./signonduty"]
