# Build stage
FROM golang:1.24-alpine AS builder

# Install build dependencies for CGO (though we plan to disable it)
RUN apk add --no-cache git gcc musl-dev

WORKDIR /app

# Copy go.mod and go.sum first for better caching
COPY go.mod go.sum ./
RUN go mod download

# Copy the rest of the source code
COPY . .

# Build a statically linked binary
# CGO_ENABLED=0 ensures we don't depend on glibc
RUN CGO_ENABLED=0 go build -ldflags="-s -w" -o clouddns cmd/clouddns/main.go

# Final stage
FROM alpine:3.20

# Add security updates and root CA certificates
RUN apk add --no-cache ca-certificates tzdata

WORKDIR /app

# Create a non-root user for security
RUN adduser -D -u 1000 clouddns
USER clouddns

# Copy the binary from the builder
COPY --from=builder /app/clouddns .
# Copy schema for database initialization if needed (used by entrypoint scripts)
COPY --from=builder /app/internal/adapters/repository/schema.sql ./schema.sql

# Expose standard DNS ports
EXPOSE 53/udp 53/tcp
# Expose DoT port
EXPOSE 853/tcp
# Expose Management API and DoH port
EXPOSE 8080/tcp
# Expose default DoH port if configured
EXPOSE 443/tcp

# Run the server
ENTRYPOINT ["./clouddns"]
