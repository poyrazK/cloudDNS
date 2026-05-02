# ADR 0010: DNS-over-QUIC (DoQ) Support

## Status
Accepted

## Context

cloudDNS currently supports DNS over UDP, TCP, TLS (DoT), and HTTPS (DoH). DNS-over-QUIC (RFC 9250) offers significant advantages over existing transports:

1. **Lower latency** - No head-of-line blocking unlike TCP-based DoT
2. **Better congestion control** - QUIC's congestion control is superior to UDP-based alternatives
3. **Native 0-RTT connection establishment** - Reduces latency for previously connected clients
4. **Built-in encryption** - Unlike raw UDP, QUIC provides built-in encryption without TLS overhead

RFC 9250 specifies DNS-over-QUIC with:
- ALPN protocol identifier `doq`
- Service port 853 (same as DoT)
- Variable-length DNS messages on bidirectional streams (no 2-byte length prefix like TCP)
- Stream cancellation on timeout

## Decision

We chose to implement DoQ as an additional transport alongside existing DoT/DoH:

### Implementation

Added `github.com/quic-go/quic-go v0.59.0` dependency and created `internal/dns/server/doq.go`:

```go
// handleDoQListener handles incoming QUIC connections for DNS-over-QUIC.
func (s *Server) handleDoQListener(listener *quic.Listener)

// handleDoQConnection handles a QUIC session and its streams.
func (s *Server) handleDoQConnection(conn *quic.Conn)

// handleDoQStream handles a single bidirectional QUIC stream.
// RFC 9250 Section 4.2: DNS messages are sent on streams without any framing.
func (s *Server) handleDoQStream(stream *quic.Stream)

// setupDoQListener creates a QUIC listener for DNS-over-QUIC.
func (s *Server) setupDoQListener(addr string) (*quic.Listener, error)
```

### Server Integration

Added to `internal/dns/server/server.go`:

```go
type Server struct {
    // ...
    TLSConfig *tls.Config
    DoQAddr  string // DNS-over-QUIC listen address (default ":853")

    // Listener handles for graceful shutdown
    doqListener *quic.Listener
}
```

Added DoQ listener setup in `Run()` method (section 6):

```go
// 6. DoQ Listener (Port 853)
if s.DoQAddr != "" && s.TLSConfig != nil {
    quicListener, errDoQ := s.setupDoQListener(s.DoQAddr)
    if errDoQ == nil {
        s.doqListener = quicListener
        s.Logger.Info("DNS over QUIC (DoQ) starting", "addr", s.DoQAddr)
        s.wg.Add(1)
        go func() {
            defer s.wg.Done()
            s.handleDoQListener(quicListener)
        }()
    }
}
```

### Key RFC 9250 Requirements

| Requirement | Implementation |
|-------------|----------------|
| ALPN `doq` | Handled automatically by quic-go |
| Variable-length messages | `stream.Read()` returns raw DNS bytes, no framing |
| Port 853 | Same as DoT, configured via `DOQ_ADDR` env var |
| Bidirectional streams | Each DNS query/response uses a dedicated stream |
| Stream timeouts | 30-second read/write deadlines per stream |
| 0-RTT support | Enabled by default via `KeepAlivePeriod: 10s` |

## Consequences

### Positive
- QUIC provides better latency than DoT due to no head-of-line blocking
- 0-RTT enables faster reconnects for health checks and monitoring
- QUIC's built-in encryption is more efficient than TLS for short bursts
- Follows existing cloudDNS pattern for adding protocol transports

### Negative
- Requires TLS configuration (same certificate as DoT/DoH)
- Additional dependency (`quic-go`) increases build complexity
- DoQ support is not as widely adopted as DoT/DoH yet

### Trade-offs
- Reused existing `TLSConfig` field rather than creating separate DoQ certificate
- Chose 30-second timeouts rather than configurable values for simplicity
- Implemented as opt-in via `DoQAddr` rather than always-enabled

## Configuration

DoQ is enabled by setting the `DOQ_ADDR` environment variable:

```bash
DOQ_ADDR=:853   # Enable DoQ on port 853
```

DoQ requires TLS to be configured (DoT must also be configured since they share `TLSConfig`).

## References

- [RFC 9250: DNS-over-QUIC](https://datatracker.ietf.org/doc/html/rfc9250)
- [RFC 7830: DNS-over-QUIC Initial Keys](https://datatracker.ietf.org/doc/html/rfc7830)
- [quic-go library](https://github.com/quic-go/quic-go)
