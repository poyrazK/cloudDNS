package server

import (
	"context"
	"fmt"
	"io"
	"time"

	"github.com/quic-go/quic-go"
)

// handleDoQListener handles incoming QUIC connections for DNS-over-QUIC.
func (s *Server) handleDoQListener(listener *quic.Listener) {
	for {
		conn, err := listener.Accept(context.Background())
		if err != nil {
			select {
			case <-s.done:
				return
			default:
				continue
			}
		}

		s.wg.Add(1)
		go func() {
			defer s.wg.Done()
			s.handleDoQConnection(conn)
		}()
	}
}

// handleDoQConnection handles a QUIC session and its streams.
func (s *Server) handleDoQConnection(conn *quic.Conn) {
	defer conn.CloseWithError(0, "")

	for {
		stream, err := conn.AcceptStream(context.Background())
		if err != nil {
			return
		}

		s.wg.Add(1)
		go func() {
			defer stream.Close()
			defer s.wg.Done()
			s.handleDoQStream(stream)
		}()
	}
}

// handleDoQStream handles a single bidirectional QUIC stream.
// RFC 9250 Section 4.2: DNS messages are sent on streams without any framing.
func (s *Server) handleDoQStream(stream *quic.Stream) {
	// Set read deadline to prevent hanging on slow clients
	_ = stream.SetReadDeadline(time.Now().Add(30 * time.Second))
	_ = stream.SetWriteDeadline(time.Now().Add(30 * time.Second))

	// DNS-over-QUIC uses variable-length messages (no 2-byte length prefix like TCP)
	buf := make([]byte, 65535)
	n, err := stream.Read(buf)
	if err != nil {
		if err != io.EOF && err != io.ErrUnexpectedEOF {
			return
		}
	}
	if n == 0 {
		return
	}

	dnsMsg := make([]byte, n)
	copy(dnsMsg, buf[:n])

	// Process the DNS message - use placeholder IP since QUIC doesn't provide peer addr
	s.handlePacket(context.Background(), dnsMsg, "127.0.0.1:0", func(resp []byte) error {
		_, err := stream.Write(resp)
		return err
	}, "doq")
}

// setupDoQListener creates a QUIC listener for DNS-over-QUIC.
func (s *Server) setupDoQListener(addr string) (*quic.Listener, error) {
	quicConfig := &quic.Config{
		// Require handshaking to complete for 0-RTT early data acceptance.
		// 0-RTT has privacy implications but improves latency for known entities.
		KeepAlivePeriod: 10 * time.Second,
		MaxIdleTimeout: 30 * time.Second,
	}

	tlsConfig := s.TLSConfig
	if tlsConfig == nil {
		return nil, fmt.Errorf("TLS config required for DoQ")
	}

	listener, err := quic.ListenAddr(addr, tlsConfig, quicConfig)
	if err != nil {
		return nil, fmt.Errorf("failed to create DoQ listener: %w", err)
	}

	return listener, nil
}
