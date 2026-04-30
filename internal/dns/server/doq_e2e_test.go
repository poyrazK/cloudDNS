package server

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"math/big"
	"testing"
	"time"

	"github.com/poyrazK/cloudDNS/internal/core/domain"
	"github.com/poyrazK/cloudDNS/internal/dns/packet"
	"github.com/quic-go/quic-go"
)

// generateTLSConfig creates a self-signed TLS config for DoQ testing.
func generateTLSConfig() *tls.Config {
	_, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		panic(err)
	}
	template := x509.Certificate{SerialNumber: big.NewInt(1)}
	certDER, err := x509.CreateCertificate(rand.Reader, &template, &template, priv.Public(), priv)
	if err != nil {
		panic(err)
	}
	return &tls.Config{
		Certificates: []tls.Certificate{{
			Certificate: [][]byte{certDER},
			PrivateKey:  priv,
		}},
		NextProtos: []string{"doq"},
	}
}

func TestDoQ_E2E_BasicQuery(t *testing.T) {
	repo := &mockServerRepo{
		records: []domain.Record{
			{Name: "doq-e2e.test.", Type: domain.TypeA, Content: "9.9.9.9", TTL: 60},
		},
		zones: []domain.Zone{
			{ID: "zone1", Name: "doq-e2e.test."},
		},
	}
	srv := NewServer("127.0.0.1:0", repo, nil)
	srv.TLSConfig = generateTLSConfig()
	srv.DoQAddr = GetFreeAddr()

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go func() {
		_ = srv.Run(ctx)
	}()
	time.Sleep(200 * time.Millisecond)

	// Dial QUIC client
	tlsConf := &tls.Config{
		InsecureSkipVerify: true,
		NextProtos:         []string{"doq"},
	}
	conn, err := quic.DialAddr(ctx, srv.DoQAddr, tlsConf, nil)
	if err != nil {
		t.Fatalf("Failed to dial QUIC: %v", err)
	}
	defer conn.CloseWithError(0, "")

	// Open stream and send DNS query
	stream, err := conn.OpenStream()
	if err != nil {
		t.Fatalf("Failed to open stream: %v", err)
	}

	// Build DNS query
	q := packet.NewDNSPacket()
	q.Header.ID = 1234
	q.Questions = append(q.Questions, packet.DNSQuestion{Name: "doq-e2e.test.", QType: packet.A})
	qb := packet.NewBytePacketBuffer()
	_ = q.Write(qb)
	queryBytes := qb.Buf[:qb.Position()]

	// Write DNS query (variable-length, no framing per RFC 9250)
	_, err = stream.Write(queryBytes)
	if err != nil {
		t.Fatalf("Failed to write query: %v", err)
	}

	// Give server time to process and respond - QUIC is async
	time.Sleep(500 * time.Millisecond)

	// Read response - stream is still open for reading
	respBuf := make([]byte, 65535)
	stream.SetReadDeadline(time.Now().Add(5 * time.Second))
	n, err := stream.Read(respBuf)
	if err != nil && !(n > 0 && isEOFLike(err)) {
		t.Fatalf("Failed to read response (n=%d, err=%v): %v", n, err, err)
	}
	_ = stream.Close()

	// Parse response
	resPacket := packet.NewDNSPacket()
	resBuf := packet.NewBytePacketBuffer()
	resBuf.Load(respBuf[:n])
	if err := resPacket.FromBuffer(resBuf); err != nil {
		t.Fatalf("Failed to parse response: %v", err)
	}

	if len(resPacket.Answers) != 1 || resPacket.Answers[0].IP.String() != "9.9.9.9" {
		t.Errorf("Expected answer 9.9.9.9, got: %+v", resPacket.Answers)
	}
	_ = stream.Close()
}

func TestDoQ_E2E_MultipleStreams(t *testing.T) {
	repo := &mockServerRepo{
		records: []domain.Record{
			{Name: "multi-doq.test.", Type: domain.TypeA, Content: "1.2.3.4", TTL: 60},
		},
		zones: []domain.Zone{
			{ID: "zone1", Name: "multi-doq.test."},
		},
	}
	srv := NewServer("127.0.0.1:0", repo, nil)
	srv.TLSConfig = generateTLSConfig()
	srv.DoQAddr = GetFreeAddr()

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go func() {
		_ = srv.Run(ctx)
	}()
	time.Sleep(200 * time.Millisecond)

	tlsConf := &tls.Config{
		InsecureSkipVerify: true,
		NextProtos:         []string{"doq"},
	}
	conn, err := quic.DialAddr(ctx, srv.DoQAddr, tlsConf, nil)
	if err != nil {
		t.Fatalf("Failed to dial QUIC: %v", err)
	}
	defer conn.CloseWithError(0, "")

	// Open first stream
	stream1, _ := conn.OpenStream()
	defer stream1.Close()

	q1 := packet.NewDNSPacket()
	q1.Questions = append(q1.Questions, packet.DNSQuestion{Name: "multi-doq.test.", QType: packet.A})
	qb1 := packet.NewBytePacketBuffer()
	_ = q1.Write(qb1)
	_, _ = stream1.Write(qb1.Buf[:qb1.Position()])

	respBuf1 := make([]byte, 65535)
	stream1.SetReadDeadline(time.Now().Add(5 * time.Second))
	n1, _ := stream1.Read(respBuf1)

	// Open second stream (same connection)
	stream2, _ := conn.OpenStream()
	defer stream2.Close()

	q2 := packet.NewDNSPacket()
	q2.Header.ID = 5678
	q2.Questions = append(q2.Questions, packet.DNSQuestion{Name: "multi-doq.test.", QType: packet.A})
	qb2 := packet.NewBytePacketBuffer()
	_ = q2.Write(qb2)
	_, _ = stream2.Write(qb2.Buf[:qb2.Position()])

	respBuf2 := make([]byte, 65535)
	stream2.SetReadDeadline(time.Now().Add(5 * time.Second))
	n2, _ := stream2.Read(respBuf2)

	resPacket := packet.NewDNSPacket()
	pb := packet.NewBytePacketBuffer()
	pb.Load(respBuf1[:n1])
	_ = resPacket.FromBuffer(pb)
	if len(resPacket.Answers) != 1 || resPacket.Answers[0].IP.String() != "1.2.3.4" {
		t.Errorf("First stream response failed")
	}

	resPacket2 := packet.NewDNSPacket()
	pb2 := packet.NewBytePacketBuffer()
	pb2.Load(respBuf2[:n2])
	_ = resPacket2.FromBuffer(pb2)
	if len(resPacket2.Answers) != 1 || resPacket2.Answers[0].IP.String() != "1.2.3.4" {
		t.Errorf("Second stream response failed")
	}
}

func TestDoQ_E2E_InvalidQuery(t *testing.T) {
	repo := &mockServerRepo{
		records: []domain.Record{
			{Name: "invalid-doq.test.", Type: domain.TypeA, Content: "1.2.3.4", TTL: 60},
		},
	}
	srv := NewServer("127.0.0.1:0", repo, nil)
	srv.TLSConfig = generateTLSConfig()
	srv.DoQAddr = GetFreeAddr()

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go func() {
		_ = srv.Run(ctx)
	}()
	time.Sleep(200 * time.Millisecond)

	tlsConf := &tls.Config{
		InsecureSkipVerify: true,
		NextProtos:         []string{"doq"},
	}
	conn, err := quic.DialAddr(ctx, srv.DoQAddr, tlsConf, nil)
	if err != nil {
		t.Fatalf("Failed to dial QUIC: %v", err)
	}
	defer conn.CloseWithError(0, "")

	stream, _ := conn.OpenStream()
	defer stream.Close()

	// Write invalid DNS message (too short)
	_, _ = stream.Write([]byte{0x01, 0x02})

	// Server should handle gracefully (close stream or return empty)
	respBuf := make([]byte, 65535)
	stream.SetReadDeadline(time.Now().Add(5 * time.Second))
	_, err = stream.Read(respBuf)
	// EOF or error is acceptable - server may close stream on parse failure
	if err != nil && !isEOFLike(err) {
		t.Logf("Stream error (may be expected): %v", err)
	}
}

func TestDoQ_E2E_ConnectionClose(t *testing.T) {
	repo := &mockServerRepo{
		records: []domain.Record{
			{Name: "close-doq.test.", Type: domain.TypeA, Content: "5.6.7.8", TTL: 60},
		},
	}
	srv := NewServer("127.0.0.1:0", repo, nil)
	srv.TLSConfig = generateTLSConfig()
	srv.DoQAddr = GetFreeAddr()

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go func() {
		_ = srv.Run(ctx)
	}()
	time.Sleep(200 * time.Millisecond)

	tlsConf := &tls.Config{
		InsecureSkipVerify: true,
		NextProtos:         []string{"doq"},
	}
	conn, err := quic.DialAddr(ctx, srv.DoQAddr, tlsConf, nil)
	if err != nil {
		t.Fatalf("Failed to dial QUIC: %v", err)
	}

	// Close connection explicitly
	conn.CloseWithError(0, "")

	// Give server time to process close
	time.Sleep(100 * time.Millisecond)
	cancel()
}

func isEOFLike(err error) bool {
	if err == nil {
		return true
	}
	// Check for EOF, stream closed, etc.
	return bytes.Contains([]byte(err.Error()), []byte("EOF")) ||
		bytes.Contains([]byte(err.Error()), []byte("closed"))
}
