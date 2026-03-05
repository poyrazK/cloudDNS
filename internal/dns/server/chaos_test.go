package server

import (
	"errors"
	"net"
	"testing"
	"time"

	"github.com/poyrazK/cloudDNS/internal/core/domain"
	"github.com/poyrazK/cloudDNS/internal/dns/packet"
	"github.com/poyrazK/cloudDNS/internal/testutil"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"
)

func TestChaos_SimulateDBLatency(t *testing.T) {
	mockRepo := new(testutil.MockRepo)
	srv := NewServer("127.0.0.1:0", mockRepo, nil)
	srv.DisableAsync = true
	// Set an intentional latency
	baseLatency := 50 * time.Millisecond
	srv.SimulateDBLatency = baseLatency

	mockRepo.On("GetZone", mock.Anything, mock.Anything).Return(&domain.Zone{ID: "zone1", Name: "example.com."}, nil)
	mockRepo.On("GetRecords", mock.Anything, mock.Anything, mock.Anything, mock.Anything).Return([]domain.Record{
		{Name: "example.com.", Type: domain.TypeA, Content: "1.2.3.4", TTL: 300},
	}, nil)

	req := packet.NewDNSPacket()
	req.Header.ID = 1234
	req.Questions = append(req.Questions, packet.DNSQuestion{Name: "example.com.", QType: packet.A, QClass: 1})
	buf := packet.GetBuffer()
	_ = req.Write(buf)
	data := buf.Buf[:buf.Position()]
	packet.PutBuffer(buf)

	start := time.Now()
	err := srv.handlePacket(data, &net.UDPAddr{IP: net.ParseIP("127.0.0.1"), Port: 12345}, func(resp []byte) error {
		return nil
	}, "udp")

	duration := time.Since(start)
	assert.NoError(t, err)

	// Due to jitter formula: SimulateDBLatency * (0.5 + jitter(0.0-1.0))
	// The minimum delay is 0.5 * SimulateDBLatency
	minExpectedDelay := time.Duration(float64(baseLatency) * 0.5)
	
	// Add a small buffer for execution time, but mainly ensure the sleep happened
	assert.GreaterOrEqual(t, duration.Milliseconds(), minExpectedDelay.Milliseconds(), "Latency simulation failed to delay the request")
}

func TestChaos_DBError_Query(t *testing.T) {
	mockRepo := new(testutil.MockRepo)
	srv := NewServer("127.0.0.1:0", mockRepo, nil)
	srv.DisableAsync = true

	// Simulate database connection failure during zone and records fetch
	mockRepo.On("GetZone", mock.Anything, mock.Anything).Return((*domain.Zone)(nil), errors.New("simulated db connection lost"))
	mockRepo.On("GetRecords", mock.Anything, mock.Anything, mock.Anything, mock.Anything).Return(([]domain.Record)(nil), errors.New("simulated db connection lost"))

	req := packet.NewDNSPacket()
	req.Header.ID = 5678
	req.Questions = append(req.Questions, packet.DNSQuestion{Name: "error.test.", QType: packet.A, QClass: 1})
	buf := packet.GetBuffer()
	_ = req.Write(buf)
	data := buf.Buf[:buf.Position()]
	packet.PutBuffer(buf)

	var responseData []byte
	err := srv.handlePacket(data, "127.0.0.1:54321", func(resp []byte) error {
		responseData = resp
		return nil
	}, "udp")

	assert.NoError(t, err, "handlePacket should not return an error despite DB failing; it should gracefully degrade")

	res := packet.NewDNSPacket()
	resBuf := packet.GetBuffer()
	resBuf.Load(responseData)
	err = res.FromBuffer(resBuf)
	packet.PutBuffer(resBuf)

	assert.NoError(t, err)
	assert.Equal(t, uint16(5678), res.Header.ID)
	// With no zone and no recursion enabled, the server defaults to NXDOMAIN (RCODE 3).
	// Crucially, it must not panic and should still form a valid response packet.
	assert.Equal(t, uint8(packet.RcodeNxDomain), res.Header.ResCode)
}

func TestChaos_DBError_Update(t *testing.T) {
	mockRepo := new(testutil.MockRepo)
	srv := NewServer("127.0.0.1:0", mockRepo, nil)
	srv.DisableAsync = true

	// Simulate zone exists, but prerequisite check fails because GetRecords throws a DB error
	mockRepo.On("GetZone", mock.Anything, mock.Anything).Return(&domain.Zone{ID: "zone1", Name: "update.test."}, nil)
	mockRepo.On("GetRecords", mock.Anything, mock.Anything, mock.Anything, mock.Anything).Return(([]domain.Record)(nil), errors.New("db offline"))

	req := packet.NewDNSPacket()
	req.Header.ID = 9999
	req.Header.Opcode = packet.OpcodeUpdate
	req.Questions = append(req.Questions, packet.DNSQuestion{Name: "update.test.", QType: packet.SOA, QClass: 1})
	
	// Add a prerequisite that will require a DB lookup
	req.Answers = append(req.Answers, packet.DNSRecord{Name: "update.test.", Type: packet.ANY, Class: 255})

	buf := packet.GetBuffer()
	_ = req.Write(buf)
	data := buf.Buf[:buf.Position()]
	packet.PutBuffer(buf)

	var responseData []byte
	err := srv.handlePacket(data, "127.0.0.1:54321", func(resp []byte) error {
		responseData = resp
		return nil
	}, "udp")

	assert.NoError(t, err)

	res := packet.NewDNSPacket()
	resBuf := packet.GetBuffer()
	resBuf.Load(responseData)
	err = res.FromBuffer(resBuf)
	packet.PutBuffer(resBuf)

	assert.NoError(t, err, "Response packet should be well-formed")
	// Since prerequisite check threw an error from DB ("failed to fetch records for prerequisite check"),
	// it should return SERVFAIL.
	assert.Equal(t, uint8(packet.RcodeServFail), res.Header.ResCode)
}
