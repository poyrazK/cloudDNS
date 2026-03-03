package server

import (
	"context"
	"net"
	"strings"
	"testing"

	"github.com/poyrazK/cloudDNS/internal/core/domain"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestIXFR_Success(t *testing.T) {
	// Setup Master Repo with history
	masterRepo := &mockServerRepo{}
	zoneID := "zone-1"
	zoneName := "example.com."
	masterRepo.zones = append(masterRepo.zones, domain.Zone{ID: zoneID, Name: zoneName})

	// Serial 1: Base State
	masterRepo.records = append(masterRepo.records, domain.Record{
		ZoneID: zoneID, Name: zoneName, Type: domain.TypeSOA, Content: "ns1.example.com. admin.example.com. 1 3600 600 604800 300",
	})
	masterRepo.records = append(masterRepo.records, domain.Record{
		ZoneID: zoneID, Name: "www.example.com.", Type: domain.TypeA, Content: "1.1.1.1", TTL: 300,
	})

	// Serial 2: Change (Delete 1.1.1.1, Add 2.2.2.2)
	// Log entries for Serial 2
	masterRepo.changes = append(masterRepo.changes, domain.ZoneChange{
		ZoneID: zoneID, Serial: 2, Action: "DELETE", Name: zoneName, Type: domain.TypeSOA, Content: "ns1.example.com. admin.example.com. 1 3600 600 604800 300",
	})
	masterRepo.changes = append(masterRepo.changes, domain.ZoneChange{
		ZoneID: zoneID, Serial: 2, Action: "DELETE", Name: "www.example.com.", Type: domain.TypeA, Content: "1.1.1.1", TTL: 300,
	})
	masterRepo.changes = append(masterRepo.changes, domain.ZoneChange{
		ZoneID: zoneID, Serial: 2, Action: "ADD", Name: "www.example.com.", Type: domain.TypeA, Content: "2.2.2.2", TTL: 300,
	})
	masterRepo.changes = append(masterRepo.changes, domain.ZoneChange{
		ZoneID: zoneID, Serial: 2, Action: "ADD", Name: zoneName, Type: domain.TypeSOA, Content: "ns1.example.com. admin.example.com. 2 3600 600 604800 300",
	})

	// Update current records to Serial 2
	masterRepo.records[0].Content = "ns1.example.com. admin.example.com. 2 3600 600 604800 300"
	masterRepo.records[1].Content = "2.2.2.2"

	masterSrv := NewServer("127.0.0.1:0", masterRepo, nil)
	
	// Start Master TCP Listener
	lc := net.ListenConfig{}
	listener, err := lc.Listen(context.Background(), "tcp", "127.0.0.1:0")
	require.NoError(t, err)
	masterAddr := listener.Addr().String()
	go func() {
		for {
			conn, err := listener.Accept()
			if err != nil {
				return
			}
			go masterSrv.handleTCPConnection(conn)
		}
	}()
	defer func() { _ = listener.Close() }()

	// Setup Slave
	slaveRepo := &mockServerRepo{}
	slaveRepo.zones = append(slaveRepo.zones, domain.Zone{ID: zoneID, Name: zoneName, Role: "slave", MasterServer: "127.0.0.1"})
	// Slave starts at Serial 1
	slaveRepo.records = append(slaveRepo.records, domain.Record{
		ZoneID: zoneID, Name: zoneName, Type: domain.TypeSOA, Content: "ns1.example.com. admin.example.com. 1 3600 600 604800 300",
	})
	slaveRepo.records = append(slaveRepo.records, domain.Record{
		ZoneID: zoneID, Name: "www.example.com.", Type: domain.TypeA, Content: "1.1.1.1", TTL: 300,
	})

	slaveSrv := NewServer("127.0.0.1:0", slaveRepo, nil)
	// Trigger Refresh on Slave
	err = slaveSrv.performIXFR(&slaveRepo.zones[0], masterAddr, 1)
	assert.NoError(t, err)

	// Verify Slave State
	// It should now have 2.2.2.2 and Serial 2
	// Debugging: If Slave has 4, print them.
	if len(slaveRepo.records) != 2 {
		for _, r := range slaveRepo.records {
			t.Logf("Slave Record: %s %s %s", r.Name, r.Type, r.Content)
		}
	}
	assert.Equal(t, 2, len(slaveRepo.records))
	
	var soaFound, aFound bool
	for _, r := range slaveRepo.records {
		if r.Type == domain.TypeSOA {
			if strings.Contains(r.Content, " 2 ") {
				soaFound = true
			}
		}
		if r.Type == domain.TypeA {
			if r.Content == "2.2.2.2" {
				aFound = true
			}
		}
	}
	assert.True(t, soaFound, "SOA v2 not found")
	assert.True(t, aFound, "A 2.2.2.2 not found")
}

func TestIXFR_FallbackToAXFR(t *testing.T) {
	// Master has Serial 10, History only has 5-10. Slave has Serial 1.
	masterRepo := &mockServerRepo{}
	zoneID := "zone-1"
	zoneName := "example.com."
	masterRepo.zones = append(masterRepo.zones, domain.Zone{ID: zoneID, Name: zoneName})
	
	// Current State (Serial 10)
	masterRepo.records = append(masterRepo.records, domain.Record{
		ZoneID: zoneID, Name: zoneName, Type: domain.TypeSOA, Content: "ns1.example.com. admin.example.com. 10 3600 600 604800 300",
	})
	masterRepo.records = append(masterRepo.records, domain.Record{
		ZoneID: zoneID, Name: "www.example.com.", Type: domain.TypeA, Content: "10.10.10.10", TTL: 300,
	})

	// History starts from Serial 5
	masterRepo.changes = append(masterRepo.changes, domain.ZoneChange{
		ZoneID: zoneID, Serial: 6, Action: "ADD", Name: "other.example.com.", Type: domain.TypeA, Content: "6.6.6.6",
	})

	masterSrv := NewServer("127.0.0.1:0", masterRepo, nil)
	
	lc := net.ListenConfig{}
	listener, err := lc.Listen(context.Background(), "tcp", "127.0.0.1:0")
	require.NoError(t, err)
	masterAddr := listener.Addr().String()
	go func() {
		for {
			conn, err := listener.Accept()
			if err != nil {
				return
			}
			go masterSrv.handleTCPConnection(conn)
		}
	}()
	defer func() { _ = listener.Close() }()

	// Slave starts at Serial 1
	slaveRepo := &mockServerRepo{}
	slaveRepo.records = append(slaveRepo.records, domain.Record{
		ZoneID: zoneID, Name: zoneName, Type: domain.TypeSOA, Content: "ns1.example.com. admin.example.com. 1 3600 600 604800 300",
	})

	slaveSrv := NewServer("127.0.0.1:0", slaveRepo, nil)

	// Trigger IXFR from Serial 1 -> Master only has history from 5. Should fallback.
	err = slaveSrv.performIXFR(&domain.Zone{ID: zoneID, Name: zoneName, TenantID: "t1"}, masterAddr, 1)
	assert.NoError(t, err)

	// Verify Slave State matches Master's Full State
	if len(slaveRepo.records) != 2 {
		for _, r := range slaveRepo.records {
			t.Logf("Slave Record (AXFR Fallback): %s %s %s", r.Name, r.Type, r.Content)
		}
	}
	assert.Equal(t, 2, len(slaveRepo.records))
	foundWWW := false
	for _, r := range slaveRepo.records {
		if r.Name == "www.example.com." {
			assert.Equal(t, "10.10.10.10", r.Content)
			foundWWW = true
		}
	}
	assert.True(t, foundWWW)
}
