package main

import (
	"net"
	"testing"

	"github.com/DATA-DOG/go-sqlmock"
	"github.com/poyrazK/cloudDNS/internal/dns/packet"
)

func TestRunBench_Errors(t *testing.T) {
	db, mock, _ := sqlmock.New()
	defer func() { _ = db.Close() }()

	// 1. Fetch names error
	mock.ExpectQuery("SELECT .* FROM dns_records").WillReturnError(sqlmock.ErrCancelled)
	err := RunBench(db, "127.0.0.1:10053", 10, 1)
	if err == nil {
		t.Error("Expected error when fetch names fails")
	}

	// 2. No names in DB
	mock.ExpectQuery("SELECT .* FROM dns_records").WillReturnRows(sqlmock.NewRows(nil))
	err = RunBench(db, "127.0.0.1:10053", 10, 1)
	if err == nil {
		t.Error("Expected error when no names found")
	}
	
	if err := mock.ExpectationsWereMet(); err != nil {
		t.Errorf("unmet sqlmock expectations: %v", err)
	}
}

func TestRunBench_Success(t *testing.T) {
	db, mock, _ := sqlmock.New()
	defer func() { _ = db.Close() }()

	rows := sqlmock.NewRows([]string{"name"}).
		AddRow("example.com.").
		AddRow("test.org.")
	mock.ExpectQuery("SELECT .* FROM dns_records").WillReturnRows(rows)

	// Start mock UDP server
	addr, _ := net.ResolveUDPAddr("udp", "127.0.0.1:0")
	conn, _ := net.ListenUDP("udp", addr)
	defer conn.Close()
	
	go func() {
		buf := make([]byte, 512)
		for {
			n, remote, err := conn.ReadFromUDP(buf)
			if err != nil { return }
			
			req := packet.NewDNSPacket()
			pb := packet.NewBytePacketBuffer()
			pb.Load(buf[:n])
			_ = req.FromBuffer(pb)
			
			resp := packet.NewDNSPacket()
			resp.Header.ID = req.Header.ID
			resp.Header.Response = true
			resBuf := packet.NewBytePacketBuffer()
			_ = resp.Write(resBuf)
			_, _ = conn.WriteToUDP(resBuf.Buf[:resBuf.Position()], remote)
		}
	}()

	err := RunBench(db, conn.LocalAddr().String(), 5, 2)
	if err != nil {
		t.Errorf("RunBench failed: %v", err)
	}
	
	if err := mock.ExpectationsWereMet(); err != nil {
		t.Errorf("unmet sqlmock expectations: %v", err)
	}
}

func TestMain_Coverage(t *testing.T) {
	// Call Run instead of main to avoid os.Exit
	_ = Run([]string{"iana-bench", "-n", "1", "-c", "1"})
}
