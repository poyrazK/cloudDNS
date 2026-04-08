package main

import (
	"net"
	"testing"

	"github.com/DATA-DOG/go-sqlmock"
	"github.com/poyrazK/cloudDNS/internal/dns/packet"
)

func TestRunBench_Errors(t *testing.T) {
	db, mock, err := sqlmock.New()
	if err != nil { t.Fatalf("sqlmock.New failed: %v", err) }
	defer func() { _ = db.Close() }()

	// 1. Fetch names error
	mock.ExpectQuery("SELECT .* FROM dns_records").WillReturnError(sqlmock.ErrCancelled)
	err = RunBench(db, "127.0.0.1:10053", 10, 1)
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
	db, mock, err := sqlmock.New()
	if err != nil { t.Fatalf("sqlmock.New failed: %v", err) }
	defer func() { _ = db.Close() }()

	rows := sqlmock.NewRows([]string{"name"}).
		AddRow("example.com.").
		AddRow("test.org.")
	mock.ExpectQuery("SELECT .* FROM dns_records").WillReturnRows(rows)

	// Start mock UDP server
	addr, err := net.ResolveUDPAddr("udp", "127.0.0.1:0")
	if err != nil { t.Fatalf("net.ResolveUDPAddr failed: %v", err) }
	conn, err := net.ListenUDP("udp", addr)
	if err != nil { t.Fatalf("net.ListenUDP failed: %v", err) }
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

	err = RunBench(db, conn.LocalAddr().String(), 5, 2)
	if err != nil {
		t.Errorf("RunBench failed: %v", err)
	}
	
	if err := mock.ExpectationsWereMet(); err != nil {
		t.Errorf("unmet sqlmock expectations: %v", err)
	}
}

func TestMain_Coverage(t *testing.T) {
	t.Setenv("DATABASE_URL", "none")
	// Call Run instead of main to avoid os.Exit
	if err := Run([]string{"iana-bench", "-n", "1", "-c", "1"}); err != nil {
		t.Errorf("Run failed: %v", err)
	}
}

func TestRun_ConfigErrors(t *testing.T) {
	t.Run("InvalidFlags", func(t *testing.T) {
		if err := Run([]string{"iana-bench", "-invalid-flag"}); err == nil {
			t.Error("Expected error for invalid flag")
		}
	})

	t.Run("InvalidDB", func(t *testing.T) {
		t.Setenv("DATABASE_URL", "invalid-url")
		if err := Run([]string{"iana-bench"}); err == nil {
			t.Error("Expected error for invalid database URL")
		}
	})
}
