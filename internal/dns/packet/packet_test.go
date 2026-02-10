package packet

import (
	"net"
	"testing"
)

func TestHeaderSerialization(t *testing.T) {
	header := DnsHeader{
		ID:                  1234,
		Response:            true,
		AuthoritativeAnswer: true,
		Questions:           1,
	}

	buffer := NewBytePacketBuffer()
	err := header.Write(buffer)
	if err != nil {
		t.Fatalf("Failed to write header: %v", err)
	}

	if buffer.Position() != 12 {
		t.Errorf("Header should be 12 bytes, got %d", buffer.Position())
	}

	buffer.Seek(0)
	readHeader := DnsHeader{}
	err = readHeader.Read(buffer)
	if err != nil {
		t.Fatalf("Failed to read header: %v", err)
	}

	if readHeader.ID != 1234 {
		t.Errorf("Expected ID 1234, got %d", readHeader.ID)
	}
	if !readHeader.Response {
		t.Errorf("Expected Response bit to be set")
	}
	if !readHeader.AuthoritativeAnswer {
		t.Errorf("Expected AuthoritativeAnswer bit to be set")
	}
}

func TestNameSerialization(t *testing.T) {
	buffer := NewBytePacketBuffer()
	name := "google.com"
	
	err := buffer.WriteName(name)
	if err != nil {
		t.Fatalf("Failed to write name: %v", err)
	}

	buffer.Seek(0)
	readName, err := buffer.ReadName()
	if err != nil {
		t.Fatalf("Failed to read name: %v", err)
	}

	if readName != name {
		t.Errorf("Expected %s, got %s", name, readName)
	}
}

func TestFullPacket(t *testing.T) {
	packet := NewDnsPacket()
	packet.Header.ID = 666
	packet.Header.Response = true
	packet.Questions = append(packet.Questions, DnsQuestion{
		Name:  "test.com",
		QType: A,
	})
	packet.Answers = append(packet.Answers, DnsRecord{
		Name:  "test.com",
		Type:  A,
		Class: 1,
		TTL:   3600,
		IP:    net.ParseIP("127.0.0.1"),
	})

	buffer := NewBytePacketBuffer()
	err := packet.Write(buffer)
	if err != nil {
		t.Fatalf("Failed to write packet: %v", err)
	}

	buffer.Seek(0)
	parsedPacket := NewDnsPacket()
	err = parsedPacket.FromBuffer(buffer)
	if err != nil {
		t.Fatalf("Failed to parse packet: %v", err)
	}

	if parsedPacket.Header.ID != 666 {
		t.Errorf("Expected ID 666, got %d", parsedPacket.Header.ID)
	}
	if len(parsedPacket.Questions) != 1 || parsedPacket.Questions[0].Name != "test.com" {
		t.Errorf("Question mismatch")
	}
	if len(parsedPacket.Answers) != 1 || parsedPacket.Answers[0].IP.String() != "127.0.0.1" {
		t.Errorf("Answer mismatch")
	}
}
