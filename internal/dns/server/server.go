package server

import (
	"context"
	"fmt"
	"net"
	"github.com/poyrazK/cloudDNS/internal/dns/packet"
	"github.com/poyrazK/cloudDNS/internal/core/ports"
	"github.com/poyrazK/cloudDNS/internal/core/domain"
	"github.com/poyrazK/cloudDNS/internal/adapters/repository"
)

type Server struct {
	Addr string
	Repo ports.DNSRepository
}

func NewServer(addr string, repo ports.DNSRepository) *Server {
	return &Server{Addr: addr, Repo: repo}
}

func (s *Server) Run() error {
	fmt.Printf("Attempting to listen on %s (UDP)...\n", s.Addr)
	pc, err := net.ListenPacket("udp", s.Addr)
	if err != nil {
		fmt.Printf("Failed to listen: %v\n", err)
		return err
	}
	defer pc.Close()

	fmt.Println("DNS Server successfully listening on", s.Addr, "(UDP)...")

	for {
		buf := make([]byte, 512)
		n, addr, err := pc.ReadFrom(buf)
		if err != nil {
			fmt.Println("Read error:", err)
			continue
		}

		go s.handlePacket(pc, addr, buf[:n])
	}
}

func (s *Server) handlePacket(pc net.PacketConn, addr net.Addr, data []byte) {
	fmt.Printf("Received %d bytes from %s\n", len(data), addr)
	// 1. Parse Request
	reqBuffer := packet.NewBytePacketBuffer()
	copy(reqBuffer.Buf, data) // Copy data into buffer structure
	
	request := packet.NewDnsPacket()
	if err := request.FromBuffer(reqBuffer); err != nil {
		fmt.Printf("Failed to parse packet from %s: %s\n", addr, err)
		return
	}

	// 2. Prepare Response
	response := packet.NewDnsPacket()
	response.Header.ID = request.Header.ID
	response.Header.Response = true
	response.Header.Opcode = request.Header.Opcode
	response.Header.RecursionDesired = request.Header.RecursionDesired
	response.Header.RecursionAvailable = false // We are authoritative only
	response.Header.AuthoritativeAnswer = true
	response.Header.ResCode = 0 // NOERROR by default

	// 3. Resolve using Repository
	if len(request.Questions) > 0 {
		q := request.Questions[0]
		response.Questions = append(response.Questions, q)
		
		fmt.Printf("Query: %s %d FROM %s\n", q.Name, q.QType, addr)

		// Map packet.QueryType to domain.RecordType
		var domainType domain.RecordType
		switch q.QType {
		case packet.A: domainType = domain.TypeA
		case packet.AAAA: domainType = domain.TypeAAAA
		case packet.CNAME: domainType = domain.TypeCNAME
		case packet.NS: domainType = domain.TypeNS
		}

		records, err := s.Repo.GetRecords(context.Background(), q.Name, domainType)
		if err != nil {
			fmt.Printf("Repository error: %v\n", err)
			response.Header.ResCode = 2 // SERVFAIL
		} else if len(records) > 0 {
			for _, rec := range records {
				pRec, err := repository.ConvertDomainToPacketRecord(rec)
				if err == nil {
					response.Answers = append(response.Answers, pRec)
				}
			}
		} else {
			response.Header.ResCode = 3 // NXDOMAIN
		}
	} else {
		response.Header.ResCode = 4 // FORMERR
	}

	// 4. Serialize Response
	resBuffer := packet.NewBytePacketBuffer()
	if err := response.Write(resBuffer); err != nil {
		fmt.Printf("Failed to serialize response: %s\n", err)
		return
	}

	// 5. Send Back
	lenRes := resBuffer.Position()
	if _, err := pc.WriteTo(resBuffer.Buf[:lenRes], addr); err != nil {
		fmt.Printf("Failed to send response: %s\n", err)
	}
}