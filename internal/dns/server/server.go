package server

import (
	"context"
	"fmt"
	"net"
	"time"
	"github.com/poyrazK/cloudDNS/internal/dns/packet"
	"github.com/poyrazK/cloudDNS/internal/core/ports"
	"github.com/poyrazK/cloudDNS/internal/core/domain"
	"github.com/poyrazK/cloudDNS/internal/adapters/repository"
)

type Server struct {
	Addr  string
	Repo  ports.DNSRepository
	Cache *DNSCache
}

func NewServer(addr string, repo ports.DNSRepository) *Server {
	return &Server{
		Addr:  addr,
		Repo:  repo,
		Cache: NewDNSCache(),
	}
}

func (s *Server) Run() error {
	fmt.Printf("Attempting to listen on %s (UDP/TCP)...\n", s.Addr)

	// UDP
	udpAddr, err := net.ResolveUDPAddr("udp", s.Addr)
	if err != nil {
		return err
	}
	udpConn, err := net.ListenUDP("udp", udpAddr)
	if err != nil {
		fmt.Printf("Failed to listen UDP: %v\n", err)
		return err
	}
	defer udpConn.Close()

	// TCP
	tcpListener, err := net.Listen("tcp", s.Addr)
	if err != nil {
		fmt.Printf("Failed to listen TCP: %v\n", err)
		return err
	}
	defer tcpListener.Close()

	fmt.Println("DNS Server successfully listening on", s.Addr, "(UDP and TCP)...")

	go func() {
		for {
			conn, err := tcpListener.Accept()
			if err != nil {
				fmt.Println("TCP Accept error:", err)
				continue
			}
			go s.handleTCPConnection(conn)
		}
	}()

	for {
		buf := make([]byte, 512)
		n, addr, err := udpConn.ReadFrom(buf)
		if err != nil {
			fmt.Println("UDP Read error:", err)
			continue
		}

		go s.handleUDPConnection(udpConn, addr, buf[:n])
	}
}

func (s *Server) handleUDPConnection(pc net.PacketConn, addr net.Addr, data []byte) {
	fmt.Printf("Received %d bytes via UDP from %s\n", len(data), addr)
	s.handlePacket(data, func(resp []byte) error {
		_, err := pc.WriteTo(resp, addr)
		return err
	})
}

func (s *Server) handleTCPConnection(conn net.Conn) {
	defer conn.Close()
	fmt.Printf("New TCP connection from %s\n", conn.RemoteAddr())

	for {
		// Read 2-byte length prefix
		lenBuf := make([]byte, 2)
		_, err := conn.Read(lenBuf)
		if err != nil {
			return
		}
		packetLen := uint16(lenBuf[0])<<8 | uint16(lenBuf[1])

		// Read actual packet
		data := make([]byte, packetLen)
		_, err = conn.Read(data)
		if err != nil {
			return
		}

		fmt.Printf("Received %d bytes via TCP from %s\n", len(data), conn.RemoteAddr())

		err = s.handlePacket(data, func(resp []byte) error {
			resLen := uint16(len(resp))
			fullResp := append([]byte{byte(resLen >> 8), byte(resLen & 0xFF)}, resp...)
			_, err := conn.Write(fullResp)
			return err
		})

		if err != nil {
			fmt.Printf("TCP processing error: %v\n", err)
			return
		}
	}
}

func (s *Server) handlePacket(data []byte, sendFn func([]byte) error) error {
	// 1. Parse Request
	reqBuffer := packet.NewBytePacketBuffer()
	copy(reqBuffer.Buf, data)

	request := packet.NewDnsPacket()
	if err := request.FromBuffer(reqBuffer); err != nil {
		fmt.Printf("Failed to parse packet: %s\n", err)
		return err
	}

	// 2. Check Cache
	if len(request.Questions) > 0 {
		q := request.Questions[0]
		cacheKey := fmt.Sprintf("%s:%d", q.Name, q.QType)
		if cachedData, found := s.Cache.Get(cacheKey); found {
			fmt.Printf("Cache hit for %s\n", cacheKey)
			if len(cachedData) >= 2 {
				cachedData[0] = byte(request.Header.ID >> 8)
				cachedData[1] = byte(request.Header.ID & 0xFF)
			}
			return sendFn(cachedData)
		}
	}

	// 3. Prepare Response
	response := packet.NewDnsPacket()
	response.Header.ID = request.Header.ID
	response.Header.Response = true
	response.Header.Opcode = request.Header.Opcode
	response.Header.RecursionDesired = request.Header.RecursionDesired
	response.Header.RecursionAvailable = false
	response.Header.AuthoritativeAnswer = true
	response.Header.ResCode = 0

	// 4. Resolve using Repository
	var minTTL uint32 = 300
	if len(request.Questions) > 0 {
		q := request.Questions[0]
		response.Questions = append(response.Questions, q)

		fmt.Printf("Query: %s %d\n", q.Name, q.QType)

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
			for i, rec := range records {
				pRec, err := repository.ConvertDomainToPacketRecord(rec)
				if err == nil {
					response.Answers = append(response.Answers, pRec)
					if i == 0 || pRec.TTL < minTTL {
						minTTL = pRec.TTL
					}
				}
			}
		} else if request.Header.RecursionDesired {
			// RECURSIVE LOOKUP
			recursiveResp, err := s.resolveRecursive(q.Name, q.QType)
			if err == nil {
				response.Answers = recursiveResp.Answers
				response.Authorities = recursiveResp.Authorities
				response.Resources = recursiveResp.Resources
				response.Header.ResCode = recursiveResp.Header.ResCode
			} else {
				fmt.Printf("Recursive error: %v\n", err)
				response.Header.ResCode = 2 // SERVFAIL
			}
		} else {
			response.Header.ResCode = 3 // NXDOMAIN
		}
	} else {
		response.Header.ResCode = 4 // FORMERR
	}

	// 5. Serialize Response
	resBuffer := packet.NewBytePacketBuffer()
	if err := response.Write(resBuffer); err != nil {
		fmt.Printf("Failed to serialize response: %s\n", err)
		return err
	}

	resData := resBuffer.Buf[:resBuffer.Position()]

	// 6. Cache successful response
	if len(request.Questions) > 0 && (response.Header.ResCode == 0 || response.Header.ResCode == 3) {
		q := request.Questions[0]
		cacheKey := fmt.Sprintf("%s:%d", q.Name, q.QType)
		cacheData := make([]byte, len(resData))
		copy(cacheData, resData)
		s.Cache.Set(cacheKey, cacheData, time.Duration(minTTL)*time.Second)
	}

	// 7. Send Back
	return sendFn(resData)
}
