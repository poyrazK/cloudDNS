package packet

import (
	"errors"
	"net"
)

type QueryType uint16

const (
	UNKNOWN QueryType = 0
	A       QueryType = 1
	NS      QueryType = 2
	CNAME   QueryType = 5
	MX      QueryType = 15
	TXT     QueryType = 16
	SOA     QueryType = 6
	AAAA    QueryType = 28
	OPT     QueryType = 41
)

type DnsHeader struct {
	ID             uint16
	RecursionDesired bool
	TruncatedMessage bool
	AuthoritativeAnswer bool
	Opcode          uint8
	Response        bool
	ResCode         uint8 // RCODE
	CheckingDisabled bool
	AuthedData       bool
	Z               bool
	RecursionAvailable bool

	Questions       uint16
	Answers         uint16
	AuthoritativeEntries uint16
	ResourceEntries uint16
}

func NewDnsHeader() *DnsHeader {
	return &DnsHeader{}
}

func (h *DnsHeader) Read(buffer *BytePacketBuffer) error {
	if buffer.Position()+12 > 512 {
		return errors.New("end of buffer")
	}
	var err error
	h.ID, err = buffer.Readu16()
	if err != nil {
		return err
	}

	flags, err := buffer.Readu16()
	if err != nil {
		return err
	}

	a := uint8(flags >> 8)
	b := uint8(flags & 0xFF)

	h.RecursionDesired = (a & (1 << 0)) > 0
	h.TruncatedMessage = (a & (1 << 1)) > 0
	h.AuthoritativeAnswer = (a & (1 << 2)) > 0
	h.Opcode = (a >> 3) & 0x0F
	h.Response = (a & (1 << 7)) > 0

	h.ResCode = b & 0x0F
	h.CheckingDisabled = (b & (1 << 4)) > 0
	h.AuthedData = (b & (1 << 5)) > 0
	h.Z = (b & (1 << 6)) > 0
	h.RecursionAvailable = (b & (1 << 7)) > 0

	h.Questions, err = buffer.Readu16()
	if err != nil { return err }
	h.Answers, err = buffer.Readu16()
	if err != nil { return err }
	h.AuthoritativeEntries, err = buffer.Readu16()
	if err != nil { return err }
	h.ResourceEntries, err = buffer.Readu16()
	if err != nil { return err }

	return nil
}

func (h *DnsHeader) Write(buffer *BytePacketBuffer) error {
	if err := buffer.Writeu16(h.ID); err != nil {
		return err
	}

	var flags uint16 = 0
	if h.Response { flags |= (1 << 15) }
	flags |= (uint16(h.Opcode) << 11)
	if h.AuthoritativeAnswer { flags |= (1 << 10) }
	if h.TruncatedMessage { flags |= (1 << 9) }
	if h.RecursionDesired { flags |= (1 << 8) }
	if h.RecursionAvailable { flags |= (1 << 7) }
	if h.Z { flags |= (1 << 6) }
	if h.AuthedData { flags |= (1 << 5) }
	if h.CheckingDisabled { flags |= (1 << 4) }
	flags |= uint16(h.ResCode)

	if err := buffer.Writeu16(flags); err != nil { return err }
	if err := buffer.Writeu16(h.Questions); err != nil { return err }
	if err := buffer.Writeu16(h.Answers); err != nil { return err }
	if err := buffer.Writeu16(h.AuthoritativeEntries); err != nil { return err }
	if err := buffer.Writeu16(h.ResourceEntries); err != nil { return err }

	return nil
}

type DnsQuestion struct {
	Name  string
	QType QueryType
}

func NewDnsQuestion(name string, qtype QueryType) *DnsQuestion {
	return &DnsQuestion{
		Name:  name,
		QType: qtype,
	}
}

func (q *DnsQuestion) Read(buffer *BytePacketBuffer) error {
	var err error
	q.Name, err = buffer.ReadName()
	if err != nil { return err }

	qtype, err := buffer.Readu16()
	if err != nil { return err }
	q.QType = QueryType(qtype)

	_, err = buffer.Readu16() // QCLASS (ignore for now)
	if err != nil { return err }

	return nil
}

func (q *DnsQuestion) Write(buffer *BytePacketBuffer) error {
	if err := buffer.WriteName(q.Name); err != nil { return err }
	if err := buffer.Writeu16(uint16(q.QType)); err != nil { return err }
	if err := buffer.Writeu16(1); err != nil { return err } // CLASS IN
	return nil
}

type DnsRecord struct {
	Name     string
	Type     QueryType
	Class    uint16
	TTL      uint32
	Data     []byte
	IP       net.IP   // Helper for A/AAAA
	Host     string   // Helper for CNAME/NS/MX
	Priority uint16   // Helper for MX
	Txt      string   // Helper for TXT
	MName    string   // SOA primary name server
	RName    string   // SOA mailbox for responsible person
	Serial   uint32   // SOA serial number
	Refresh  uint32   // SOA refresh interval
	Retry    uint32   // SOA retry interval
	Expire   uint32   // SOA expire limit
	Minimum  uint32   // SOA minimum TTL
	// EDNS fields
	UDPPayloadSize uint16
	ExtendedRcode  uint8
	EDNSVersion    uint8
	Z              uint16
}

func (r *DnsRecord) Read(buffer *BytePacketBuffer) error {
	var err error
	r.Name, err = buffer.ReadName()
	if err != nil { return err }

	typeVal, err := buffer.Readu16()
	if err != nil { return err }
	r.Type = QueryType(typeVal)

	r.Class, err = buffer.Readu16()
	if err != nil { return err }

	r.TTL, err = buffer.Readu32() // Actually u32
	if err != nil { return err } // Corrected method call

	dataLen, err := buffer.Readu16()
	if err != nil { return err }

	switch r.Type {
	case A:
		rawIP, err := buffer.ReadRange(buffer.Position(), 4)
		if err != nil { return err }
		r.IP = net.IP(rawIP)
		buffer.Step(4)
	case AAAA:
		rawIP, err := buffer.ReadRange(buffer.Position(), 16)
		if err != nil { return err }
		r.IP = net.IP(rawIP)
		buffer.Step(16)
	case NS, CNAME:
		r.Host, err = buffer.ReadName()
		if err != nil { return err }
	case MX:
		r.Priority, err = buffer.Readu16()
		if err != nil { return err }
		r.Host, err = buffer.ReadName()
		if err != nil { return err }
	case OPT:
		r.UDPPayloadSize = r.Class
		r.ExtendedRcode = uint8(r.TTL >> 24)
		r.EDNSVersion = uint8((r.TTL >> 16) & 0xFF)
		r.Z = uint16(r.TTL & 0xFFFF)
		buffer.Step(int(dataLen))
	default:
		buffer.Step(int(dataLen))
	}
	return nil
}

func (r *DnsRecord) Write(buffer *BytePacketBuffer) (int, error) {
	startPos := buffer.Position()
	if r.Type == OPT {
		// OPT record uses name "" (root)
		if err := buffer.Write(0); err != nil { return 0, err }
		if err := buffer.Writeu16(uint16(r.Type)); err != nil { return 0, err }
		if err := buffer.Writeu16(r.UDPPayloadSize); err != nil { return 0, err }
		
		ttl := uint32(r.ExtendedRcode) << 24
		ttl |= uint32(r.EDNSVersion) << 16
		ttl |= uint32(r.Z)
		if err := buffer.Writeu32(ttl); err != nil { return 0, err }
		if err := buffer.Writeu16(0); err != nil { return 0, err } // No options for now
		return buffer.Position() - startPos, nil
	}
	
	if err := buffer.WriteName(r.Name); err != nil { return 0, err }
	if err := buffer.Writeu16(uint16(r.Type)); err != nil { return 0, err }
	if err := buffer.Writeu16(r.Class); err != nil { return 0, err }
	if err := buffer.Writeu32(r.TTL); err != nil { return 0, err }

	// Write RDATA based on type
	switch r.Type {
	case A:
		if err := buffer.Writeu16(4); err != nil { return 0, err } // len
		ip4 := r.IP.To4()
		if ip4 == nil { return 0, errors.New("invalid IPv4") }
		for _, b := range ip4 {
			if err := buffer.Write(b); err != nil { return 0, err }
		}
	case AAAA:
		if err := buffer.Writeu16(16); err != nil { return 0, err }
		ip6 := r.IP.To16()
		if ip6 == nil { return 0, errors.New("invalid IPv6") }
		for _, b := range ip6 {
			if err := buffer.Write(b); err != nil { return 0, err }
		}
	case CNAME, NS:
		// We need to calculate length AFTER writing name... 
		lenPos := buffer.Position()
		if err := buffer.Writeu16(0); err != nil { return 0, err } // Placeholder
		
		if err := buffer.WriteName(r.Host); err != nil { return 0, err }
		
		currPos := buffer.Position()
		dataLen := currPos - (lenPos + 2)
		
		buffer.Seek(lenPos)
		buffer.Writeu16(uint16(dataLen))
		buffer.Seek(currPos)
	case MX:
		lenPos := buffer.Position()
		if err := buffer.Writeu16(0); err != nil { return 0, err } // Placeholder

		if err := buffer.Writeu16(r.Priority); err != nil { return 0, err }
		if err := buffer.WriteName(r.Host); err != nil { return 0, err }

		currPos := buffer.Position()
		dataLen := currPos - (lenPos + 2)
		buffer.Seek(lenPos)
		buffer.Writeu16(uint16(dataLen))
		buffer.Seek(currPos)
	case TXT:
		if len(r.Txt) > 255 { return 0, errors.New("TXT record too long") }
		if err := buffer.Writeu16(uint16(len(r.Txt) + 1)); err != nil { return 0, err } // +1 for len byte
		if err := buffer.Write(byte(len(r.Txt))); err != nil { return 0, err }
		for i := 0; i < len(r.Txt); i++ {
			if err := buffer.Write(r.Txt[i]); err != nil { return 0, err }
		}
	case SOA:
		lenPos := buffer.Position()
		if err := buffer.Writeu16(0); err != nil { return 0, err } // Placeholder

		if err := buffer.WriteName(r.MName); err != nil { return 0, err }
		if err := buffer.WriteName(r.RName); err != nil { return 0, err }
		if err := buffer.Writeu32(r.Serial); err != nil { return 0, err }
		if err := buffer.Writeu32(r.Refresh); err != nil { return 0, err }
		if err := buffer.Writeu32(r.Retry); err != nil { return 0, err }
		if err := buffer.Writeu32(r.Expire); err != nil { return 0, err }
		if err := buffer.Writeu32(r.Minimum); err != nil { return 0, err }

		currPos := buffer.Position()
		dataLen := currPos - (lenPos + 2)
		buffer.Seek(lenPos)
		buffer.Writeu16(uint16(dataLen))
		buffer.Seek(currPos)
	default:
		return 0, errors.New("unsupported record type for write")
	}

	return buffer.Position() - startPos, nil
}

type DnsPacket struct {
	Header      DnsHeader
	Questions   []DnsQuestion
	Answers     []DnsRecord
	Authorities []DnsRecord
	Resources   []DnsRecord
}

func NewDnsPacket() *DnsPacket {
	return &DnsPacket{
		Header: DnsHeader{},
		Questions: []DnsQuestion{},
		Answers: []DnsRecord{},
		Authorities: []DnsRecord{},
		Resources: []DnsRecord{},
	}
}

func (p *DnsPacket) FromBuffer(buffer *BytePacketBuffer) error {
	if err := p.Header.Read(buffer); err != nil {
		return err
	}

	for i := 0; i < int(p.Header.Questions); i++ {
		var q DnsQuestion
		if err := q.Read(buffer); err != nil {
			return err
		}
		p.Questions = append(p.Questions, q)
	}

	for i := 0; i < int(p.Header.Answers); i++ {
		var r DnsRecord
		if err := r.Read(buffer); err != nil { return err }
		p.Answers = append(p.Answers, r)
	}

	for i := 0; i < int(p.Header.AuthoritativeEntries); i++ {
		var r DnsRecord
		if err := r.Read(buffer); err != nil { return err }
		p.Authorities = append(p.Authorities, r)
	}

	for i := 0; i < int(p.Header.ResourceEntries); i++ {
		var r DnsRecord
		if err := r.Read(buffer); err != nil { return err }
		p.Resources = append(p.Resources, r)
	}

	return nil
}

func (p *DnsPacket) Write(buffer *BytePacketBuffer) error {
	p.Header.Questions = uint16(len(p.Questions))
	p.Header.Answers = uint16(len(p.Answers))
	p.Header.AuthoritativeEntries = uint16(len(p.Authorities))
	p.Header.ResourceEntries = uint16(len(p.Resources))

	if err := p.Header.Write(buffer); err != nil { return err }

	for _, q := range p.Questions {
		if err := q.Write(buffer); err != nil { return err }
	}

	for _, a := range p.Answers {
		if _, err := a.Write(buffer); err != nil { return err }
	}
	
	for _, a := range p.Authorities {
		if _, err := a.Write(buffer); err != nil { return err }
	}
	
	for _, a := range p.Resources {
		if _, err := a.Write(buffer); err != nil { return err }
	}

	return nil
}
