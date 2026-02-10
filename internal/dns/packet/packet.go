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
	AAAA    QueryType = 28
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
	IP       net.IP // Helper for A/AAAA
	Host     string // Helper for CNAME/MX
	Priority uint16 // Helper for MX
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
	case CNAME, NS, MX:
		// Complex handling needed for reading compressed names inside RDATA
		// For now, just skip
		buffer.Step(int(dataLen))
	default:
		buffer.Step(int(dataLen))
	}
	return nil
}

func (r *DnsRecord) Write(buffer *BytePacketBuffer) (int, error) {
	startPos := buffer.Position()
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
		// For simplicity in this scratch version, we'll reserve 2 bytes for length, 
		// write name, then jump back
		lenPos := buffer.Position()
		if err := buffer.Writeu16(0); err != nil { return 0, err } // Placeholder
		
		if err := buffer.WriteName(r.Host); err != nil { return 0, err }
		
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
	if err := p.Header.Read(buffer); err != nil { return err }

	for i := 0; i < int(p.Header.Questions); i++ {
		var q DnsQuestion
		if err := q.Read(buffer); err != nil { return err }
		p.Questions = append(p.Questions, q)
	}

	for i := 0; i < int(p.Header.Answers); i++ {
		var r DnsRecord
		if err := r.Read(buffer); err != nil { return err }
		p.Answers = append(p.Answers, r)
	}

	// Authorities and Resources skipped for now for brevity of reading request
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
