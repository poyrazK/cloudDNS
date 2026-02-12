package packet

import (
	"net"
)

type QueryType uint16

const (
	UNKNOWN    QueryType = 0
	A          QueryType = 1
	NS         QueryType = 2
	MD         QueryType = 3
	MF         QueryType = 4
	CNAME      QueryType = 5
	SOA        QueryType = 6
	MB         QueryType = 7
	MG         QueryType = 8
	MR         QueryType = 9
	NULL       QueryType = 10
	WKS        QueryType = 11
	PTR        QueryType = 12
	HINFO      QueryType = 13
	MINFO      QueryType = 14
	MX         QueryType = 15
	TXT        QueryType = 16
	AAAA       QueryType = 28
	SRV        QueryType = 33
	DS         QueryType = 43
	RRSIG      QueryType = 46
	NSEC       QueryType = 47
	DNSKEY     QueryType = 48
	NSEC3      QueryType = 50
	NSEC3PARAM QueryType = 51
	AXFR       QueryType = 252
	ANY        QueryType = 255
	OPT        QueryType = 41
	TSIG       QueryType = 250
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
	if err != nil { return err }

	flags, err := buffer.Readu16()
	if err != nil { return err }

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
	if err := buffer.Writeu16(h.ID); err != nil { return err }

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

	_, err = buffer.Readu16() // QCLASS
	if err != nil { return err }

	return nil
}

func (q *DnsQuestion) Write(buffer *BytePacketBuffer) error {
	if err := buffer.WriteName(q.Name); err != nil { return err }
	if err := buffer.Writeu16(uint16(q.QType)); err != nil { return err }
	if err := buffer.Writeu16(1); err != nil { return err } // CLASS IN
	return nil
}

type EdnsOption struct {
	Code uint16
	Data []byte
}

type DnsRecord struct {
	Name     string
	Type     QueryType
	Class    uint16
	TTL      uint32
	Data     []byte
	IP       net.IP   // A/AAAA
	Host     string   // NS/CNAME/PTR/MD/MF/MB/MG/MR
	Priority uint16   // MX
	Txt      string   // TXT
	MName    string   // SOA
	RName    string   // SOA
	Serial   uint32   // SOA
	Refresh  uint32   // SOA
	Retry    uint32   // SOA
	Expire   uint32   // SOA
	Minimum  uint32   // SOA
	CPU      string   // HINFO
	OS       string   // HINFO
	Protocol uint8    // WKS
	BitMap   []byte   // WKS
	RMailBX  string   // MINFO
	EMailBX  string   // MINFO
	// NSEC
	NextName   string
	TypeBitMap []byte
	// DNSKEY
	Flags     uint16
	Algorithm uint8
	PublicKey []byte
	// RRSIG
	TypeCovered uint16
	Labels      uint8
	OrigTTL     uint32
	Expiration  uint32
	Inception   uint32
	KeyTag      uint16
	SignerName  string
	Signature   []byte
	// NSEC3
	HashAlg    uint8
	Iterations uint16
	Salt       []byte
	NextHash   []byte
	// EDNS
	UDPPayloadSize uint16
	ExtendedRcode  uint8
	EDNSVersion    uint8
	Z              uint16
	Options        []EdnsOption
	// TSIG
	AlgorithmName string
	TimeSigned    uint64
	Fudge         uint16
	MAC           []byte
	OriginalID    uint16
	Error         uint16
	Other         []byte
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

	r.TTL, err = buffer.Readu32() 
	if err != nil { return err } 

	dataLen, err := buffer.Readu16()
	if err != nil { return err }
	startPos := buffer.Position()

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
	case NS, CNAME, PTR, MD, MF, MB, MG, MR:
		r.Host, err = buffer.ReadName()
		if err != nil { return err }
	case MX:
		r.Priority, err = buffer.Readu16()
		if err != nil { return err }
		r.Host, err = buffer.ReadName()
		if err != nil { return err }
	case TXT:
		txtLen, _ := buffer.Read()
		txtData, err := buffer.ReadRange(buffer.Position(), int(txtLen))
		if err != nil { return err }
		r.Txt = string(txtData)
		buffer.Step(int(txtLen))
	case SOA:
		r.MName, _ = buffer.ReadName()
		r.RName, _ = buffer.ReadName()
		r.Serial, _ = buffer.Readu32()
		r.Refresh, _ = buffer.Readu32()
		r.Retry, _ = buffer.Readu32()
		r.Expire, _ = buffer.Readu32()
		r.Minimum, _ = buffer.Readu32()
	case HINFO:
		cpuLen, _ := buffer.Read()
		cpu, _ := buffer.ReadRange(buffer.Position(), int(cpuLen))
		r.CPU = string(cpu)
		buffer.Step(int(cpuLen))
		osLen, _ := buffer.Read()
		osData, _ := buffer.ReadRange(buffer.Position(), int(osLen))
		r.OS = string(osData)
		buffer.Step(int(osLen))
	case MINFO:
		r.RMailBX, _ = buffer.ReadName()
		r.EMailBX, _ = buffer.ReadName()
	case NSEC:
		r.NextName, _ = buffer.ReadName()
		remaining := int(dataLen) - (buffer.Position() - startPos)
		r.TypeBitMap, _ = buffer.ReadRange(buffer.Position(), remaining)
		buffer.Step(remaining)
	case DNSKEY:
		r.Flags, _ = buffer.Readu16()
		protocol, _ := buffer.Read() // Must be 3
		_ = protocol
		r.Algorithm, _ = buffer.Read()
		remaining := int(dataLen) - (buffer.Position() - startPos)
		r.PublicKey, _ = buffer.ReadRange(buffer.Position(), remaining)
		buffer.Step(remaining)
	case RRSIG:
		r.TypeCovered, _ = buffer.Readu16()
		r.Algorithm, _ = buffer.Read()
		r.Labels, _ = buffer.Read()
		r.OrigTTL, _ = buffer.Readu32()
		r.Expiration, _ = buffer.Readu32()
		r.Inception, _ = buffer.Readu32()
		r.KeyTag, _ = buffer.Readu16()
		r.SignerName, _ = buffer.ReadName()
		remaining := int(dataLen) - (buffer.Position() - startPos)
		r.Signature, _ = buffer.ReadRange(buffer.Position(), remaining)
		buffer.Step(remaining)
	case NSEC3:
		r.HashAlg, _ = buffer.Read()
		r.Flags = 0 // simplified
		f, _ := buffer.Read()
		_ = f
		r.Iterations, _ = buffer.Readu16()
		saltLen, _ := buffer.Read()
		r.Salt, _ = buffer.ReadRange(buffer.Position(), int(saltLen))
		buffer.Step(int(saltLen))
		hashLen, _ := buffer.Read()
		r.NextHash, _ = buffer.ReadRange(buffer.Position(), int(hashLen))
		buffer.Step(int(hashLen))
		remaining := int(dataLen) - (buffer.Position() - startPos)
		r.TypeBitMap, _ = buffer.ReadRange(buffer.Position(), remaining)
		buffer.Step(remaining)
	case NSEC3PARAM:
		r.HashAlg, _ = buffer.Read()
		f, _ := buffer.Read()
		_ = f
		r.Iterations, _ = buffer.Readu16()
		saltLen, _ := buffer.Read()
		r.Salt, _ = buffer.ReadRange(buffer.Position(), int(saltLen))
		buffer.Step(int(saltLen))
	case OPT:
		r.UDPPayloadSize = r.Class
		r.ExtendedRcode = uint8(r.TTL >> 24)
		r.EDNSVersion = uint8((r.TTL >> 16) & 0xFF)
		r.Z = uint16(r.TTL & 0xFFFF)
		remaining := int(dataLen)
		for remaining >= 4 {
			optCode, _ := buffer.Readu16()
			optLen, _ := buffer.Readu16()
			if int(optLen) > remaining-4 { break }
			optData, _ := buffer.ReadRange(buffer.Position(), int(optLen))
			buffer.Step(int(optLen))
			r.Options = append(r.Options, EdnsOption{Code: optCode, Data: optData})
			remaining -= (4 + int(optLen))
		}
	default:
		buffer.Step(int(dataLen))
	}
	return nil
}

func (r *DnsRecord) Write(buffer *BytePacketBuffer) (int, error) {
	startPos := buffer.Position()
	if r.Type == OPT {
		buffer.Write(0)
		buffer.Writeu16(uint16(r.Type))
		buffer.Writeu16(r.UDPPayloadSize)
		ttl := uint32(r.ExtendedRcode) << 24 | uint32(r.EDNSVersion) << 16 | uint32(r.Z)
		buffer.Writeu32(ttl)
		lenPos := buffer.Position()
		buffer.Writeu16(0)
		for _, opt := range r.Options {
			buffer.Writeu16(opt.Code)
			buffer.Writeu16(uint16(len(opt.Data)))
			for _, b := range opt.Data { buffer.Write(b) }
		}
		currPos := buffer.Position()
		buffer.Seek(lenPos)
		buffer.Writeu16(uint16(currPos - (lenPos + 2)))
		buffer.Seek(currPos)
		return currPos - startPos, nil
	}

	if r.Type == TSIG {
		buffer.WriteName(r.Name)
		buffer.Writeu16(uint16(r.Type))
		buffer.Writeu16(r.Class)
		buffer.Writeu32(r.TTL)
		lenPos := buffer.Position()
		buffer.Writeu16(0)
		buffer.WriteName(r.AlgorithmName)
		buffer.Writeu16(uint16(r.TimeSigned >> 32))
		buffer.Writeu32(uint32(r.TimeSigned & 0xFFFFFFFF))
		buffer.Writeu16(r.Fudge)
		buffer.Writeu16(uint16(len(r.MAC)))
		for _, b := range r.MAC { buffer.Write(b) }
		buffer.Writeu16(r.OriginalID)
		buffer.Writeu16(r.Error)
		buffer.Writeu16(uint16(len(r.Other)))
		for _, b := range r.Other { buffer.Write(b) }
		currPos := buffer.Position()
		buffer.Seek(lenPos)
		buffer.Writeu16(uint16(currPos - (lenPos + 2)))
		buffer.Seek(currPos)
		return currPos - startPos, nil
	}
	
	buffer.WriteName(r.Name)
	buffer.Writeu16(uint16(r.Type))
	buffer.Writeu16(r.Class)
	buffer.Writeu32(r.TTL)

	switch r.Type {
	case A:
		buffer.Writeu16(4)
		ip4 := r.IP.To4()
		for _, b := range ip4 { buffer.Write(b) }
	case AAAA:
		buffer.Writeu16(16)
		for _, b := range r.IP.To16() { buffer.Write(b) }
	case NS, CNAME, PTR, MD, MF, MB, MG, MR:
		lenPos := buffer.Position()
		buffer.Writeu16(0)
		buffer.WriteName(r.Host)
		currPos := buffer.Position()
		buffer.Seek(lenPos)
		buffer.Writeu16(uint16(currPos - (lenPos + 2)))
		buffer.Seek(currPos)
	case MX:
		lenPos := buffer.Position()
		buffer.Writeu16(0)
		buffer.Writeu16(r.Priority)
		buffer.WriteName(r.Host)
		currPos := buffer.Position()
		buffer.Seek(lenPos)
		buffer.Writeu16(uint16(currPos - (lenPos + 2)))
		buffer.Seek(currPos)
	case TXT:
		buffer.Writeu16(uint16(len(r.Txt) + 1))
		buffer.Write(byte(len(r.Txt)))
		for i := 0; i < len(r.Txt); i++ { buffer.Write(r.Txt[i]) }
	case SOA:
		lenPos := buffer.Position()
		buffer.Writeu16(0)
		buffer.WriteName(r.MName)
		buffer.WriteName(r.RName)
		buffer.Writeu32(r.Serial)
		buffer.Writeu32(r.Refresh)
		buffer.Writeu32(r.Retry)
		buffer.Writeu32(r.Expire)
		buffer.Writeu32(r.Minimum)
		currPos := buffer.Position()
		buffer.Seek(lenPos)
		buffer.Writeu16(uint16(currPos - (lenPos + 2)))
		buffer.Seek(currPos)
	case HINFO:
		buffer.Writeu16(uint16(len(r.CPU) + len(r.OS) + 2))
		buffer.Write(byte(len(r.CPU)))
		for i := 0; i < len(r.CPU); i++ { buffer.Write(r.CPU[i]) }
		buffer.Write(byte(len(r.OS)))
		for i := 0; i < len(r.OS); i++ { buffer.Write(r.OS[i]) }
	case MINFO:
		lenPos := buffer.Position()
		buffer.Writeu16(0)
		buffer.WriteName(r.RMailBX)
		buffer.WriteName(r.EMailBX)
		currPos := buffer.Position()
		buffer.Seek(lenPos)
		buffer.Writeu16(uint16(currPos - (lenPos + 2)))
		buffer.Seek(currPos)
	case NSEC:
		lenPos := buffer.Position()
		buffer.Writeu16(0)
		buffer.WriteName(r.NextName)
		for _, b := range r.TypeBitMap { buffer.Write(b) }
		currPos := buffer.Position()
		buffer.Seek(lenPos)
		buffer.Writeu16(uint16(currPos - (lenPos + 2)))
		buffer.Seek(currPos)
	case DNSKEY:
		buffer.Writeu16(uint16(4 + len(r.PublicKey)))
		buffer.Writeu16(r.Flags)
		buffer.Write(3) // Protocol
		buffer.Write(r.Algorithm)
		for _, b := range r.PublicKey { buffer.Write(b) }
	case RRSIG:
		lenPos := buffer.Position()
		buffer.Writeu16(0)
		buffer.Writeu16(r.TypeCovered)
		buffer.Write(r.Algorithm)
		buffer.Write(r.Labels)
		buffer.Writeu32(r.OrigTTL)
		buffer.Writeu32(r.Expiration)
		buffer.Writeu32(r.Inception)
		buffer.Writeu16(r.KeyTag)
		buffer.WriteName(r.SignerName)
		for _, b := range r.Signature { buffer.Write(b) }
		currPos := buffer.Position()
		buffer.Seek(lenPos)
		buffer.Writeu16(uint16(currPos - (lenPos + 2)))
		buffer.Seek(currPos)
	case NSEC3:
		lenPos := buffer.Position()
		buffer.Writeu16(0)
		buffer.Write(r.HashAlg)
		buffer.Write(uint8(r.Flags))
		buffer.Writeu16(r.Iterations)
		buffer.Write(uint8(len(r.Salt)))
		for _, b := range r.Salt { buffer.Write(b) }
		buffer.Write(uint8(len(r.NextHash)))
		for _, b := range r.NextHash { buffer.Write(b) }
		for _, b := range r.TypeBitMap { buffer.Write(b) }
		currPos := buffer.Position()
		buffer.Seek(lenPos)
		buffer.Writeu16(uint16(currPos - (lenPos + 2)))
		buffer.Seek(currPos)
	case NSEC3PARAM:
		lenPos := buffer.Position()
		buffer.Writeu16(0)
		buffer.Write(r.HashAlg)
		buffer.Write(uint8(r.Flags))
		buffer.Writeu16(r.Iterations)
		buffer.Write(uint8(len(r.Salt)))
		for _, b := range r.Salt { buffer.Write(b) }
		currPos := buffer.Position()
		buffer.Seek(lenPos)
		buffer.Writeu16(uint16(currPos - (lenPos + 2)))
		buffer.Seek(currPos)
	default:
		buffer.Writeu16(uint16(len(r.Data)))
		for _, b := range r.Data { buffer.Write(b) }
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
