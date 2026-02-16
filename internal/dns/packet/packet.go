package packet

import (
	"fmt"
	"net"
	"github.com/poyrazK/cloudDNS/internal/core/domain"
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
	IXFR       QueryType = 251
	ANY        QueryType = 255
	OPT        QueryType = 41
	TSIG       QueryType = 250
)

// RFC 8914: Extended DNS Error Codes
const (
	EDE_OTHER               uint16 = 0
	EDE_UNSUPPORTED_DNSKEY  uint16 = 1
	EDE_UNSUPPORTED_DS      uint16 = 2
	EDE_STALE_ANSWER        uint16 = 3
	EDE_FORGED_ANSWER       uint16 = 4
	EDE_DNSSEC_INDETERMINATE uint16 = 5
	EDE_DNSSEC_BOGUS        uint16 = 6
	EDE_SIGNATURE_EXPIRED   uint16 = 7
	EDE_SIGNATURE_NOT_YET   uint16 = 8
	EDE_MISSING_DNSKEY      uint16 = 9
	EDE_MISSING_DS          uint16 = 10
	EDE_UNSUPPORTED_ALG     uint16 = 11
	EDE_PROHIBITED          uint16 = 18
	EDE_BLOCKED             uint16 = 15
	EDE_CENSORED            uint16 = 16
	EDE_FILTERED            uint16 = 17
)

func RecordTypeToQueryType(t domain.RecordType) QueryType {
	switch t {
	case domain.TypeA: return A
	case domain.TypeNS: return NS
	case domain.TypeCNAME: return CNAME
	case domain.TypeSOA: return SOA
	case domain.TypeMX: return MX
	case domain.TypeTXT: return TXT
	case domain.TypeAAAA: return AAAA
	case domain.TypePTR: return PTR
	default: return UNKNOWN
	}
}

func (t QueryType) String() string {
	switch t {
	case A: return "A"
	case NS: return "NS"
	case CNAME: return "CNAME"
	case SOA: return "SOA"
	case MX: return "MX"
	case TXT: return "TXT"
	case AAAA: return "AAAA"
	case SRV: return "SRV"
	case DS: return "DS"
	case RRSIG: return "RRSIG"
	case NSEC: return "NSEC"
	case DNSKEY: return "DNSKEY"
	case NSEC3: return "NSEC3"
	case NSEC3PARAM: return "NSEC3PARAM"
	case AXFR: return "AXFR"
	case IXFR: return "IXFR"
	case ANY: return "ANY"
	case OPT: return "OPT"
	case TSIG: return "TSIG"
	case PTR: return "PTR"
	default: return fmt.Sprintf("TYPE%d", t)
	}
}

const (
	OPCODE_QUERY  uint8 = 0
	OPCODE_IQUERY uint8 = 1
	OPCODE_STATUS uint8 = 2
	OPCODE_NOTIFY uint8 = 4
	OPCODE_UPDATE uint8 = 5
)

const (
	RCODE_NOERROR  uint8 = 0
	RCODE_FORMERR  uint8 = 1
	RCODE_SERVFAIL uint8 = 2
	RCODE_NXDOMAIN uint8 = 3
	RCODE_NOTIMP   uint8 = 4
	RCODE_REFUSED  uint8 = 5
	RCODE_YXDOMAIN uint8 = 6
	RCODE_YXRRSET  uint8 = 7
	RCODE_NXRRSET  uint8 = 8
	RCODE_NOTAUTH  uint8 = 9
	RCODE_NOTZONE  uint8 = 10
)

type DNSHeader struct {
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

	// RFC 2136 (Dynamic Update) field renames:
	// Questions -> ZOCOUNT (Number of zones)
	// Answers -> PRCOUNT (Number of prerequisites)
	// AuthoritativeEntries -> UPCOUNT (Number of updates)
	// ResourceEntries -> ADCOUNT (Number of additional records)
	Questions       uint16
	Answers         uint16
	AuthoritativeEntries uint16
	ResourceEntries uint16
}

func NewDNSHeader() *DNSHeader {
	return &DNSHeader{}
}

func (h *DNSHeader) Read(buffer *BytePacketBuffer) error {
	var err error
	h.ID, err = buffer.Readu16()
	if err != nil { return err }

	flags, err := buffer.Readu16()
	if err != nil { return err }

	a := uint8(flags >> 8) // #nosec G115
	b := uint8(flags & 0xFF) // #nosec G115

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

func (h *DNSHeader) Write(buffer *BytePacketBuffer) error {
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

type DNSQuestion struct {
	Name  string
	QType QueryType
}

func NewDNSQuestion(name string, qtype QueryType) *DNSQuestion {
	return &DNSQuestion{
		Name:  name,
		QType: qtype,
	}
}

func (q *DNSQuestion) Read(buffer *BytePacketBuffer) error {
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

func (q *DNSQuestion) Write(buffer *BytePacketBuffer) error {
	if err := buffer.WriteName(q.Name); err != nil { return err }
	if err := buffer.Writeu16(uint16(q.QType)); err != nil { return err }
	if err := buffer.Writeu16(1); err != nil { return err } // CLASS IN
	return nil
}

type EdnsOption struct {
	Code uint16
	Data []byte
}

type DNSRecord struct {
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
	// DS
	DigestType uint8
	Digest     []byte
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

func (r *DNSRecord) AddEDE(code uint16, text string) {
	data := []byte{byte(code >> 8), byte(code & 0xFF)}
	if text != "" {
		data = append(data, []byte(text)...)
	}
	r.Options = append(r.Options, EdnsOption{Code: 15, Data: data})
}

func (r *DNSRecord) Read(buffer *BytePacketBuffer) error {
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

	// fmt.Printf("DEBUG: Reading %v dataLen=%d\n", r.Type, dataLen)

	switch r.Type {
	case A:
		rawIP, err := buffer.ReadRange(buffer.Position(), 4)
		if err != nil { return err }
		r.IP = net.IP(rawIP)
		if err := buffer.Step(4); err != nil { return err }
	case AAAA:
		rawIP, err := buffer.ReadRange(buffer.Position(), 16)
		if err != nil { return err }
		r.IP = net.IP(rawIP)
		if err := buffer.Step(16); err != nil { return err }
	case NS, CNAME, PTR, MD, MF, MB, MG, MR:
		r.Host, err = buffer.ReadName()
		if err != nil { return err }
	case MX:
		r.Priority, err = buffer.Readu16()
		if err != nil { return err }
		r.Host, err = buffer.ReadName()
		if err != nil { return err }
	case TXT:
		txtLen, err := buffer.Read()
		if err != nil { return err }
		txtData, err := buffer.ReadRange(buffer.Position(), int(txtLen))
		if err != nil { return err }
		r.Txt = string(txtData)
		if err := buffer.Step(int(txtLen)); err != nil { return err }
	case SOA:
		var err error
		if r.MName, err = buffer.ReadName(); err != nil { return err }
		if r.RName, err = buffer.ReadName(); err != nil { return err }
		if r.Serial, err = buffer.Readu32(); err != nil { return err }
		if r.Refresh, err = buffer.Readu32(); err != nil { return err }
		if r.Retry, err = buffer.Readu32(); err != nil { return err }
		if r.Expire, err = buffer.Readu32(); err != nil { return err }
		if r.Minimum, err = buffer.Readu32(); err != nil { return err }
	case HINFO:
		cpuLen, err := buffer.Read()
		if err != nil { return err }
		cpu, err := buffer.ReadRange(buffer.Position(), int(cpuLen))
		if err != nil { return err }
		r.CPU = string(cpu)
		if err := buffer.Step(int(cpuLen)); err != nil { return err }
		osLen, err := buffer.Read()
		if err != nil { return err }
		osData, err := buffer.ReadRange(buffer.Position(), int(osLen))
		if err != nil { return err }
		r.OS = string(osData)
		if err := buffer.Step(int(osLen)); err != nil { return err }
	case MINFO:
		var err error
		if r.RMailBX, err = buffer.ReadName(); err != nil { return err }
		if r.EMailBX, err = buffer.ReadName(); err != nil { return err }
	case NSEC:
		var err error
		if r.NextName, err = buffer.ReadName(); err != nil { return err }
		remaining := int(dataLen) - (buffer.Position() - startPos)
		if r.TypeBitMap, err = buffer.ReadRange(buffer.Position(), remaining); err != nil { return err }
		if err := buffer.Step(remaining); err != nil { return err }
	case DNSKEY:
		var err error
		if r.Flags, err = buffer.Readu16(); err != nil { return err }
		protocol, err := buffer.Read() // Must be 3
		if err != nil { return err }
		_ = protocol
		if r.Algorithm, err = buffer.Read(); err != nil { return err }
		remaining := int(dataLen) - (buffer.Position() - startPos)
		if r.PublicKey, err = buffer.ReadRange(buffer.Position(), remaining); err != nil { return err }
		if err := buffer.Step(remaining); err != nil { return err }
	case RRSIG:
		var err error
		if r.TypeCovered, err = buffer.Readu16(); err != nil { return err }
		if r.Algorithm, err = buffer.Read(); err != nil { return err }
		if r.Labels, err = buffer.Read(); err != nil { return err }
		if r.OrigTTL, err = buffer.Readu32(); err != nil { return err }
		if r.Expiration, err = buffer.Readu32(); err != nil { return err }
		if r.Inception, err = buffer.Readu32(); err != nil { return err }
		if r.KeyTag, err = buffer.Readu16(); err != nil { return err }
		if r.SignerName, err = buffer.ReadName(); err != nil { return err }
		remaining := int(dataLen) - (buffer.Position() - startPos)
		if r.Signature, err = buffer.ReadRange(buffer.Position(), remaining); err != nil { return err }
		if err := buffer.Step(remaining); err != nil { return err }
	case NSEC3:
		var err error
		if r.HashAlg, err = buffer.Read(); err != nil { return err }
		r.Flags = 0 // simplified
		f, err := buffer.Read()
		if err != nil { return err }
		_ = f
		if r.Iterations, err = buffer.Readu16(); err != nil { return err }
		saltLen, err := buffer.Read()
		if err != nil { return err }
		if r.Salt, err = buffer.ReadRange(buffer.Position(), int(saltLen)); err != nil { return err }
		if err := buffer.Step(int(saltLen)); err != nil { return err }
		hashLen, err := buffer.Read()
		if err != nil { return err }
		if r.NextHash, err = buffer.ReadRange(buffer.Position(), int(hashLen)); err != nil { return err }
		if err := buffer.Step(int(hashLen)); err != nil { return err }
		remaining := int(dataLen) - (buffer.Position() - startPos)
		if r.TypeBitMap, err = buffer.ReadRange(buffer.Position(), remaining); err != nil { return err }
		if err := buffer.Step(remaining); err != nil { return err }
	case NSEC3PARAM:
		var err error
		if r.HashAlg, err = buffer.Read(); err != nil { return err }
		f, err := buffer.Read()
		if err != nil { return err }
		_ = f
		if r.Iterations, err = buffer.Readu16(); err != nil { return err }
		saltLen, err := buffer.Read()
		if err != nil { return err }
		if r.Salt, err = buffer.ReadRange(buffer.Position(), int(saltLen)); err != nil { return err }
		if err := buffer.Step(int(saltLen)); err != nil { return err }
	case DS:
		var err error
		if r.KeyTag, err = buffer.Readu16(); err != nil { return err }
		if r.Algorithm, err = buffer.Read(); err != nil { return err }
		if r.DigestType, err = buffer.Read(); err != nil { return err }
		remaining := int(dataLen) - (buffer.Position() - startPos)
		if r.Digest, err = buffer.ReadRange(buffer.Position(), remaining); err != nil { return err }
		if err := buffer.Step(remaining); err != nil { return err }
	case TSIG:
		var err error
		if r.AlgorithmName, err = buffer.ReadName(); err != nil { return err }
		timeHigh, err := buffer.Readu16()
		if err != nil { return err }
		timeLow, err := buffer.Readu32()
		if err != nil { return err }
		r.TimeSigned = uint64(timeHigh)<<32 | uint64(timeLow)
		if r.Fudge, err = buffer.Readu16(); err != nil { return err }
		macLen, err := buffer.Readu16()
		if err != nil { return err }
		if r.MAC, err = buffer.ReadRange(buffer.Position(), int(macLen)); err != nil { return err }
		if err := buffer.Step(int(macLen)); err != nil { return err }
		if r.OriginalID, err = buffer.Readu16(); err != nil { return err }
		if r.Error, err = buffer.Readu16(); err != nil { return err }
		otherLen, err := buffer.Readu16()
		if err != nil { return err }
		if r.Other, err = buffer.ReadRange(buffer.Position(), int(otherLen)); err != nil { return err }
		if err := buffer.Step(int(otherLen)); err != nil { return err }
	case OPT:
		r.UDPPayloadSize = r.Class
		r.ExtendedRcode = uint8(r.TTL >> 24) // #nosec G115
		r.EDNSVersion = uint8((r.TTL >> 16) & 0xFF) // #nosec G115
		r.Z = uint16(r.TTL & 0xFFFF) // #nosec G115
		remaining := int(dataLen)
		for remaining >= 4 {
			optCode, err := buffer.Readu16()
			if err != nil { return err }
			optLen, err := buffer.Readu16()
			if err != nil { return err }
			if int(optLen) > remaining-4 { break }
			optData, err := buffer.ReadRange(buffer.Position(), int(optLen))
			if err != nil { return err }
			if err := buffer.Step(int(optLen)); err != nil { return err }
			r.Options = append(r.Options, EdnsOption{Code: optCode, Data: optData})
			remaining -= (4 + int(optLen))
		}
	default:
		if err := buffer.Step(int(dataLen)); err != nil { return err }
	}
	return nil
}

func (r *DNSRecord) Write(buffer *BytePacketBuffer) (int, error) {
	startPos := buffer.Position()
	if r.Type == OPT {
		if err := buffer.Write(0); err != nil { return 0, err }
		if err := buffer.Writeu16(uint16(r.Type)); err != nil { return 0, err }
		if err := buffer.Writeu16(r.UDPPayloadSize); err != nil { return 0, err }
		ttl := uint32(r.ExtendedRcode) << 24 | uint32(r.EDNSVersion) << 16 | uint32(r.Z)
		if err := buffer.Writeu32(ttl); err != nil { return 0, err }
		lenPos := buffer.Position()
		if err := buffer.Writeu16(0); err != nil { return 0, err }
		for _, opt := range r.Options {
			if err := buffer.Writeu16(opt.Code); err != nil { return 0, err }
			if err := buffer.Writeu16(uint16(len(opt.Data))); err != nil { return 0, err } // #nosec G115
			for _, b := range opt.Data { 
				if err := buffer.Write(b); err != nil { return 0, err }
			}
		}
		currPos := buffer.Position()
		if err := buffer.Seek(lenPos); err != nil { return 0, err }
		if err := buffer.Writeu16(uint16(currPos - (lenPos + 2))); err != nil { return 0, err } // #nosec G115
		if err := buffer.Seek(currPos); err != nil { return 0, err }
		return currPos - startPos, nil
	}

	if r.Type == TSIG {
		if err := buffer.WriteName(r.Name); err != nil { return 0, err }
		if err := buffer.Writeu16(uint16(r.Type)); err != nil { return 0, err }
		if err := buffer.Writeu16(r.Class); err != nil { return 0, err }
		if err := buffer.Writeu32(r.TTL); err != nil { return 0, err }
		lenPos := buffer.Position()
		if err := buffer.Writeu16(0); err != nil { return 0, err }
		if err := buffer.WriteName(r.AlgorithmName); err != nil { return 0, err }
		if err := buffer.Writeu16(uint16(r.TimeSigned >> 32)); err != nil { return 0, err } // #nosec G115
		if err := buffer.Writeu32(uint32(r.TimeSigned & 0xFFFFFFFF)); err != nil { return 0, err } // #nosec G115
		if err := buffer.Writeu16(r.Fudge); err != nil { return 0, err }
		if err := buffer.Writeu16(uint16(len(r.MAC))); err != nil { return 0, err } // #nosec G115
		for _, b := range r.MAC { 
			if err := buffer.Write(b); err != nil { return 0, err }
		}
		if err := buffer.Writeu16(r.OriginalID); err != nil { return 0, err }
		if err := buffer.Writeu16(r.Error); err != nil { return 0, err }
		if err := buffer.Writeu16(uint16(len(r.Other))); err != nil { return 0, err } // #nosec G115
		for _, b := range r.Other { 
			if err := buffer.Write(b); err != nil { return 0, err }
		}
		currPos := buffer.Position()
		if err := buffer.Seek(lenPos); err != nil { return 0, err }
		if err := buffer.Writeu16(uint16(currPos - (lenPos + 2))); err != nil { return 0, err } // #nosec G115
		if err := buffer.Seek(currPos); err != nil { return 0, err }
		return currPos - startPos, nil
	}
	
	if err := buffer.WriteName(r.Name); err != nil { return 0, err }
	if err := buffer.Writeu16(uint16(r.Type)); err != nil { return 0, err }
	if err := buffer.Writeu16(r.Class); err != nil { return 0, err }
	if err := buffer.Writeu32(r.TTL); err != nil { return 0, err }

	switch r.Type {
	case A:
		if err := buffer.Writeu16(4); err != nil { return 0, err }
		ip4 := r.IP.To4()
		for _, b := range ip4 { 
			if err := buffer.Write(b); err != nil { return 0, err }
		}
	case AAAA:
		if err := buffer.Writeu16(16); err != nil { return 0, err }
		for _, b := range r.IP.To16() { 
			if err := buffer.Write(b); err != nil { return 0, err }
		}
	case NS, CNAME, PTR, MD, MF, MB, MG, MR:
		lenPos := buffer.Position()
		if err := buffer.Writeu16(0); err != nil { return 0, err }
		if err := buffer.WriteName(r.Host); err != nil { return 0, err }
		currPos := buffer.Position()
		if err := buffer.Seek(lenPos); err != nil { return 0, err }
		if err := buffer.Writeu16(uint16(currPos - (lenPos + 2))); err != nil { return 0, err } // #nosec G115
		if err := buffer.Seek(currPos); err != nil { return 0, err }
	case MX:
		lenPos := buffer.Position()
		if err := buffer.Writeu16(0); err != nil { return 0, err }
		if err := buffer.Writeu16(r.Priority); err != nil { return 0, err }
		if err := buffer.WriteName(r.Host); err != nil { return 0, err }
		currPos := buffer.Position()
		if err := buffer.Seek(lenPos); err != nil { return 0, err }
		if err := buffer.Writeu16(uint16(currPos - (lenPos + 2))); err != nil { return 0, err } // #nosec G115
		if err := buffer.Seek(currPos); err != nil { return 0, err }
	case TXT:
		if err := buffer.Writeu16(uint16(len(r.Txt) + 1)); err != nil { return 0, err } // #nosec G115
		if err := buffer.Write(byte(len(r.Txt))); err != nil { return 0, err } // #nosec G115
		for i := 0; i < len(r.Txt); i++ {
			if err := buffer.Write(r.Txt[i]); err != nil { return 0, err }
		}
	case SOA:
		lenPos := buffer.Position()
		if err := buffer.Writeu16(0); err != nil { return 0, err }
		if err := buffer.WriteName(r.MName); err != nil { return 0, err }
		if err := buffer.WriteName(r.RName); err != nil { return 0, err }
		if err := buffer.Writeu32(r.Serial); err != nil { return 0, err }
		if err := buffer.Writeu32(r.Refresh); err != nil { return 0, err }
		if err := buffer.Writeu32(r.Retry); err != nil { return 0, err }
		if err := buffer.Writeu32(r.Expire); err != nil { return 0, err }
		if err := buffer.Writeu32(r.Minimum); err != nil { return 0, err }
		currPos := buffer.Position()
		if err := buffer.Seek(lenPos); err != nil { return 0, err }
		if err := buffer.Writeu16(uint16(currPos - (lenPos + 2))); err != nil { return 0, err } // #nosec G115
		if err := buffer.Seek(currPos); err != nil { return 0, err }
	case HINFO:
		if err := buffer.Writeu16(uint16(len(r.CPU) + len(r.OS) + 2)); err != nil { return 0, err } // #nosec G115
		if err := buffer.Write(byte(len(r.CPU))); err != nil { return 0, err } // #nosec G115
		for i := 0; i < len(r.CPU); i++ {
			if err := buffer.Write(r.CPU[i]); err != nil { return 0, err }
		}
		if err := buffer.Write(byte(len(r.OS))); err != nil { return 0, err } // #nosec G115
		for i := 0; i < len(r.OS); i++ {
			if err := buffer.Write(r.OS[i]); err != nil { return 0, err }
		}
	case MINFO:
		lenPos := buffer.Position()
		if err := buffer.Writeu16(0); err != nil { return 0, err }
		if err := buffer.WriteName(r.RMailBX); err != nil { return 0, err }
		if err := buffer.WriteName(r.EMailBX); err != nil { return 0, err }
		currPos := buffer.Position()
		if err := buffer.Seek(lenPos); err != nil { return 0, err }
		if err := buffer.Writeu16(uint16(currPos - (lenPos + 2))); err != nil { return 0, err } // #nosec G115
		if err := buffer.Seek(currPos); err != nil { return 0, err }
	case NSEC:
		lenPos := buffer.Position()
		if err := buffer.Writeu16(0); err != nil { return 0, err }
		if err := buffer.WriteName(r.NextName); err != nil { return 0, err }
		for _, b := range r.TypeBitMap {
			if err := buffer.Write(b); err != nil { return 0, err }
		}
		currPos := buffer.Position()
		if err := buffer.Seek(lenPos); err != nil { return 0, err }
		if err := buffer.Writeu16(uint16(currPos - (lenPos + 2))); err != nil { return 0, err } // #nosec G115
		if err := buffer.Seek(currPos); err != nil { return 0, err }
	case DNSKEY:
		if err := buffer.Writeu16(uint16(4 + len(r.PublicKey))); err != nil { return 0, err } // #nosec G115
		if err := buffer.Writeu16(r.Flags); err != nil { return 0, err }
		if err := buffer.Write(3); err != nil { return 0, err } // Protocol
		if err := buffer.Write(r.Algorithm); err != nil { return 0, err }
		for _, b := range r.PublicKey {
			if err := buffer.Write(b); err != nil { return 0, err }
		}
	case RRSIG:
		lenPos := buffer.Position()
		if err := buffer.Writeu16(0); err != nil { return 0, err }
		if err := buffer.Writeu16(r.TypeCovered); err != nil { return 0, err }
		if err := buffer.Write(r.Algorithm); err != nil { return 0, err }
		if err := buffer.Write(r.Labels); err != nil { return 0, err }
		if err := buffer.Writeu32(r.OrigTTL); err != nil { return 0, err }
		if err := buffer.Writeu32(r.Expiration); err != nil { return 0, err }
		if err := buffer.Writeu32(r.Inception); err != nil { return 0, err }
		if err := buffer.Writeu16(r.KeyTag); err != nil { return 0, err }
		if err := buffer.WriteName(r.SignerName); err != nil { return 0, err }
		for _, b := range r.Signature {
			if err := buffer.Write(b); err != nil { return 0, err }
		}
		currPos := buffer.Position()
		if err := buffer.Seek(lenPos); err != nil { return 0, err }
		if err := buffer.Writeu16(uint16(currPos - (lenPos + 2))); err != nil { return 0, err } // #nosec G115
		if err := buffer.Seek(currPos); err != nil { return 0, err }
	case NSEC3:
		lenPos := buffer.Position()
		if err := buffer.Writeu16(0); err != nil { return 0, err }
		if err := buffer.Write(r.HashAlg); err != nil { return 0, err }
		if err := buffer.Write(uint8(r.Flags)); err != nil { return 0, err } // #nosec G115
		if err := buffer.Writeu16(r.Iterations); err != nil { return 0, err }
		if err := buffer.Write(uint8(len(r.Salt))); err != nil { return 0, err } // #nosec G115
		for _, b := range r.Salt {
			if err := buffer.Write(b); err != nil { return 0, err }
		}
		if err := buffer.Write(uint8(len(r.NextHash))); err != nil { return 0, err } // #nosec G115
		for _, b := range r.NextHash {
			if err := buffer.Write(b); err != nil { return 0, err }
		}
		for _, b := range r.TypeBitMap {
			if err := buffer.Write(b); err != nil { return 0, err }
		}
		currPos := buffer.Position()
		if err := buffer.Seek(lenPos); err != nil { return 0, err }
		if err := buffer.Writeu16(uint16(currPos - (lenPos + 2))); err != nil { return 0, err } // #nosec G115
		if err := buffer.Seek(currPos); err != nil { return 0, err }
	case NSEC3PARAM:
		lenPos := buffer.Position()
		if err := buffer.Writeu16(0); err != nil { return 0, err }
		if err := buffer.Write(r.HashAlg); err != nil { return 0, err }
		if err := buffer.Write(uint8(r.Flags)); err != nil { return 0, err } // #nosec G115
		if err := buffer.Writeu16(r.Iterations); err != nil { return 0, err }
		if err := buffer.Write(uint8(len(r.Salt))); err != nil { return 0, err } // #nosec G115
		for _, b := range r.Salt {
			if err := buffer.Write(b); err != nil { return 0, err }
		}
		currPos := buffer.Position()
		if err := buffer.Seek(lenPos); err != nil { return 0, err }
		if err := buffer.Writeu16(uint16(currPos - (lenPos + 2))); err != nil { return 0, err } // #nosec G115
		if err := buffer.Seek(currPos); err != nil { return 0, err }
	case DS:
		if err := buffer.Writeu16(uint16(4 + len(r.Digest))); err != nil { return 0, err } // #nosec G115
		if err := buffer.Writeu16(r.KeyTag); err != nil { return 0, err }
		if err := buffer.Write(r.Algorithm); err != nil { return 0, err }
		if err := buffer.Write(r.DigestType); err != nil { return 0, err }
		for _, b := range r.Digest {
			if err := buffer.Write(b); err != nil { return 0, err }
		}
	default:
		if err := buffer.Writeu16(uint16(len(r.Data))); err != nil { return 0, err } // #nosec G115
		for _, b := range r.Data {
			if err := buffer.Write(b); err != nil { return 0, err }
		}
	}

	return buffer.Position() - startPos, nil
}

type DNSPacket struct {
	Header      DNSHeader
	Questions   []DNSQuestion
	Answers     []DNSRecord
	Authorities []DNSRecord
	Resources   []DNSRecord
	TSIGStart   int // Byte offset where TSIG record starts, -1 if not present
}

func NewDNSPacket() *DNSPacket {
	return &DNSPacket{
		Header: DNSHeader{},
		Questions: []DNSQuestion{},
		Answers: []DNSRecord{},
		Authorities: []DNSRecord{},
		Resources: []DNSRecord{},
		TSIGStart: -1,
	}
}

func (p *DNSPacket) FromBuffer(buffer *BytePacketBuffer) error {
	if err := p.Header.Read(buffer); err != nil { return err }
	for i := 0; i < int(p.Header.Questions); i++ {
		var q DNSQuestion
		if err := q.Read(buffer); err != nil { return err }
		p.Questions = append(p.Questions, q)
	}
	for i := 0; i < int(p.Header.Answers); i++ {
		var r DNSRecord
		if err := r.Read(buffer); err != nil { return err }
		p.Answers = append(p.Answers, r)
	}
	for i := 0; i < int(p.Header.AuthoritativeEntries); i++ {
		var r DNSRecord
		if err := r.Read(buffer); err != nil { return err }
		p.Authorities = append(p.Authorities, r)
	}
	for i := 0; i < int(p.Header.ResourceEntries); i++ {
		start := buffer.Position()
		var r DNSRecord
		if err := r.Read(buffer); err != nil { return err }
		if r.Type == TSIG {
			p.TSIGStart = start
		}
		p.Resources = append(p.Resources, r)
	}
	return nil
}

func (p *DNSPacket) Write(buffer *BytePacketBuffer) error {
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
