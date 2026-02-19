// Package packet provides functionality for parsing and serializing DNS packets.
package packet

import (
	"fmt"
	"net"
	"github.com/poyrazK/cloudDNS/internal/core/domain"
)

// QueryType represents the DNS record type field (e.g., A, NS, MX).
type QueryType uint16

const (
	// UNKNOWN represents an unrecognized DNS query type.
	UNKNOWN    QueryType = 0
	// A represents an IPv4 address record.
	A          QueryType = 1
	// NS represents an authoritative name server record.
	NS         QueryType = 2
	// MD represents a mail destination record (obsolete).
	MD         QueryType = 3
	// MF represents a mail forwarder record (obsolete).
	MF         QueryType = 4
	// CNAME represents a canonical name for an alias.
	CNAME      QueryType = 5
	// SOA represents the start of a zone of authority record.
	SOA        QueryType = 6
	// MB represents a mailbox domain name record (experimental).
	MB         QueryType = 7
	// MG represents a mail group member record (experimental).
	MG         QueryType = 8
	// MR represents a mail rename domain name record (experimental).
	MR         QueryType = 9
	// NULL represents a null RR (experimental).
	NULL       QueryType = 10
	// WKS represents a well known service description record.
	WKS        QueryType = 11
	// PTR represents a domain name pointer record.
	PTR        QueryType = 12
	// HINFO represents host information records.
	HINFO      QueryType = 13
	// MINFO represents mailbox or mail list information record.
	MINFO      QueryType = 14
	// MX represents a mail exchange record.
	MX         QueryType = 15
	// TXT represents text records.
	TXT        QueryType = 16
	// AAAA represents an IPv6 address record.
	AAAA       QueryType = 28
	// SRV represents service location records (RFC 2782).
	SRV        QueryType = 33
	// DS represents a delegation signer record (RFC 4034).
	DS         QueryType = 43
	// RRSIG represents a DNSSEC signature record (RFC 4034).
	RRSIG      QueryType = 46
	// NSEC represents a next secure record (RFC 4034).
	NSEC       QueryType = 47
	// DNSKEY represents a DNS public key record (RFC 4034).
	DNSKEY     QueryType = 48
	// NSEC3 represents a next secure record version 3 (RFC 5155).
	NSEC3      QueryType = 50
	// NSEC3PARAM represents NSEC3 parameters (RFC 5155).
	NSEC3PARAM QueryType = 51
	// AXFR represents a request for a full zone transfer.
	AXFR       QueryType = 252
	// IXFR represents a request for an incremental zone transfer.
	IXFR       QueryType = 251
	// ANY represents a request for all records.
	ANY        QueryType = 255
	// OPT represents an EDNS(0) pseudo-RR (RFC 6891).
	OPT        QueryType = 41
	// TSIG represents a transaction signature record (RFC 2845).
	TSIG       QueryType = 250
)

// RFC 8914: Extended DNS Error Codes
const (
	// EdeOther represents a generic error.
	EdeOther               uint16 = 0
	// EdeUnsupportedDnskey indicates an unsupported DNSKEY algorithm.
	EdeUnsupportedDnskey  uint16 = 1
	// EdeUnsupportedDs indicates an unsupported DS digest algorithm.
	EdeUnsupportedDs      uint16 = 2
	// EdeStaleAnswer indicates the answer is stale.
	EdeStaleAnswer        uint16 = 3
	// EdeForgedAnswer indicates the answer may be forged.
	EdeForgedAnswer       uint16 = 4
	// EdeDnssecIndeterminate indicates DNSSEC validation is indeterminate.
	EdeDnssecIndeterminate uint16 = 5
	// EdeDnssecBogus indicates DNSSEC validation failed.
	EdeDnssecBogus        uint16 = 6
	// EdeSignatureExpired indicates the RRSIG has expired.
	EdeSignatureExpired   uint16 = 7
	// EdeSignatureNotYet indicates the RRSIG is not yet valid.
	EdeSignatureNotYet   uint16 = 8
	// EdeMissingDnskey indicates a required DNSKEY was missing.
	EdeMissingDnskey      uint16 = 9
	// EdeMissingDs indicates a required DS record was missing.
	EdeMissingDs          uint16 = 10
	// EdeUnsupportedAlg indicates an unsupported DNSSEC algorithm.
	EdeUnsupportedAlg     uint16 = 11
	// EdeProhibited indicates the query is prohibited.
	EdeProhibited          uint16 = 18
	// EdeBlocked indicates the query was blocked by policy.
	EdeBlocked             uint16 = 15
	// EdeCensored indicates the query was censored.
	EdeCensored            uint16 = 16
	// EdeFiltered indicates the query was filtered.
	EdeFiltered            uint16 = 17
)

// RecordTypeToQueryType converts a domain model RecordType to its corresponding packet QueryType.
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

// String returns the human-readable representation of a QueryType.
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
	// OpcodeQuery represents a standard DNS query.
	OpcodeQuery  uint8 = 0
	// OpcodeIQuery represents an inverse DNS query (obsolete).
	OpcodeIQuery uint8 = 1
	// OpcodeStatus represents a server status request.
	OpcodeStatus uint8 = 2
	// OpcodeNotify represents a zone change notification (RFC 1996).
	OpcodeNotify uint8 = 4
	// OpcodeUpdate represents a dynamic update request (RFC 2136).
	OpcodeUpdate uint8 = 5
)

const (
	// RcodeNoError indicates no error condition.
	RcodeNoError  uint8 = 0
	// RcodeFormErr indicates a format error in the request.
	RcodeFormErr  uint8 = 1
	// RcodeServFail indicates a server failure.
	RcodeServFail uint8 = 2
	// RcodeNxDomain indicates the domain name does not exist.
	RcodeNxDomain uint8 = 3
	// RcodeNotImp indicates the request is not implemented.
	RcodeNotImp   uint8 = 4
	// RcodeRefused indicates the server refuses to perform the operation.
	RcodeRefused  uint8 = 5
	// RcodeYxDomain indicates a name exists that should not (RFC 2136).
	RcodeYxDomain uint8 = 6
	// RcodeYxRRSet indicates an RRset exists that should not (RFC 2136).
	RcodeYxRRSet  uint8 = 7
	// RcodeNxRRSet indicates an RRset does not exist that should (RFC 2136).
	RcodeNxRRSet  uint8 = 8
	// RcodeNotAuth indicates the server is not authoritative for the zone.
	RcodeNotAuth  uint8 = 9
	// RcodeNotZone indicates a name is not within the zone (RFC 2136).
	RcodeNotZone  uint8 = 10
)

// DNSHeader represents the header section of a DNS packet.
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

// NewDNSHeader creates and returns a pointer to a new DNSHeader.
func NewDNSHeader() *DNSHeader {
	return &DNSHeader{}
}

// Read populates the DNSHeader fields by reading from the provided buffer.
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

// Write serializes the DNSHeader into the provided buffer.
func (h *DNSHeader) Write(buffer *BytePacketBuffer) error {
	if err := buffer.Writeu16(h.ID); err != nil { return err }

	var flags uint16
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

// DNSQuestion represents a single question in the DNS question section.
type DNSQuestion struct {
	Name  string
	QType QueryType
}

// NewDNSQuestion creates and returns a pointer to a new DNSQuestion.
func NewDNSQuestion(name string, qtype QueryType) *DNSQuestion {
	return &DNSQuestion{
		Name:  name,
		QType: qtype,
	}
}

// Read populates the DNSQuestion fields by reading from the provided buffer.
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

// Write serializes the DNSQuestion into the provided buffer.
func (q *DNSQuestion) Write(buffer *BytePacketBuffer) error {
	if err := buffer.WriteName(q.Name); err != nil { return err }
	if err := buffer.Writeu16(uint16(q.QType)); err != nil { return err }
	if err := buffer.Writeu16(1); err != nil { return err } // CLASS IN
	return nil
}

// EdnsOption represents a single option in an OPT pseudo-RR (RFC 6891).
type EdnsOption struct {
	Code uint16
	Data []byte
}

// DNSRecord represents a single DNS resource record.
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

// AddEDE adds an Extended DNS Error (RFC 8914) option to an OPT record.
func (r *DNSRecord) AddEDE(code uint16, text string) {
	data := []byte{byte(code >> 8), byte(code & 0xFF)}
	if text != "" {
		data = append(data, []byte(text)...)
	}
	r.Options = append(r.Options, EdnsOption{Code: 15, Data: data})
}

// Read populates the DNSRecord fields by reading from the provided buffer.
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

	dataLen, errReadLen := buffer.Readu16()
	if errReadLen != nil { return errReadLen }
	startPos := buffer.Position()

	if dataLen == 0 && r.Type != OPT {
		return nil
	}

	switch r.Type {
	case A:
		rawIP, errRead := buffer.ReadRange(buffer.Position(), 4)
		if errRead != nil { return errRead }
		r.IP = net.IP(rawIP)
		if errStep := buffer.Step(4); errStep != nil { return errStep }
	case AAAA:
		rawIP, errRead := buffer.ReadRange(buffer.Position(), 16)
		if errRead != nil { return errRead }
		r.IP = net.IP(rawIP)
		if errStep := buffer.Step(16); errStep != nil { return errStep }
	case NS, CNAME, PTR, MD, MF, MB, MG, MR:
		r.Host, err = buffer.ReadName()
		if err != nil { return err }
	case MX:
		if r.Priority, err = buffer.Readu16(); err != nil { return err }
		if r.Host, err = buffer.ReadName(); err != nil { return err }
	case TXT:
		txtLen, errReadTxt := buffer.Read()
		if errReadTxt != nil { return errReadTxt }
		txtData, errRange := buffer.ReadRange(buffer.Position(), int(txtLen))
		if errRange != nil { return errRange }
		r.Txt = string(txtData)
		if errStep := buffer.Step(int(txtLen)); errStep != nil { return errStep }
	case SOA:
		if r.MName, err = buffer.ReadName(); err != nil { return err }
		if r.RName, err = buffer.ReadName(); err != nil { return err }
		if r.Serial, err = buffer.Readu32(); err != nil { return err }
		if r.Refresh, err = buffer.Readu32(); err != nil { return err }
		if r.Retry, err = buffer.Readu32(); err != nil { return err }
		if r.Expire, err = buffer.Readu32(); err != nil { return err }
		if r.Minimum, err = buffer.Readu32(); err != nil { return err }
	case HINFO:
		cpuLen, errReadCPU := buffer.Read()
		if errReadCPU != nil { return errReadCPU }
		cpu, errRange := buffer.ReadRange(buffer.Position(), int(cpuLen))
		if errRange != nil { return errRange }
		r.CPU = string(cpu)
		if errStep := buffer.Step(int(cpuLen)); errStep != nil { return errStep }
		osLen, errReadOS := buffer.Read()
		if errReadOS != nil { return errReadOS }
		osData, errRange2 := buffer.ReadRange(buffer.Position(), int(osLen))
		if errRange2 != nil { return errRange2 }
		r.OS = string(osData)
		if errStep2 := buffer.Step(int(osLen)); errStep2 != nil { return errStep2 }
	case MINFO:
		if r.RMailBX, err = buffer.ReadName(); err != nil { return err }
		if r.EMailBX, err = buffer.ReadName(); err != nil { return err }
	case NSEC:
		if r.NextName, err = buffer.ReadName(); err != nil { return err }
		remaining := int(dataLen) - (buffer.Position() - startPos)
		if r.TypeBitMap, err = buffer.ReadRange(buffer.Position(), remaining); err != nil { return err }
		if errStep := buffer.Step(remaining); errStep != nil { return errStep }
	case DNSKEY:
		if r.Flags, err = buffer.Readu16(); err != nil { return err }
		if _, errReadProto := buffer.Read(); errReadProto != nil { return errReadProto } // Protocol
		if r.Algorithm, err = buffer.Read(); err != nil { return err }
		remaining := int(dataLen) - (buffer.Position() - startPos)
		if r.PublicKey, err = buffer.ReadRange(buffer.Position(), remaining); err != nil { return err }
		if errStep := buffer.Step(remaining); errStep != nil { return errStep }
	case RRSIG:
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
		if errStep := buffer.Step(remaining); errStep != nil { return errStep }
	case NSEC3:
		if r.HashAlg, err = buffer.Read(); err != nil { return err }
		if _, errReadFlags := buffer.Read(); errReadFlags != nil { return errReadFlags } // Flags
		if r.Iterations, err = buffer.Readu16(); err != nil { return err }
		saltLen, errReadSalt := buffer.Read()
		if errReadSalt != nil { return errReadSalt }
		if r.Salt, err = buffer.ReadRange(buffer.Position(), int(saltLen)); err != nil { return err }
		if errStep := buffer.Step(int(saltLen)); errStep != nil { return errStep }
		hashLen, errReadHash := buffer.Read()
		if errReadHash != nil { return errReadHash }
		if r.NextHash, err = buffer.ReadRange(buffer.Position(), int(hashLen)); err != nil { return err }
		if errStep2 := buffer.Step(int(hashLen)); errStep2 != nil { return errStep2 }
		remaining := int(dataLen) - (buffer.Position() - startPos)
		if r.TypeBitMap, err = buffer.ReadRange(buffer.Position(), remaining); err != nil { return err }
		if errStep3 := buffer.Step(remaining); errStep3 != nil { return errStep3 }
	case NSEC3PARAM:
		if r.HashAlg, err = buffer.Read(); err != nil { return err }
		if _, errReadFlags := buffer.Read(); errReadFlags != nil { return errReadFlags } // Flags
		if r.Iterations, err = buffer.Readu16(); err != nil { return err }
		saltLen, errReadSalt := buffer.Read()
		if errReadSalt != nil { return errReadSalt }
		if r.Salt, err = buffer.ReadRange(buffer.Position(), int(saltLen)); err != nil { return err }
		if errStep := buffer.Step(int(saltLen)); errStep != nil { return errStep }
	case DS:
		if r.KeyTag, err = buffer.Readu16(); err != nil { return err }
		if r.Algorithm, err = buffer.Read(); err != nil { return err }
		if r.DigestType, err = buffer.Read(); err != nil { return err }
		remaining := int(dataLen) - (buffer.Position() - startPos)
		if r.Digest, err = buffer.ReadRange(buffer.Position(), remaining); err != nil { return err }
		if errStep := buffer.Step(remaining); errStep != nil { return errStep }
	case TSIG:
		if r.AlgorithmName, err = buffer.ReadName(); err != nil { return err }
		timeHigh, errReadHigh := buffer.Readu16()
		if errReadHigh != nil { return errReadHigh }
		timeLow, errReadLow := buffer.Readu32()
		if errReadLow != nil { return errReadLow }
		r.TimeSigned = uint64(timeHigh)<<32 | uint64(timeLow)
		if r.Fudge, err = buffer.Readu16(); err != nil { return err }
		macLen, errReadMAC := buffer.Readu16()
		if errReadMAC != nil { return errReadMAC }
		if r.MAC, err = buffer.ReadRange(buffer.Position(), int(macLen)); err != nil { return err }
		if errStep := buffer.Step(int(macLen)); errStep != nil { return errStep }
		if r.OriginalID, err = buffer.Readu16(); err != nil { return err }
		if r.Error, err = buffer.Readu16(); err != nil { return err }
		otherLen, errReadOther := buffer.Readu16()
		if errReadOther != nil { return errReadOther }
		if r.Other, err = buffer.ReadRange(buffer.Position(), int(otherLen)); err != nil { return err }
		if errStep2 := buffer.Step(int(otherLen)); errStep2 != nil { return errStep2 }
	case OPT:
		r.UDPPayloadSize = r.Class
		r.ExtendedRcode = uint8(r.TTL >> 24) // #nosec G115
		r.EDNSVersion = uint8((r.TTL >> 16) & 0xFF) // #nosec G115
		r.Z = uint16(r.TTL & 0xFFFF) // #nosec G115
		remaining := int(dataLen)
		for remaining >= 4 {
			optCode, errReadCode := buffer.Readu16()
			if errReadCode != nil { return errReadCode }
			optLen, errReadLen2 := buffer.Readu16()
			if errReadLen2 != nil { return errReadLen2 }
			if int(optLen) > remaining-4 { break }
			optData, errReadData := buffer.ReadRange(buffer.Position(), int(optLen))
			if errReadData != nil { return errReadData }
			if errStep := buffer.Step(int(optLen)); errStep != nil { return errStep }
			r.Options = append(r.Options, EdnsOption{Code: optCode, Data: optData})
			remaining -= (4 + int(optLen))
		}
	default:
		if errStep := buffer.Step(int(dataLen)); errStep != nil { return errStep }
	}
	return nil
}

// Write serializes the DNSRecord into the provided buffer.
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

	// RFC 2136 (Dynamic Update) special class handling:
	// Section 2.5.2: Class ANY means "Delete an RRset". 
	// The RDLENGTH MUST be 0 and RDATA MUST be empty.
	if r.Class == 255 {
		if err := buffer.Writeu16(0); err != nil { return 0, err }
		return buffer.Position() - startPos, nil
	}

	// Note: Class NONE (254) means "Delete a specific RR".
	// RFC 2136 Section 2.5.4: Both Type and RDATA MUST be specified.
	// Therefore, Class NONE falls through to standard RDATA serialization.

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
		// RFC 2136: Delete RRset (ANY/ANY) or record (NONE/type) has RDLENGTH = 0
		if len(r.Data) == 0 && (r.Class == 255 || r.Class == 254) {
			if err := buffer.Writeu16(0); err != nil { return 0, err }
		} else {
			if err := buffer.Writeu16(uint16(len(r.Data))); err != nil { return 0, err } // #nosec G115
			for _, b := range r.Data {
				if err := buffer.Write(b); err != nil { return 0, err }
			}
		}
	}

	return buffer.Position() - startPos, nil
}

// DNSPacket represents a complete DNS packet.
type DNSPacket struct {
	Header      DNSHeader
	Questions   []DNSQuestion
	Answers     []DNSRecord
	Authorities []DNSRecord
	Resources   []DNSRecord
	TSIGStart   int // Byte offset where TSIG record starts, -1 if not present
}

// NewDNSPacket creates and returns a pointer to a new DNSPacket.
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

// FromBuffer populates the DNSPacket by reading from the provided buffer.
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

// Write serializes the complete DNSPacket into the provided buffer.
func (p *DNSPacket) Write(buffer *BytePacketBuffer) error {
	p.Header.Questions = uint16(len(p.Questions)) // #nosec G115
	p.Header.Answers = uint16(len(p.Answers)) // #nosec G115
	p.Header.AuthoritativeEntries = uint16(len(p.Authorities)) // #nosec G115
	p.Header.ResourceEntries = uint16(len(p.Resources)) // #nosec G115

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
