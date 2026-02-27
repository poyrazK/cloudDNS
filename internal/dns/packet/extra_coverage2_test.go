package packet

import (
	"testing"
)

func TestSerialization_ExtraRecords(t *testing.T) {
	tests := []struct {
		name   string
		record DNSRecord
	}{
		{
			name: "TSIG Record",
			record: DNSRecord{
				Name:          "tsig.test.",
				Type:          TSIG,
				Class:         255,
				TTL:           0,
				AlgorithmName: "hmac-sha256.",
				TimeSigned:    uint64(123456789),
				Fudge:         300,
				MAC:           []byte{1, 2, 3, 4},
				OriginalID:    1234,
				Error:         0,
				Other:         []byte{5, 6},
			},
		},
		{
			name: "ANY Class Deletion",
			record: DNSRecord{
				Name:  "delete.test.",
				Type:  A,
				Class: 255,
				TTL:   0,
			},
		},
		{
			name: "MD Record",
			record: DNSRecord{
				Name: "md.test.",
				Type: MD,
				TTL:  300,
				Host: "md.host.test.",
			},
		},
		{
			name: "MF Record",
			record: DNSRecord{
				Name: "mf.test.",
				Type: MF,
				TTL:  300,
				Host: "mf.host.test.",
			},
		},
		{
			name: "MB Record",
			record: DNSRecord{
				Name: "mb.test.",
				Type: MB,
				TTL:  300,
				Host: "mb.host.test.",
			},
		},
		{
			name: "MG Record",
			record: DNSRecord{
				Name: "mg.test.",
				Type: MG,
				TTL:  300,
				Host: "mg.host.test.",
			},
		},
		{
			name: "MR Record",
			record: DNSRecord{
				Name: "mr.test.",
				Type: MR,
				TTL:  300,
				Host: "mr.host.test.",
			},
		},
		{
			name: "HINFO Record",
			record: DNSRecord{
				Name: "hinfo.test.",
				Type: HINFO,
				TTL:  300,
				CPU:  "Intel",
				OS:   "Linux",
			},
		},
		{
			name: "MINFO Record",
			record: DNSRecord{
				Name:    "minfo.test.",
				Type:    MINFO,
				TTL:     300,
				RMailBX: "r.mail.test.",
				EMailBX: "e.mail.test.",
			},
		},
		{
			name: "NSEC Record",
			record: DNSRecord{
				Name:       "nsec.test.",
				Type:       NSEC,
				TTL:        300,
				NextName:   "next.nsec.test.",
				TypeBitMap: []byte{0x00, 0x01, 0x02},
			},
		},
		{
			name: "RRSIG Record",
			record: DNSRecord{
				Name:        "rrsig.test.",
				Type:        RRSIG,
				TTL:         300,
				TypeCovered: uint16(A),
				Algorithm:   13,
				Labels:      2,
				OrigTTL:     300,
				Expiration:  1000,
				Inception:   500,
				KeyTag:      12345,
				SignerName:  "signer.test.",
				Signature:   []byte{1, 2, 3, 4, 5},
			},
		},
		{
			name: "NSEC3 Record",
			record: DNSRecord{
				Name:       "nsec3.test.",
				Type:       NSEC3,
				TTL:        300,
				HashAlg:    1,
				Flags:      0,
				Iterations: 10,
				Salt:       []byte{1, 2, 3},
				NextHash:   []byte{4, 5, 6},
				TypeBitMap: []byte{0, 1},
			},
		},
		{
			name: "NSEC3PARAM Record",
			record: DNSRecord{
				Name:       "nsec3param.test.",
				Type:       NSEC3PARAM,
				TTL:        300,
				HashAlg:    1,
				Flags:      0,
				Iterations: 10,
				Salt:       []byte{1, 2, 3},
			},
		},
		{
			name: "OPT Record",
			record: DNSRecord{
				Name:           "",
				Type:           OPT,
				Class:          4096,
				UDPPayloadSize: 4096,
				ExtendedRcode:  0,
				EDNSVersion:    0,
				Z:              0,
				Options: []EdnsOption{
					{Code: 10, Data: []byte{1, 2}},
				},
			},
		},
		{
			name: "DS Record",
			record: DNSRecord{
				Name:       "ds.test.",
				Type:       DS,
				TTL:        300,
				KeyTag:     123,
				Algorithm:  13,
				DigestType: 2,
				Digest:     []byte{1, 2, 3, 4},
			},
		},
		{
			name: "DNSKEY Record",
			record: DNSRecord{
				Name:      "dnskey.test.",
				Type:      DNSKEY,
				TTL:       300,
				Flags:     256,
				Algorithm: 13,
				PublicKey: []byte{1, 2, 3, 4},
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			buffer := NewBytePacketBuffer()
			written, err := tt.record.Write(buffer)
			if err != nil {
				t.Fatalf("Failed to write %s record: %v", tt.name, err)
			}
			if written <= 0 {
				t.Errorf("Written bytes for %s should be > 0", tt.name)
			}

			_ = buffer.Seek(0)
			parsed := DNSRecord{}
			err = parsed.Read(buffer)
			if err != nil {
				t.Fatalf("Failed to read %s record: %v", tt.name, err)
			}

			if parsed.Type != tt.record.Type {
				t.Errorf("%s type mismatch", tt.name)
			}
		})
	}
}
