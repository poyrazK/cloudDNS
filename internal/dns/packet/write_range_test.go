package packet

import (
	"net"
	"testing"
)

// TestWriteRange_LargeNSEC verifies WriteRange handles large TypeBitMap correctly.
func TestWriteRange_LargeNSEC(t *testing.T) {
	// Build a TypeBitMap with many record types (larger than typical small tests)
	// This exercises WriteRange with a larger buffer
	typeBitmap := make([]byte, 256)
	for i := range typeBitmap {
		typeBitmap[i] = byte(i % 256)
	}

	record := DNSRecord{
		Name:       "nsec-large.test.",
		Type:       NSEC,
		Class:      1,
		TTL:        300,
		NextName:   "next.test.",
		TypeBitMap: typeBitmap,
	}

	buf := NewBytePacketBuffer()
	_, err := record.Write(buf)
	if err != nil {
		t.Fatalf("Write failed: %v", err)
	}

	data := make([]byte, buf.Position())
	copy(data, buf.Buf[:buf.Position()])

	readBuf := NewBytePacketBuffer()
	readBuf.Load(data)

	var parsed DNSRecord
	if err := parsed.Read(readBuf); err != nil {
		t.Fatalf("Read failed: %v", err)
	}

	if len(parsed.TypeBitMap) != len(typeBitmap) {
		t.Errorf("TypeBitMap length mismatch: got %d, want %d", len(parsed.TypeBitMap), len(typeBitmap))
	}
	for i := range parsed.TypeBitMap {
		if parsed.TypeBitMap[i] != typeBitmap[i] {
			t.Errorf("TypeBitMap[%d] mismatch: got %v, want %v", i, parsed.TypeBitMap[i], typeBitmap[i])
		}
	}
}

// TestWriteRange_LargeHINFO verifies WriteRange handles long CPU/OS strings.
func TestWriteRange_LargeHINFO(t *testing.T) {
	// Use longer strings to exercise WriteRange with larger data
	cpu := "AMD EPYC 7763 64-Core Processor"
	os := "Ubuntu 22.04.3 LTS (Jammy Jellyfish)"

	record := DNSRecord{
		Name: "hinfo-large.test.",
		Type: HINFO,
		Class: 1,
		TTL:   300,
		CPU:   cpu,
		OS:    os,
	}

	buf := NewBytePacketBuffer()
	_, err := record.Write(buf)
	if err != nil {
		t.Fatalf("Write failed: %v", err)
	}

	data := make([]byte, buf.Position())
	copy(data, buf.Buf[:buf.Position()])

	readBuf := NewBytePacketBuffer()
	readBuf.Load(data)

	var parsed DNSRecord
	if err := parsed.Read(readBuf); err != nil {
		t.Fatalf("Read failed: %v", err)
	}

	if parsed.CPU != cpu {
		t.Errorf("CPU mismatch: got %s, want %s", parsed.CPU, cpu)
	}
	if parsed.OS != os {
		t.Errorf("OS mismatch: got %s, want %s", parsed.OS, os)
	}
}

// TestWriteRange_LargeCAA verifies WriteRange handles multi-char Tag and Value.
func TestWriteRange_LargeCAA(t *testing.T) {
	record := DNSRecord{
		Name:    "caa-large.test.",
		Type:    CAA,
		Class:   1,
		TTL:     300,
		CAAFlag: 128,
		CAATag:  "issuewild",
		CAAValue: "letsencrypt.org; validation-method=dns-01; notes=Production",
	}

	buf := NewBytePacketBuffer()
	_, err := record.Write(buf)
	if err != nil {
		t.Fatalf("Write failed: %v", err)
	}

	data := make([]byte, buf.Position())
	copy(data, buf.Buf[:buf.Position()])

	readBuf := NewBytePacketBuffer()
	readBuf.Load(data)

	var parsed DNSRecord
	if err := parsed.Read(readBuf); err != nil {
		t.Fatalf("Read failed: %v", err)
	}

	if parsed.CAAFlag != record.CAAFlag {
		t.Errorf("CAAFlag mismatch: got %d, want %d", parsed.CAAFlag, record.CAAFlag)
	}
	if parsed.CAATag != record.CAATag {
		t.Errorf("CAATag mismatch: got %s, want %s", parsed.CAATag, record.CAATag)
	}
	if parsed.CAAValue != record.CAAValue {
		t.Errorf("CAAValue mismatch: got %s, want %s", parsed.CAAValue, record.CAAValue)
	}
}

// TestWriteRange_LargeDS verifies WriteRange handles a larger digest.
func TestWriteRange_LargeDS(t *testing.T) {
	// SHA-256 digest is 32 bytes; use something larger for more coverage
	digest := make([]byte, 64)
	for i := range digest {
		digest[i] = byte(i * 3)
	}

	record := DNSRecord{
		Name:         "ds-large.test.",
		Type:         DS,
		Class:        1,
		TTL:          300,
		KeyTag:       54321,
		Algorithm:    13,
		DigestType:   2, // SHA-256
		Digest:       digest,
	}

	buf := NewBytePacketBuffer()
	_, err := record.Write(buf)
	if err != nil {
		t.Fatalf("Write failed: %v", err)
	}

	data := make([]byte, buf.Position())
	copy(data, buf.Buf[:buf.Position()])

	readBuf := NewBytePacketBuffer()
	readBuf.Load(data)

	var parsed DNSRecord
	if err := parsed.Read(readBuf); err != nil {
		t.Fatalf("Read failed: %v", err)
	}

	if len(parsed.Digest) != len(digest) {
		t.Errorf("Digest length mismatch: got %d, want %d", len(parsed.Digest), len(digest))
	}
	for i := range parsed.Digest {
		if parsed.Digest[i] != digest[i] {
			t.Errorf("Digest[%d] mismatch: got %v, want %v", i, parsed.Digest[i], digest[i])
		}
	}
}

// TestWriteRange_LargeDNSKEY verifies WriteRange handles a larger public key.
func TestWriteRange_LargeDNSKEY(t *testing.T) {
	// RSA 2048-bit key is ~256 bytes in DNSKEY format
	publicKey := make([]byte, 256)
	for i := range publicKey {
		publicKey[i] = byte((i * 7) % 256)
	}

	record := DNSRecord{
		Name:     "dnskey-large.test.",
		Type:     DNSKEY,
		Class:    1,
		TTL:      300,
		Flags:    257,
		Algorithm: 8, // RSA/SHA-256
		PublicKey: publicKey,
	}

	buf := NewBytePacketBuffer()
	_, err := record.Write(buf)
	if err != nil {
		t.Fatalf("Write failed: %v", err)
	}

	data := make([]byte, buf.Position())
	copy(data, buf.Buf[:buf.Position()])

	readBuf := NewBytePacketBuffer()
	readBuf.Load(data)

	var parsed DNSRecord
	if err := parsed.Read(readBuf); err != nil {
		t.Fatalf("Read failed: %v", err)
	}

	if len(parsed.PublicKey) != len(publicKey) {
		t.Errorf("PublicKey length mismatch: got %d, want %d", len(parsed.PublicKey), len(publicKey))
	}
	for i := range parsed.PublicKey {
		if parsed.PublicKey[i] != publicKey[i] {
			t.Errorf("PublicKey[%d] mismatch: got %v, want %v", i, parsed.PublicKey[i], publicKey[i])
		}
	}
}

// TestWriteRange_LargeRRSIG verifies WriteRange handles a larger signature.
func TestWriteRange_LargeRRSIG(t *testing.T) {
	// A typical RSA signature can be 256+ bytes
	signature := make([]byte, 256)
	for i := range signature {
		signature[i] = byte((i * 11) % 256)
	}

	record := DNSRecord{
		Name:         "rrsig-large.test.",
		Type:         RRSIG,
		Class:        1,
		TTL:          300,
		TypeCovered:  1, // A
		Algorithm:    8, // RSA/SHA-256
		Labels:       2,
		OrigTTL:      3600,
		Expiration:   2000000000,
		Inception:    1000000000,
		KeyTag:       12345,
		SignerName:   "dnskey.test.",
		Signature:    signature,
	}

	buf := NewBytePacketBuffer()
	_, err := record.Write(buf)
	if err != nil {
		t.Fatalf("Write failed: %v", err)
	}

	data := make([]byte, buf.Position())
	copy(data, buf.Buf[:buf.Position()])

	readBuf := NewBytePacketBuffer()
	readBuf.Load(data)

	var parsed DNSRecord
	if err := parsed.Read(readBuf); err != nil {
		t.Fatalf("Read failed: %v", err)
	}

	if len(parsed.Signature) != len(signature) {
		t.Errorf("Signature length mismatch: got %d, want %d", len(parsed.Signature), len(signature))
	}
	for i := range parsed.Signature {
		if parsed.Signature[i] != signature[i] {
			t.Errorf("Signature[%d] mismatch: got %v, want %v", i, parsed.Signature[i], signature[i])
		}
	}
}

// TestWriteRange_LargeNSEC3 verifies WriteRange handles large Salt, NextHash, TypeBitMap.
func TestWriteRange_LargeNSEC3(t *testing.T) {
	salt := make([]byte, 32)
	for i := range salt {
		salt[i] = byte(i * 5)
	}
	nextHash := make([]byte, 20)
	for i := range nextHash {
		nextHash[i] = byte(i * 7)
	}
	typeBitmap := make([]byte, 64)
	for i := range typeBitmap {
		typeBitmap[i] = byte(i % 256)
	}

	record := DNSRecord{
		Name:       "nsec3-large.test.",
		Type:       NSEC3,
		Class:      1,
		TTL:        300,
		HashAlg:    1, // SHA-1
		Iterations: 100,
		Salt:       salt,
		NextHash:   nextHash,
		TypeBitMap: typeBitmap,
	}

	buf := NewBytePacketBuffer()
	_, err := record.Write(buf)
	if err != nil {
		t.Fatalf("Write failed: %v", err)
	}

	data := make([]byte, buf.Position())
	copy(data, buf.Buf[:buf.Position()])

	readBuf := NewBytePacketBuffer()
	readBuf.Load(data)

	var parsed DNSRecord
	if err := parsed.Read(readBuf); err != nil {
		t.Fatalf("Read failed: %v", err)
	}

	if len(parsed.Salt) != len(salt) {
		t.Errorf("Salt length mismatch: got %d, want %d", len(parsed.Salt), len(salt))
	}
	if len(parsed.NextHash) != len(nextHash) {
		t.Errorf("NextHash length mismatch: got %d, want %d", len(parsed.NextHash), len(nextHash))
	}
	if len(parsed.TypeBitMap) != len(typeBitmap) {
		t.Errorf("TypeBitMap length mismatch: got %d, want %d", len(parsed.TypeBitMap), len(typeBitmap))
	}
}

// TestWriteRange_LargeHTTPS_IpHints verifies WriteRange with multiple IP hints.
func TestWriteRange_LargeHTTPS_IpHints(t *testing.T) {
	ipv4Hints := []net.IP{
		net.ParseIP("192.0.2.1"),
		net.ParseIP("192.0.2.2"),
		net.ParseIP("192.0.2.3"),
	}
	ipv6Hints := []net.IP{
		net.ParseIP("2001:db8::1"),
		net.ParseIP("2001:db8::2"),
	}

	record := DNSRecord{
		Name:           "https-hints-large.test.",
		Type:           HTTPS,
		Class:          1,
		TTL:            300,
		HTTPSPriority:  1,
		HTTPSTarget:    "target.test.",
		HTTPSIpv4Hint:  ipv4Hints,
		HTTPSIpv6Hint:  ipv6Hints,
	}

	buf := NewBytePacketBuffer()
	_, err := record.Write(buf)
	if err != nil {
		t.Fatalf("Write failed: %v", err)
	}

	data := make([]byte, buf.Position())
	copy(data, buf.Buf[:buf.Position()])

	readBuf := NewBytePacketBuffer()
	readBuf.Load(data)

	var parsed DNSRecord
	if err := parsed.Read(readBuf); err != nil {
		t.Fatalf("Read failed: %v", err)
	}

	if len(parsed.HTTPSIpv4Hint) != len(ipv4Hints) {
		t.Errorf("IPv4 hint count mismatch: got %d, want %d", len(parsed.HTTPSIpv4Hint), len(ipv4Hints))
	}
	if len(parsed.HTTPSIpv6Hint) != len(ipv6Hints) {
		t.Errorf("IPv6 hint count mismatch: got %d, want %d", len(parsed.HTTPSIpv6Hint), len(ipv6Hints))
	}
	for i, ip := range parsed.HTTPSIpv4Hint {
		if !ip.Equal(ipv4Hints[i]) {
			t.Errorf("HTTPSIpv4Hint[%d] mismatch: got %v, want %v", i, ip, ipv4Hints[i])
		}
	}
	for i, ip := range parsed.HTTPSIpv6Hint {
		if !ip.Equal(ipv6Hints[i]) {
			t.Errorf("HTTPSIpv6Hint[%d] mismatch: got %v, want %v", i, ip, ipv6Hints[i])
		}
	}
}

// TestWriteRange_TSIGMAC verifies WriteRange with large TSIG MAC.
func TestWriteRange_TSIGMAC(t *testing.T) {
	mac := make([]byte, 64)
	for i := range mac {
		mac[i] = byte(i * 3)
	}
	other := make([]byte, 32)
	for i := range other {
		other[i] = byte(i * 7)
	}

	record := DNSRecord{
		Name:          "tsig-large.test.",
		Type:          TSIG,
		Class:         0,
		TTL:           0,
		AlgorithmName: "hmac-sha256.",
		TimeSigned:    1234567890,
		Fudge:         300,
		MAC:           mac,
		OriginalID:    1,
		Error:         0,
		Other:         other,
	}

	buf := NewBytePacketBuffer()
	_, err := record.Write(buf)
	if err != nil {
		t.Fatalf("Write failed: %v", err)
	}

	data := make([]byte, buf.Position())
	copy(data, buf.Buf[:buf.Position()])

	readBuf := NewBytePacketBuffer()
	readBuf.Load(data)

	var parsed DNSRecord
	if err := parsed.Read(readBuf); err != nil {
		t.Fatalf("Read failed: %v", err)
	}

	if len(parsed.MAC) != len(mac) {
		t.Errorf("MAC length mismatch: got %d, want %d", len(parsed.MAC), len(mac))
	}
	if len(parsed.Other) != len(other) {
		t.Errorf("Other length mismatch: got %d, want %d", len(parsed.Other), len(other))
	}
	for i := range parsed.MAC {
		if parsed.MAC[i] != mac[i] {
			t.Errorf("MAC[%d] mismatch", i)
		}
	}
	for i := range parsed.Other {
		if parsed.Other[i] != other[i] {
			t.Errorf("Other[%d] mismatch", i)
		}
	}
}

// TestWriteRange_GenericLargeData verifies WriteRange with large generic Data.
// Note: the Read path for generic types steps over RDATA without populating r.Data,
// so this test validates the write path via buffer contents.
func TestWriteRange_GenericLargeData(t *testing.T) {
	data := make([]byte, 512)
	for i := range data {
		data[i] = byte((i * 13) % 256)
	}

	record := DNSRecord{
		Name:  "generic-large.test.",
		Type:  UNKNOWN,
		Class: 1,
		TTL:   300,
		Data:  data,
	}

	buf := NewBytePacketBuffer()
	written, err := record.Write(buf)
	if err != nil {
		t.Fatalf("Write failed: %v", err)
	}

	// Verify the written size matches expectations
	// RDLENGTH field at offset (name + type + class + ttl = variable + 10 bytes)
	// We just verify total bytes written is reasonable for 512-byte payload + header
	if written < 530 {
		t.Errorf("Written size too small: got %d, want >= 530", written)
	}

	// Read the RDLENGTH and verify it matches the data length
	// Skip name (compressed) and fixed fields, then read RDLENGTH
	readBuf := NewBytePacketBuffer()
	readBuf.Load(buf.Buf[:buf.Position()])

	// Read name
	_, _ = readBuf.ReadName()
	// Read type (2 bytes)
	readBuf.Step(2)
	// Read class (2 bytes)
	readBuf.Step(2)
	// Read TTL (4 bytes)
	readBuf.Step(4)
	// Read RDLENGTH (2 bytes)
	rdLength, err := readBuf.Readu16()
	if err != nil {
		t.Fatalf("Failed to read RDLENGTH: %v", err)
	}
	if rdLength != 512 {
		t.Errorf("RDLENGTH mismatch: got %d, want 512", rdLength)
	}

	// Read RDATA bytes and verify content
	rdata := make([]byte, 512)
	copy(rdata, readBuf.Buf[readBuf.Position():readBuf.Position()+512])
	for i := range rdata {
		if rdata[i] != data[i] {
			t.Errorf("RDATA[%d] mismatch: got %v, want %v", i, rdata[i], data[i])
		}
	}
}