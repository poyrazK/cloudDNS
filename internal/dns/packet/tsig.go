package packet

import (
	"crypto/hmac"
	"crypto/md5"
	"errors"
	"time"
)

// VerifyTSIG checks if the TSIG record in the packet matches the provided key
func (p *DnsPacket) VerifyTSIG(rawBuffer []byte, tsigStart int, secret []byte) error {
	// 1. Find TSIG record (must be the last record in additional)
	if len(p.Resources) == 0 {
		return errors.New("no records in additional section")
	}
	tsig := p.Resources[len(p.Resources)-1]
	if tsig.Type != TSIG {
		return errors.New("last record is not TSIG")
	}

	// 2. Check time drift (Fudge)
	now := uint64(time.Now().Unix())
	drift := uint64(0)
	if now > tsig.TimeSigned {
		drift = now - tsig.TimeSigned
	} else {
		drift = tsig.TimeSigned - now
	}
	if drift > uint64(tsig.Fudge) {
		return errors.New("TSIG time drift exceeded")
	}

	// 3. Compute HMAC
	h := hmac.New(md5.New, secret)
	
	// Create a copy of the buffer before TSIG and adjust ARCOUNT
	// Header is 12 bytes, ARCOUNT is at offset 10 (2 bytes)
	prefix := make([]byte, tsigStart)
	copy(prefix, rawBuffer[:tsigStart])
	if len(prefix) >= 12 {
		arCount := uint16(len(p.Resources) - 1)
		prefix[10] = byte(arCount >> 8)
		prefix[11] = byte(arCount & 0xFF)
	}
	h.Write(prefix)
	
	// Add TSIG variables (RFC 2845 Section 3.4.1)
	// Note: Names and Algorithms should be in canonical wire format
	vBuf := NewBytePacketBuffer()
	vBuf.WriteName(tsig.Name)
	vBuf.Writeu16(tsig.Class)
	vBuf.Writeu32(tsig.TTL)
	vBuf.WriteName(tsig.AlgorithmName)
	vBuf.Writeu16(uint16(tsig.TimeSigned >> 32))
	vBuf.Writeu32(uint32(tsig.TimeSigned & 0xFFFFFFFF))
	vBuf.Writeu16(tsig.Fudge)
	vBuf.Writeu16(tsig.Error)
	vBuf.Writeu16(uint16(len(tsig.Other)))
	vBuf.WriteRange(vBuf.Position(), tsig.Other)
	
	h.Write(vBuf.Buf[:vBuf.Position()])
	
	expectedMAC := h.Sum(nil)
	if !hmac.Equal(tsig.MAC, expectedMAC) {
		return errors.New("TSIG MAC mismatch")
	}

	return nil
}

func (p *DnsPacket) SignTSIG(buffer *BytePacketBuffer, keyName string, secret []byte) error {
	// 1. Prepare TSIG Record (without MAC yet)
	tsig := DnsRecord{
		Name:          keyName,
		Type:          TSIG,
		Class:         255, // ANY
		TTL:           0,
		AlgorithmName: "hmac-md5.sig-alg.reg.int.",
		TimeSigned:    uint64(time.Now().Unix()),
		Fudge:         300,
		OriginalID:    p.Header.ID,
	}

	// 2. Compute MAC
	h := hmac.New(md5.New, secret)
	
	// Write current buffer content (packet without TSIG)
	h.Write(buffer.Buf[:buffer.Position()])
	
	// Add TSIG variables to HMAC
	vBuf := NewBytePacketBuffer()
	vBuf.WriteName(tsig.Name)
	vBuf.Writeu16(tsig.Class)
	vBuf.Writeu32(tsig.TTL)
	vBuf.WriteName(tsig.AlgorithmName)
	vBuf.Writeu16(uint16(tsig.TimeSigned >> 32))
	vBuf.Writeu32(uint32(tsig.TimeSigned & 0xFFFFFFFF))
	vBuf.Writeu16(tsig.Fudge)
	vBuf.Writeu16(tsig.Error)
	vBuf.Writeu16(uint16(len(tsig.Other)))
	vBuf.WriteRange(vBuf.Position(), tsig.Other)
	
	h.Write(vBuf.Buf[:vBuf.Position()])
	
	tsig.MAC = h.Sum(nil)

	// 3. Update the packet state before writing to buffer
	p.Resources = append(p.Resources, tsig)
	p.Header.ResourceEntries = uint16(len(p.Resources))

	// 4. Update Header's ARCOUNT in the wire format (at offset 10)
	buffer.Buf[10] = byte(p.Header.ResourceEntries >> 8)
	buffer.Buf[11] = byte(p.Header.ResourceEntries & 0xFF)

	// 5. Write TSIG record to buffer
	p.TsigStart = buffer.Position()
	_, err := tsig.Write(buffer)
	return err
}
