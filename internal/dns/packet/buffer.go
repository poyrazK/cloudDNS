package packet

import (
	"errors"
	"strings"
)

// BytePacketBuffer simplifies reading and writing the DNS packet buffer
type BytePacketBuffer struct {
	Buf []byte
	Pos int
}

const MaxPacketSize = 65535

func NewBytePacketBuffer() *BytePacketBuffer {
	return &BytePacketBuffer{
		Buf: make([]byte, MaxPacketSize),
		Pos: 0,
	}
}

func (b *BytePacketBuffer) Load(data []byte) {
	copy(b.Buf, data)
}

// Position returns the current cursor position
func (b *BytePacketBuffer) Position() int {
	return b.Pos
}

// Step moves the cursor forward by steps
func (b *BytePacketBuffer) Step(steps int) error {
	b.Pos += steps
	return nil
}

// Seek moves the cursor to a specific position
func (b *BytePacketBuffer) Seek(pos int) error {
	b.Pos = pos
	return nil
}

// Read reads a single byte
func (b *BytePacketBuffer) Read() (byte, error) {
	if b.Pos >= MaxPacketSize {
		return 0, errors.New("end of buffer")
	}
	res := b.Buf[b.Pos]
	b.Pos++
	return res, nil
}

// ReadRange reads a slice of bytes
func (b *BytePacketBuffer) ReadRange(start int, length int) ([]byte, error) {
	if start+length > MaxPacketSize {
		return nil, errors.New("out of bounds")
	}
	res := make([]byte, length)
	copy(res, b.Buf[start:start+length])
	return res, nil
}

// Readu16 reads 2 bytes as uint16 (Big Endian)
func (b *BytePacketBuffer) Readu16() (uint16, error) {
	if b.Pos+2 > MaxPacketSize {
		return 0, errors.New("end of buffer")
	}
	b1, _ := b.Read()
	b2, _ := b.Read()
	return uint16(b1)<<8 | uint16(b2), nil
}

// Readu32 reads 4 bytes as uint32 (Big Endian)
func (b *BytePacketBuffer) Readu32() (uint32, error) {
	if b.Pos+4 > MaxPacketSize {
		return 0, errors.New("end of buffer")
	}
	b1, _ := b.Read()
	b2, _ := b.Read()
	b3, _ := b.Read()
	b4, _ := b.Read()
	return uint32(b1)<<24 | uint32(b2)<<16 | uint32(b3)<<8 | uint32(b4), nil
}

// ReadName reads a domain name, handling compression
func (b *BytePacketBuffer) ReadName() (string, error) {
	pos := b.Pos
	jumped := false
	maxJumps := 5
	jumpsPerformed := 0

	delimiter := ""
	var out strings.Builder

	for {
		if jumpsPerformed > maxJumps {
			return "", errors.New("limit of jumps exceeded")
		}

		lenByte, err := b.Get(pos)
		if err != nil {
			return "", err
		}

		// End of labels
		if lenByte == 0 {
			pos++
			if !jumped {
				b.Seek(pos)
			}
			return out.String(), nil
		}

		// Compression pointer (11xxxxxx)
		if (lenByte & 0xC0) == 0xC0 {
			if !jumped {
				b.Seek(pos + 2)
			}
			b2, err := b.Get(pos + 1)
			if err != nil {
				return "", err
			}
			offset := ((uint16(lenByte) ^ 0xC0) << 8) | uint16(b2)
			pos = int(offset)
			jumped = true
			jumpsPerformed++
			continue
		}

		// Normal label
		pos++
		lenInt := int(lenByte)
		
		out.WriteString(delimiter)
		strBuffer, err := b.GetRange(pos, lenInt)
		if err != nil {
			return "", err
		}
		out.WriteString(strings.ToLower(string(strBuffer)))
		
		delimiter = "."
		pos += lenInt
	}
}

// Get reads a byte at a specific position without moving cursor
func (b *BytePacketBuffer) Get(pos int) (byte, error) {
	if pos >= MaxPacketSize {
		return 0, errors.New("end of buffer")
	}
	return b.Buf[pos], nil
}

// GetRange reads a range without moving cursor
func (b *BytePacketBuffer) GetRange(start int, length int) ([]byte, error) {
	if start+length > MaxPacketSize {
		return nil, errors.New("out of bounds")
	}
	return b.Buf[start : start+length], nil
}

// Write writes a single byte
func (b *BytePacketBuffer) Write(val byte) error {
	if b.Pos >= MaxPacketSize {
		return errors.New("end of buffer")
	}
	b.Buf[b.Pos] = val
	b.Pos++
	return nil
}

// Writeu16 writes a uint16
func (b *BytePacketBuffer) Writeu16(val uint16) error {
	if err := b.Write(byte(val >> 8)); err != nil {
		return err
	}
	return b.Write(byte(val & 0xFF))
}

// Writeu32 writes a uint32
func (b *BytePacketBuffer) Writeu32(val uint32) error {
	if err := b.Write(byte(val >> 24)); err != nil {
		return err
	}
	if err := b.Write(byte(val >> 16)); err != nil {
		return err
	}
	if err := b.Write(byte(val >> 8)); err != nil {
		return err
	}
	return b.Write(byte(val & 0xFF))
}

// WriteName writes a domain name (simple version, no compression yet)
func (b *BytePacketBuffer) WriteName(name string) error {
	parts := strings.Split(name, ".")
	for _, part := range parts {
		lenPart := len(part)
		if lenPart > 63 {
			return errors.New("label too long")
		}
		if lenPart == 0 {
			continue
		}
		if err := b.Write(byte(lenPart)); err != nil {
			return err
		}
		for i := 0; i < lenPart; i++ {
			if err := b.Write(part[i]); err != nil {
				return err
			}
		}
	}
	return b.Write(0)
}
