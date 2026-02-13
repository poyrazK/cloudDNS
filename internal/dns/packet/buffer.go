package packet

import (
	"errors"
	"strings"
	"sync"
)

// BytePacketBuffer simplifies reading and writing the DNS packet buffer
type BytePacketBuffer struct {
	Buf      []byte
	Pos      int
	names    map[string]int // For Name Compression
	HasNames bool           // Enable/Disable name compression tracking
}

const MaxPacketSize = 65535

var bufferPool = sync.Pool{
	New: func() interface{} {
		return &BytePacketBuffer{
			Buf: make([]byte, MaxPacketSize),
			Pos: 0,
		}
	},
}

// GetBuffer retrieves a buffer from the pool
func GetBuffer() *BytePacketBuffer {
	b := bufferPool.Get().(*BytePacketBuffer)
	b.Reset()
	return b
}

// PutBuffer returns a buffer to the pool
func PutBuffer(b *BytePacketBuffer) {
	bufferPool.Put(b)
}

func (b *BytePacketBuffer) Reset() {
	b.Pos = 0
	if b.names == nil {
		b.names = make(map[string]int)
	} else {
		clear(b.names)
	}
	b.HasNames = false
}

func NewBytePacketBuffer() *BytePacketBuffer {
	return &BytePacketBuffer{
		Buf:   make([]byte, MaxPacketSize),
		Pos:   0,
		names: make(map[string]int),
	}
}

func (b *BytePacketBuffer) Load(data []byte) {
	copy(b.Buf, data)
	b.Pos = 0
	if b.names == nil {
		b.names = make(map[string]int)
	} else {
		clear(b.names)
	}
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
	b1 := b.Buf[b.Pos]
	b2 := b.Buf[b.Pos+1]
	b.Pos += 2
	return uint16(b1)<<8 | uint16(b2), nil
}

// Readu32 reads 4 bytes as uint32 (Big Endian)
func (b *BytePacketBuffer) Readu32() (uint32, error) {
	if b.Pos+4 > MaxPacketSize {
		return 0, errors.New("end of buffer")
	}
	b1 := b.Buf[b.Pos]
	b2 := b.Buf[b.Pos+1]
	b3 := b.Buf[b.Pos+2]
	b4 := b.Buf[b.Pos+3]
	b.Pos += 4
	return uint32(b1)<<24 | uint32(b2)<<16 | uint32(b3)<<8 | uint32(b4), nil
}

// ReadName reads a domain name, handling compression
func (b *BytePacketBuffer) ReadName() (string, error) {
	pos := b.Pos
	jumped := false
	maxJumps := 5
	jumpsPerformed := 0

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
			res := out.String()
			if res == "" { return ".", nil }
			return res, nil
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
		
		if pos+lenInt > MaxPacketSize {
			return "", errors.New("out of bounds")
		}
		label := b.Buf[pos : pos+lenInt]
		for _, char := range label {
			if char >= 'A' && char <= 'Z' {
				out.WriteByte(char + 32) // tolower
			} else {
				out.WriteByte(char)
			}
		}
		out.WriteByte('.')
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
	if b.Pos+2 > MaxPacketSize {
		return errors.New("end of buffer")
	}
	b.Buf[b.Pos] = byte(val >> 8)
	b.Buf[b.Pos+1] = byte(val & 0xFF)
	b.Pos += 2
	return nil
}

// Writeu32 writes a uint32
func (b *BytePacketBuffer) Writeu32(val uint32) error {
	if b.Pos+4 > MaxPacketSize {
		return errors.New("end of buffer")
	}
	b.Buf[b.Pos] = byte(val >> 24)
	b.Buf[b.Pos+1] = byte(val >> 16)
	b.Buf[b.Pos+2] = byte(val >> 8)
	b.Buf[b.Pos+3] = byte(val & 0xFF)
	b.Pos += 4
	return nil
}

// WriteName writes a domain name with compression support
func (b *BytePacketBuffer) WriteName(name string) error {
	if name == "" || name == "." {
		return b.Write(0)
	}

	// Standardize: ensure name ends with a dot
	if !strings.HasSuffix(name, ".") {
		name += "."
	}

	curr := name
	for {
		if curr == "" || curr == "." {
			return b.Write(0)
		}

		if b.HasNames {
			lower := strings.ToLower(curr)
			if pos, ok := b.names[lower]; ok {
				return b.Writeu16(uint16(pos) | 0xC000)
			}
			if b.Pos < 0x4000 {
				b.names[lower] = b.Pos
			}
		}

		dotIdx := strings.IndexByte(curr, '.')
		if dotIdx == -1 { break }

		label := curr[:dotIdx]
		if len(label) > 63 {
			return errors.New("label too long")
		}
		if len(label) > 0 {
			if err := b.Write(byte(len(label))); err != nil { return err }
			for i := 0; i < len(label); i++ {
				if err := b.Write(label[i]); err != nil { return err }
			}
		}
		curr = curr[dotIdx+1:]
	}
	return nil
}

// WriteRange writes a slice of bytes at a specific position
func (b *BytePacketBuffer) WriteRange(start int, data []byte) error {
	if start+len(data) > MaxPacketSize {
		return errors.New("out of bounds")
	}
	copy(b.Buf[start:start+len(data)], data)
	if start+len(data) > b.Pos {
		b.Pos = start + len(data)
	}
	return nil
}
