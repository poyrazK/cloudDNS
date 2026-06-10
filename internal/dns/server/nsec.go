package server

import (
	"bytes"
	"context"
	"fmt"
	"sort"
	"strings"

	"github.com/poyrazK/cloudDNS/internal/core/domain"
	"github.com/poyrazK/cloudDNS/internal/dns/master"
	"github.com/poyrazK/cloudDNS/internal/dns/packet"
)

// generateNSEC creates an NSEC record proving no records exist for a name (DNSSEC).
func (s *Server) generateNSEC(ctx context.Context, zone *domain.Zone, queryName string) (packet.DNSRecord, error) {
	iter, errZoneRecs := s.Repo.ListRecordsForZoneStreaming(ctx, zone.ID, zone.TenantID)
	if errZoneRecs != nil {
		return packet.DNSRecord{}, errZoneRecs
	}
	defer func() { _ = iter.Close() }()

	nameToTypes := make(map[string][]domain.RecordType)
	var uniqueNames []string
	seen := make(map[string]bool)
	for iter.Next() {
		r := iter.Record()
		if !seen[r.Name] {
			uniqueNames = append(uniqueNames, r.Name)
			seen[r.Name] = true
		}
		nameToTypes[r.Name] = append(nameToTypes[r.Name], r.Type)
	}
	if err := iter.Err(); err != nil {
		return packet.DNSRecord{}, err
	}

	if len(uniqueNames) == 0 {
		return packet.DNSRecord{}, fmt.Errorf("no records in zone")
	}

	sort.Slice(uniqueNames, func(i, j int) bool {
		return master.CompareNamesCanonically(uniqueNames[i], uniqueNames[j]) < 0
	})

	var ownerName, nextName string
	found := false
	for i := 0; i < len(uniqueNames); i++ {
		cmp := master.CompareNamesCanonically(queryName, uniqueNames[i])
		if cmp < 0 {
			if i == 0 {
				ownerName = uniqueNames[len(uniqueNames)-1]
				nextName = uniqueNames[0]
			} else {
				ownerName = uniqueNames[i-1]
				nextName = uniqueNames[i]
			}
			found = true
			break
		}
		if cmp == 0 {
			ownerName = uniqueNames[i]
			if i == len(uniqueNames)-1 {
				nextName = uniqueNames[0]
			} else {
				nextName = uniqueNames[i+1]
			}
			found = true
			break
		}
	}

	if !found {
		ownerName = uniqueNames[len(uniqueNames)-1]
		nextName = uniqueNames[0]
	}

	types := nameToTypes[ownerName]
	types = append(types, "NSEC")
	bitmap := s.generateTypeBitMap(types)

	nsec := packet.DNSRecord{
		Name:       ownerName,
		Type:       packet.NSEC,
		Class:      1,
		TTL:        300,
		NextName:   nextName,
		TypeBitMap: bitmap,
	}

	return nsec, nil
}

// generateNSEC3 creates an NSEC3 record for a query name (DNSSEC with NSEC3).
func (s *Server) generateNSEC3(ctx context.Context, zone *domain.Zone, queryName string, wildcardName string) (packet.DNSRecord, error) {
	params, errParams := s.Repo.GetRecords(ctx, zone.Name, "NSEC3PARAM", "")
	if errParams != nil || len(params) == 0 {
		return packet.DNSRecord{}, fmt.Errorf("no NSEC3PARAM")
	}

	parts := strings.Fields(params[0].Content)
	if len(parts) < 4 {
		return packet.DNSRecord{}, fmt.Errorf("invalid NSEC3PARAM")
	}

	var alg, flags uint8
	var iterations uint16
	_, _ = fmt.Sscanf(parts[0], "%d", &alg)
	_, _ = fmt.Sscanf(parts[1], "%d", &flags)
	_, _ = fmt.Sscanf(parts[2], "%d", &iterations)
	salt := parts[3]
	if salt == "-" {
		salt = ""
	}

	iter, errIter := s.Repo.ListRecordsForZoneStreaming(ctx, zone.ID, zone.TenantID)
	if errIter != nil {
		return packet.DNSRecord{}, errIter
	}
	defer func() { _ = iter.Close() }()

	nameToTypes := make(map[string][]domain.RecordType)
	var ownerNames []string
	seen := make(map[string]bool)
	for iter.Next() {
		r := iter.Record()
		if !seen[r.Name] {
			ownerNames = append(ownerNames, r.Name)
			seen[r.Name] = true
		}
		nameToTypes[r.Name] = append(nameToTypes[r.Name], r.Type)
	}
	if err := iter.Err(); err != nil {
		return packet.DNSRecord{}, err
	}

	saltBytes := []byte(salt)
	hashes := make([]hashEntry, 0, len(ownerNames))
	for _, name := range ownerNames {
		h := packet.HashName(name, alg, iterations, saltBytes)
		hashes = append(hashes, hashEntry{name: name, hash: h})
	}

	if len(hashes) == 0 {
		return packet.DNSRecord{}, fmt.Errorf("no records to hash for NSEC3")
	}

	sort.Slice(hashes, func(i, j int) bool {
		return bytes.Compare(hashes[i].hash, hashes[j].hash) < 0
	})

	// If wildcardName is provided, generate NSEC3 for wildcard proof
	if wildcardName != "" {
		return s.generateNSEC3ForWildcardProof(ctx, zone, wildcardName, queryName, alg, iterations, flags, saltBytes, hashes, nameToTypes)
	}

	qHash := packet.HashName(queryName, alg, iterations, saltBytes)
	var ownerEntry, nextEntry hashEntry
	found := false
	for i := 0; i < len(hashes); i++ {
		cmp := bytes.Compare(qHash, hashes[i].hash)
		if cmp < 0 {
			if i == 0 {
				ownerEntry = hashes[len(hashes)-1]
				nextEntry = hashes[0]
			} else {
				ownerEntry = hashes[i-1]
				nextEntry = hashes[i]
			}
			found = true
			break
		}
		if cmp == 0 {
			ownerEntry = hashes[i]
			if i == len(hashes)-1 {
				nextEntry = hashes[0]
			} else {
				nextEntry = hashes[i+1]
			}
			found = true
			break
		}
	}
	if !found {
		ownerEntry = hashes[len(hashes)-1]
		nextEntry = hashes[0]
	}

	types := nameToTypes[ownerEntry.name]
	types = append(types, "NSEC3")
	bitmap := s.generateTypeBitMap(types)

	nsec3 := packet.DNSRecord{
		Name:       packet.Base32Encode(ownerEntry.hash) + "." + zone.Name,
		Type:       packet.NSEC3,
		Class:      1,
		TTL:        300,
		HashAlg:    alg,
		Flags:      uint16(flags),
		Iterations: iterations,
		Salt:       saltBytes,
		NextHash:   nextEntry.hash,
		TypeBitMap: bitmap,
	}

	return nsec3, nil
}

// generateNSEC3ForWildcardProof generates an NSEC3 record proving a wildcard match.
// Per RFC 5155 Section 7.2.14, the NSEC3 proves that the wildcard RRset exists.
func (s *Server) generateNSEC3ForWildcardProof(_ context.Context, zone *domain.Zone, wildcardName, _ string, alg uint8, iterations uint16, flags uint8, salt []byte, hashes []hashEntry, nameToTypes map[string][]domain.RecordType) (packet.DNSRecord, error) {
	// Hash the wildcard name
	wildcardHash := packet.HashName(wildcardName, alg, iterations, salt)

	// Find the wildcard hash in the chain and get next hash
	var nextEntry hashEntry
	wildcardIdx := -1
	for i, h := range hashes {
		if bytes.Equal(h.hash, wildcardHash) {
			wildcardIdx = i
			break
		}
	}

	if wildcardIdx == -1 {
		return packet.DNSRecord{}, fmt.Errorf("wildcard hash not found in NSEC3 chain")
	}

	// Next hash in the chain
	if wildcardIdx == len(hashes)-1 {
		nextEntry = hashes[0]
	} else {
		nextEntry = hashes[wildcardIdx+1]
	}

	// Get types from wildcard record and add the query type
	types := nameToTypes[wildcardName]
	types = append(types, "NSEC3")
	bitmap := s.generateTypeBitMap(types)

	nsec3 := packet.DNSRecord{
		Name:       packet.Base32Encode(wildcardHash) + "." + zone.Name,
		Type:       packet.NSEC3,
		Class:      1,
		TTL:        300,
		HashAlg:    alg,
		Flags:      uint16(flags),
		Iterations: iterations,
		Salt:       salt,
		NextHash:   nextEntry.hash,
		TypeBitMap: bitmap,
	}

	return nsec3, nil
}

// generateTypeBitMap creates the NSEC3 type bitmap window blocks.
func (s *Server) generateTypeBitMap(types []domain.RecordType) []byte {
	bits := make([]byte, 32)
	maxType := 0
	for _, t := range types {
		qt := master.RecordTypeToQueryType(t)
		if qt == 0 {
			if t == "NSEC" {
				qt = 47
			}
			if t == "NSEC3" {
				qt = 50
			}
		}
		if qt == 0 || qt > 255 {
			continue
		}

		byteIdx := qt / 8
		bitIdx := 7 - (qt % 8)
		bits[byteIdx] |= (1 << bitIdx)
		if int(byteIdx) > maxType {
			maxType = int(byteIdx)
		}
	}

	res := make([]byte, 0, 2+(maxType+1))
	res = append(res, 0, byte(maxType+1))
	res = append(res, bits[:maxType+1]...)
	return res
}
