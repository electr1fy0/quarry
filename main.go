package main

import (
	"encoding/binary"
	"fmt"
	"math/rand/v2"
	"strings"
	"uuid"
)

// Everything is big endian
// Header (12 bytes): 6 uint16
// ID (verify req and resp id) |
// Flags (QR 1 OPCODE 4 AA 1 TC 1 RD 1 RA 1 ZZZ 3 RCODE 4)
// qr 0 is query 1 is response aa is authoritative answer
// tc is response was truncated, rd is recursion desired
// ra is server supports recursion rcode 0 is success, 3 = nxdomain |
// QDCOUNT | ANCOUNT | NSCOUNT | ARCOUNT
// DNS Packet structure:
// Header: 12 bytes
// Questions: QDCOUNT
// Answers: ANCOUNT
// Authority: NSCOUNT
// Additional: ARCOUNT

type Query struct {
	Header   []uint16 //
	Question string
	// Name     string
	ID uuid.UUID
}

const (
	TypeA     = 1
	TypeNS    = 2
	TypeCNAME = 5
	TypeMX    = 15
	TypeAAAA  = 28
	flagRD    = 0x0100
)

func NewQuery(name string, qtype uint16, recurse bool) ([]byte, uint16, error) {
	encodedName, err := encodeName(name)
	if err != nil {
		return nil, 0, fmt.Errorf("failed to encode name: %w", err)
	}

	id := uint16(rand.Uint32())

	header := make([]byte, 12, 512)

	// id
	binary.BigEndian.PutUint16(header[0:2], id)

	// flags: 0x100 if recurse, else 0
	var flag uint16
	if recurse {
		flag = 0x100
	} else {
		flag = 0
	}
	binary.BigEndian.PutUint16(header[2:4], flag)

	// qdcount
	binary.BigEndian.PutUint16(header[4:6], 1)

	// now we dont give a fuck about 6-11 bytes rn
	// bytes 6-11 left as 0 (no answer, authority, additional records)
	// header is finished here
	// TODO: rename header var to msg

	// now we append the question: qname, qtype, qclass

	// this is variable size
	header = append(header, encodedName...)

	header = binary.BigEndian.AppendUint16(header, uint16(qtype))

	// almost always a 1. IN for internet
	header = binary.BigEndian.AppendUint16(header, uint16(1))

	return header, id, nil
}

// human-readable name into dns wire format: len label len label 0
// allowed: meow.example.com, ".", ""
// not allowed: a..b
func encodeName(name string) ([]byte, error) {
	// reject empty labels and labels over 63 bytes

	name = strings.TrimSuffix(name, ".")
	if name == "" {
		return []byte{0}, nil
	}

	parts := strings.Split(name, ".")
	result := make([]byte, 0, 256)

	for _, part := range parts {
		if part == "" {
			return nil, fmt.Errorf("empty label in %q", name)
		}

		if len(part) > 63 {
			return nil, fmt.Errorf("label %q exceeds 63 bytes", part)
		}

		result = append(result, byte(len(part)))
		result = append(result, part...)
	}

	result = append(result, byte(0))

	if len(result) > 255 {
		return nil, fmt.Errorf("name too large")
	}
	return result, nil
}

func main() {
	header, _, err := NewQuery("example.com", TypeA, true)
	if err != nil {
		fmt.Printf("failed to create query: %v", err)
		return
	}

	fmt.Printf("% x\n", header)
}
