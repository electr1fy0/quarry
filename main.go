package main

import (
	"encoding/binary"
	"fmt"
	"math/rand/v2"
	"net"
	"strings"
	"time"
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

// func decodeName(msg []byte, off int) (string, int, error) {
// 	// length byte 0 ends the name
// 	// 0xc0 bits set means a pointer
// 	// anything else: normal label
//
// 	// returned offset is the one after the first pointer
// 	// also cap the jump cnt
//
// 	// for the example packet
// 	// at offset 12 it should return example.com. and next offset 25
// 	// at offset 29
// 	//
// }

type Header struct {
	ID      uint16
	Flags   uint16
	QDCount uint16
	ANCount uint16
	NSCount uint16
	ARCount uint16
}

func parseHeader(msg []byte) (Header, error) {
	// means no valid header since header of dns is 12 bytes
	if len(msg) < 12 {
		return Header{}, fmt.Errorf("message too short")
	}

	var h Header

	h.ID = binary.BigEndian.Uint16(msg[0:2])
	h.Flags = binary.BigEndian.Uint16(msg[2:4])
	h.QDCount = binary.BigEndian.Uint16(msg[4:6])
	h.ANCount = binary.BigEndian.Uint16(msg[6:8])
	h.NSCount = binary.BigEndian.Uint16(msg[8:10])
	h.ARCount = binary.BigEndian.Uint16(msg[10:12])

	return h, nil
}

// func parseRR(qname string, qtype uint16, qclass uint16, ttl int, rdlength) {
//
// }
// initial offset 12 ofc
func decodeName(msg []byte, off int) (string, int, error) {
	// labels are the text parts of a domain name
	var labels []string
	next := -1
	jumps := 0

	for {
		if off >= len(msg) {
			return "", 0, fmt.Errorf("offset is greater than the message length")
		}
		length := int(msg[off]) // read the length byte

		switch {
		// end of name
		case length == 0:
			off++
			if next == -1 {
				next = off
			}
			return strings.Join(labels, ".") + ".", next, nil

		case length&0xC0 == 0xc0: // pointer
			if off+1 >= len(msg) {
				return "", 0, fmt.Errorf("truncated pointer")
			}

			ptr := (length&0x3f)<<8 | int(msg[off+1])
			if next == -1 {
				next = off + 2
			}
			jumps++
			if jumps > 10 {
				return "", 0, fmt.Errorf("too many pointer jumps")
			}
			off = ptr

		case length&0xc0 != 0: // 01 or 10 prefix: not allowed
			return "", 0, fmt.Errorf("bad label prefix")

		default:
			off++
			if off+length > len(msg) {
				return "", 0, fmt.Errorf("label runs past end of message")
			}
			labels = append(labels, string(msg[off:off+length]))
			off += length
		}
	}
}

func parseQuestion(qname string, qtype uint16, qclass uint16) {

}

func main() {
	conn, err := net.Dial("udp", "1.1.1.1:53")
	if err := conn.SetDeadline(time.Now().Add(time.Second * 2)); err != nil {
		fmt.Println("failed to set deadline:", err)
		return
	}

	defer conn.Close()

	header, _, err := NewQuery("example.com", TypeA, true)
	if err != nil {
		fmt.Printf("failed to create query: %v", err)
		return
	}

	conn.Write(header)

	buf := make([]byte, 4096)
	n, err := conn.Read(buf)
	resp := buf[:n]

	fmt.Printf("% x\n", header)
	fmt.Printf("% x\n", resp)

	// res := []byte{
	// 	0x2f, 0x3c, 0x81, 0x80, 0x00, 0x01, 0x00, 0x02, 0x00, 0x00, 0x00, 0x00,
	// 	0x07, 0x65, 0x78, 0x61, 0x6d, 0x70, 0x6c, 0x65, 0x03, 0x63, 0x6f, 0x6d, 0x00,
	// 	0x00, 0x01, 0x00, 0x01,
	// 	0xc0, 0x0c, 0x00, 0x01, 0x00, 0x01, 0x00, 0x00, 0x00, 0xc7, 0x00, 0x04, 0x68, 0x14, 0x17, 0x9a,
	// 	0xc0, 0x0c, 0x00, 0x01, 0x00, 0x01, 0x00, 0x00, 0x00, 0xc7, 0x00, 0x04, 0xac, 0x42, 0x93, 0xf3,
	// } // h, _ := parseHeader(res)
	// fmt.Printf("%+v\n", h)
	// bad := []byte{0xc0, 0x00}
	// name, next, err := decodeName(bad, 0)
	// fmt.Printf("%q %d %v\n", name, next, err)
	// "" 0 too many pointer jumps
	//
	// name, _, err := decodeName(res, 27)
	bad2 := []byte{0xc0, 0x02, 0xc0, 0x00}
	_, _, err = decodeName(bad2, 0)
	fmt.Println(err) // too many pointer jumps
	// fmt.Println(name)
}
