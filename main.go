package main

import (
	"encoding/binary"
	"fmt"
	"math/rand/v2"
	"net"
	"os"
	"strings"
	"time"
)

// Everything is big endian.
//
// DNS message:
//   Header:     12 bytes
//   Questions:  QDCOUNT entries
//   Answers:    ANCOUNT resource records
//   Authority:  NSCOUNT resource records
//   Additional: ARCOUNT resource records
//
// Header (6 x uint16): ID | Flags | QDCOUNT | ANCOUNT | NSCOUNT | ARCOUNT
// Flags: QR(1) OPCODE(4) AA(1) TC(1) RD(1) RA(1) Z(3) RCODE(4)
//   QR 0 = query, 1 = response; AA = authoritative answer
//   TC = truncated; RD = recursion desired; RA = recursion available
//   RCODE 0 = success, 3 = NXDOMAIN
//
// Question: QNAME | QTYPE (2) | QCLASS (2)
// Resource record: NAME | TYPE (2) | CLASS (2) | TTL (4) | RDLENGTH (2) | RDATA

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

	msg := make([]byte, 12, 512)

	binary.BigEndian.PutUint16(msg[0:2], id)

	var flags uint16
	if recurse {
		flags = flagRD
	}
	binary.BigEndian.PutUint16(msg[2:4], flags)

	// qdcount: one question. Bytes 6-11 (an/ns/ar counts) stay 0.
	binary.BigEndian.PutUint16(msg[4:6], 1) // rd flag set

	// question: qname, qtype, qclass
	msg = append(msg, encodedName...)
	msg = binary.BigEndian.AppendUint16(msg, qtype)
	msg = binary.BigEndian.AppendUint16(msg, 1) // IN (internet)

	return msg, id, nil
}

// human-readable name into dns wire format: len label len label 0
// allowed: meow.example.com, ".", ""
// not allowed: a..b
func encodeName(name string) ([]byte, error) {
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

type Header struct {
	ID      uint16
	Flags   uint16
	QDCount uint16
	ANCount uint16
	NSCount uint16
	ARCount uint16
}

func parseHeader(msg []byte) (Header, error) {
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

// decodeName reads a (possibly compressed) name starting at off.
// It returns the name and the offset of the first byte after the name
// in the original position, i.e. not wherever a pointer sent us.
func decodeName(msg []byte, off int) (string, int, error) {
	var labels []string
	next := -1
	jumps := 0

	for {
		if off >= len(msg) {
			return "", 0, fmt.Errorf("offset is greater than the message length")
		}
		length := int(msg[off])

		switch {
		// end of name
		case length == 0:
			off++
			if next == -1 {
				next = off
			}
			return strings.Join(labels, ".") + ".", next, nil

		case length&0xC0 == 0xC0: // pointer
			if off+1 >= len(msg) {
				return "", 0, fmt.Errorf("truncated pointer")
			}

			ptr := (length&0x3F)<<8 | int(msg[off+1])
			if next == -1 {
				next = off + 2
			}
			jumps++
			if jumps > 10 {
				return "", 0, fmt.Errorf("too many pointer jumps")
			}
			off = ptr

		case length&0xC0 != 0: // 01 or 10 prefix: not allowed
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

type Question struct {
	Name  string
	Type  uint16
	Class uint16
}

// parseQuestion reads one question starting at off and returns it along
// with the offset of the byte after it.
func parseQuestion(msg []byte, off int) (Question, int, error) {
	name, off, err := decodeName(msg, off)
	if err != nil {
		return Question{}, 0, fmt.Errorf("question name: %w", err)
	}

	// qtype + qclass = 4 bytes
	if off+4 > len(msg) {
		return Question{}, 0, fmt.Errorf("question truncated")
	}

	q := Question{
		Name:  name,
		Type:  binary.BigEndian.Uint16(msg[off : off+2]),
		Class: binary.BigEndian.Uint16(msg[off+2 : off+4]),
	}
	return q, off + 4, nil
}

type Record struct {
	Name  string
	Type  uint16
	Class uint16
	TTL   uint32
	RData []byte // raw bytes as they came off the wire
	Data  string // RData decoded to readable form, depending on Type
}

func typeName(t uint16) string {
	switch t {
	case TypeA:
		return "A"
	case TypeNS:
		return "NS"
	case TypeCNAME:
		return "CNAME"
	case TypeMX:
		return "MX"
	case TypeAAAA:
		return "AAAA"
	}
	return fmt.Sprintf("TYPE%d", t)
}

// decodeRData turns the rdlen bytes of rdata at msg[off:] into readable text.
// It takes the whole message, not just the rdata slice, because names inside
// rdata (NS, CNAME, MX) may be compression pointers back into the message.
func decodeRData(msg []byte, typ uint16, off, rdlen int) (string, error) {
	end := off + rdlen

	switch typ {
	case TypeA:
		if rdlen != 4 {
			return "", fmt.Errorf("A rdata is %d bytes, want 4", rdlen)
		}
		return net.IP(msg[off:end]).String(), nil

	case TypeAAAA:
		if rdlen != 16 {
			return "", fmt.Errorf("AAAA rdata is %d bytes, want 16", rdlen)
		}
		return net.IP(msg[off:end]).String(), nil

	case TypeNS, TypeCNAME:
		name, next, err := decodeName(msg, off)
		if err != nil {
			return "", err
		}
		if next > end {
			return "", fmt.Errorf("name runs past end of rdata")
		}
		return name, nil

	case TypeMX:
		// preference (2 bytes), then the mail server's name
		if rdlen < 3 {
			return "", fmt.Errorf("MX rdata too short")
		}
		pref := binary.BigEndian.Uint16(msg[off : off+2])
		name, next, err := decodeName(msg, off+2)
		if err != nil {
			return "", err
		}
		if next > end {
			return "", fmt.Errorf("name runs past end of rdata")
		}
		return fmt.Sprintf("%d %s", pref, name), nil
	}

	// unknown type: keep the bytes visible instead of failing
	return fmt.Sprintf("% x", msg[off:end]), nil
}

// parseRR reads one resource record starting at off and returns it along
// with the offset of the byte after it.
func parseRR(msg []byte, off int) (Record, int, error) {
	name, off, err := decodeName(msg, off)
	if err != nil {
		return Record{}, 0, fmt.Errorf("record name: %w", err)
	}

	// type(2) + class(2) + ttl(4) + rdlength(2) = 10 fixed bytes
	if off+10 > len(msg) {
		return Record{}, 0, fmt.Errorf("record header truncated")
	}

	rr := Record{
		Name:  name,
		Type:  binary.BigEndian.Uint16(msg[off : off+2]),
		Class: binary.BigEndian.Uint16(msg[off+2 : off+4]),
		TTL:   binary.BigEndian.Uint32(msg[off+4 : off+8]),
	}
	rdlen := int(binary.BigEndian.Uint16(msg[off+8 : off+10]))
	off += 10

	if off+rdlen > len(msg) {
		return Record{}, 0, fmt.Errorf("rdata runs past end of message")
	}
	rr.RData = msg[off : off+rdlen]

	rr.Data, err = decodeRData(msg, rr.Type, off, rdlen)
	if err != nil {
		return Record{}, 0, fmt.Errorf("%s rdata: %w", typeName(rr.Type), err)
	}

	// always trust rdlen for where the next record starts
	return rr, off + rdlen, nil
}

const usage = "usage: quarry <name> [A|AAAA|NS|CNAME|MX] [@server]"

var typeNums = map[string]uint16{
	"A":     TypeA,
	"NS":    TypeNS,
	"CNAME": TypeCNAME,
	"MX":    TypeMX,
	"AAAA":  TypeAAAA,
}

// parseArgs understands: quarry <name> [TYPE] [@server]
// The type and server are optional and may come in any order.
func parseArgs(args []string) (name string, qtype uint16, server string, err error) {
	qtype = TypeA
	server = "1.1.1.1"

	for _, a := range args {
		if s, ok := strings.CutPrefix(a, "@"); ok {
			server = s
		} else if t, ok := typeNums[strings.ToUpper(a)]; ok {
			qtype = t
		} else if name == "" {
			name = a
		} else {
			return "", 0, "", fmt.Errorf("unexpected argument %q", a)
		}
	}

	if name == "" {
		return "", 0, "", fmt.Errorf("missing name")
	}

	// no port given: use the standard DNS port
	if _, _, err := net.SplitHostPort(server); err != nil {
		server = net.JoinHostPort(server, "53")
	}
	return name, qtype, server, nil
}

func run(name string, qtype uint16, server string) error {
	conn, err := net.Dial("udp", server)
	if err != nil {
		return fmt.Errorf("dial: %w", err)
	}
	defer conn.Close()

	if err := conn.SetDeadline(time.Now().Add(2 * time.Second)); err != nil {
		return fmt.Errorf("set deadline: %w", err)
	}

	query, _, err := NewQuery(name, qtype, true)
	if err != nil {
		return err
	}

	if _, err := conn.Write(query); err != nil {
		return fmt.Errorf("send query: %w", err)
	}

	buf := make([]byte, 4096)
	n, err := conn.Read(buf)
	if err != nil {
		return fmt.Errorf("read response: %w", err)
	}
	resp := buf[:n]

	h, err := parseHeader(resp)
	if err != nil {
		return fmt.Errorf("header: %w", err)
	}

	// skip past the question(s) to reach the answers
	off := 12
	for i := 0; i < int(h.QDCount); i++ {
		_, off, err = parseQuestion(resp, off)
		if err != nil {
			return fmt.Errorf("question: %w", err)
		}
	}

	if h.ANCount == 0 {
		fmt.Fprintf(os.Stderr, "no answers (rcode %d)\n", h.Flags&0xF)
		return nil
	}

	for i := 0; i < int(h.ANCount); i++ {
		var rr Record
		rr, off, err = parseRR(resp, off)
		if err != nil {
			return fmt.Errorf("answer: %w", err)
		}
		fmt.Printf("%s\t%d\t%s\t%s\n", rr.Name, rr.TTL, typeName(rr.Type), rr.Data)
	}
	return nil
}

func main() {
	name, qtype, server, err := parseArgs(os.Args[1:])
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		fmt.Fprintln(os.Stderr, usage)
		os.Exit(2)
	}

	if err := run(name, qtype, server); err != nil {
		fmt.Fprintln(os.Stderr, "quarry:", err)
		os.Exit(1)
	}
}
