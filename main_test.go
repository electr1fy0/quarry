package main

import (
	"bytes"
	"testing"
)

// A captured response to an A query for example.com.
var exampleResp = []byte{
	// header: id, flags, qd=1, an=2, ns=0, ar=0
	0x2f, 0x3c, 0x81, 0x80, 0x00, 0x01, 0x00, 0x02, 0x00, 0x00, 0x00, 0x00,
	// question: example.com A IN
	0x07, 0x65, 0x78, 0x61, 0x6d, 0x70, 0x6c, 0x65, 0x03, 0x63, 0x6f, 0x6d, 0x00,
	0x00, 0x01, 0x00, 0x01,
	// answer 1: pointer to offset 12, A IN ttl 199, 104.20.23.154
	0xc0, 0x0c, 0x00, 0x01, 0x00, 0x01, 0x00, 0x00, 0x00, 0xc7, 0x00, 0x04, 0x68, 0x14, 0x17, 0x9a,
	// answer 2: pointer to offset 12, A IN ttl 199, 172.66.147.243
	0xc0, 0x0c, 0x00, 0x01, 0x00, 0x01, 0x00, 0x00, 0x00, 0xc7, 0x00, 0x04, 0xac, 0x42, 0x93, 0xf3,
}

func TestParseResponse(t *testing.T) {
	h, err := parseHeader(exampleResp)
	if err != nil {
		t.Fatal(err)
	}
	if h.ID != 0x2f3c || h.QDCount != 1 || h.ANCount != 2 {
		t.Fatalf("unexpected header: %+v", h)
	}

	q, off, err := parseQuestion(exampleResp, 12)
	if err != nil {
		t.Fatal(err)
	}
	if q != (Question{Name: "example.com.", Type: TypeA, Class: 1}) {
		t.Fatalf("unexpected question: %+v", q)
	}
	if off != 29 {
		t.Fatalf("question end offset = %d, want 29", off)
	}

	want := [][]byte{{104, 20, 23, 154}, {172, 66, 147, 243}}
	for i := 0; i < int(h.ANCount); i++ {
		var rr Record
		rr, off, err = parseRR(exampleResp, off)
		if err != nil {
			t.Fatal(err)
		}
		if rr.Name != "example.com." || rr.Type != TypeA || rr.Class != 1 || rr.TTL != 199 {
			t.Fatalf("unexpected record %d: %+v", i, rr)
		}
		if !bytes.Equal(rr.RData, want[i]) {
			t.Fatalf("record %d rdata = %v, want %v", i, rr.RData, want[i])
		}
		wantData := []string{"104.20.23.154", "172.66.147.243"}
		if rr.Data != wantData[i] {
			t.Fatalf("record %d data = %q, want %q", i, rr.Data, wantData[i])
		}
	}
	if off != len(exampleResp) {
		t.Fatalf("final offset = %d, want %d", off, len(exampleResp))
	}
}

func TestParseTruncated(t *testing.T) {
	// every cut of the message must return an error, never panic
	for n := 12; n < len(exampleResp); n++ {
		msg := exampleResp[:n]
		_, off, err := parseQuestion(msg, 12)
		if err != nil {
			continue
		}
		for off < len(msg) {
			_, off, err = parseRR(msg, off)
			if err != nil {
				break
			}
		}
	}
}

func TestDecodeNamePointerLoop(t *testing.T) {
	if _, _, err := decodeName([]byte{0xc0, 0x02, 0xc0, 0x00}, 0); err == nil {
		t.Fatal("expected error for pointer loop")
	}
}

// header + question "example.com" (offset 12), then caller appends records
func msgWithQuestion() []byte {
	msg := []byte{0, 1, 0x81, 0x80, 0, 1, 0, 1, 0, 0, 0, 0}
	msg = append(msg, 7, 'e', 'x', 'a', 'm', 'p', 'l', 'e', 3, 'c', 'o', 'm', 0)
	return append(msg, 0, 1, 0, 1)
}

func TestDecodeRData(t *testing.T) {
	// every record's name is c0 0c, a pointer to example.com at offset 12
	rec := func(typ byte, rdata ...byte) []byte {
		r := []byte{0xc0, 0x0c, 0, typ, 0, 1, 0, 0, 0, 60, 0, byte(len(rdata))}
		return append(r, rdata...)
	}

	tests := []struct {
		name  string
		rec   []byte
		want  string
		isErr bool
	}{
		{"AAAA", rec(28, 0x20, 0x01, 0x0d, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1), "2001:db8::1", false},
		// CNAME rdata is "www" followed by a pointer to example.com
		{"CNAME with pointer", rec(5, 3, 'w', 'w', 'w', 0xc0, 0x0c), "www.example.com.", false},
		{"NS", rec(2, 0xc0, 0x0c), "example.com.", false},
		// MX: preference 10, then "mail" + pointer to example.com
		{"MX", rec(15, 0, 10, 4, 'm', 'a', 'i', 'l', 0xc0, 0x0c), "10 mail.example.com.", false},
		{"unknown type keeps bytes", rec(99, 0xde, 0xad), "de ad", false},
		{"A wrong length", rec(1, 1, 2, 3), "", true},
		{"AAAA wrong length", rec(28, 1, 2, 3, 4), "", true},
		{"MX too short", rec(15, 0, 10), "", true},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			msg := append(msgWithQuestion(), tc.rec...)
			rr, off, err := parseRR(msg, 29)
			if tc.isErr {
				if err == nil {
					t.Fatalf("expected error, got %+v", rr)
				}
				return
			}
			if err != nil {
				t.Fatal(err)
			}
			if rr.Data != tc.want {
				t.Fatalf("data = %q, want %q", rr.Data, tc.want)
			}
			if off != len(msg) {
				t.Fatalf("end offset = %d, want %d", off, len(msg))
			}
		})
	}
}

func TestParseArgs(t *testing.T) {
	tests := []struct {
		name       string
		args       []string
		wantName   string
		wantType   uint16
		wantServer string
		isErr      bool
	}{
		{"name only", []string{"example.com"}, "example.com", TypeA, "1.1.1.1:53", false},
		{"with type", []string{"example.com", "MX"}, "example.com", TypeMX, "1.1.1.1:53", false},
		{"lowercase type", []string{"example.com", "aaaa"}, "example.com", TypeAAAA, "1.1.1.1:53", false},
		{"with server", []string{"example.com", "@8.8.8.8"}, "example.com", TypeA, "8.8.8.8:53", false},
		{"server with port", []string{"example.com", "@127.0.0.1:5353"}, "example.com", TypeA, "127.0.0.1:5353", false},
		{"ipv6 server", []string{"example.com", "@2606:4700:4700::1111"}, "example.com", TypeA, "[2606:4700:4700::1111]:53", false},
		{"any order", []string{"@9.9.9.9", "NS", "example.com"}, "example.com", TypeNS, "9.9.9.9:53", false},
		{"no args", nil, "", 0, "", true},
		{"only a type", []string{"MX"}, "", 0, "", true},
		{"two names", []string{"a.com", "b.com"}, "", 0, "", true},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			name, qtype, server, err := parseArgs(tc.args)
			if tc.isErr {
				if err == nil {
					t.Fatalf("expected error, got %q %d %q", name, qtype, server)
				}
				return
			}
			if err != nil {
				t.Fatal(err)
			}
			if name != tc.wantName || qtype != tc.wantType || server != tc.wantServer {
				t.Fatalf("got %q %d %q, want %q %d %q", name, qtype, server, tc.wantName, tc.wantType, tc.wantServer)
			}
		})
	}
}
