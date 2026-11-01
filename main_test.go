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
