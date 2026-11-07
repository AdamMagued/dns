package dns

// Tests that solve that an specific issue.

import (
	"bytes"
	"encoding/binary"
	"strings"
	"testing"
)

func TestNSEC3MissingSalt(t *testing.T) {
	rr := testRR("ji6neoaepv8b5o6k4ev33abha8ht9fgc.example. NSEC3 1 1 12 aabbccdd K8UDEMVP1J2F7EG6JEBPS17VP3N8I58H")
	m := new(Msg)
	m.Answer = []RR{rr}
	mb, err := m.Pack()
	if err != nil {
		t.Fatalf("expected to pack message. err: %s", err)
	}
	if err := m.Unpack(mb); err != nil {
		t.Fatalf("expected to unpack message. missing salt? err: %s", err)
	}
	in := rr.(*NSEC3).Salt
	out := m.Answer[0].(*NSEC3).Salt
	if in != out {
		t.Fatalf("expected salts to match. packed: `%s`. returned: `%s`", in, out)
	}
}

func TestNSEC3MixedNextDomain(t *testing.T) {
	rr := testRR("ji6neoaepv8b5o6k4ev33abha8ht9fgc.example. NSEC3 1 1 12 - k8udemvp1j2f7eg6jebps17vp3n8i58h")
	m := new(Msg)
	m.Answer = []RR{rr}
	mb, err := m.Pack()
	if err != nil {
		t.Fatalf("expected to pack message. err: %s", err)
	}
	if err := m.Unpack(mb); err != nil {
		t.Fatalf("expected to unpack message. err: %s", err)
	}
	in := strings.ToUpper(rr.(*NSEC3).NextDomain)
	out := m.Answer[0].(*NSEC3).NextDomain
	if in != out {
		t.Fatalf("expected round trip to produce NextDomain `%s`, instead `%s`", in, out)
	}
}

func buildWireCAA(tag string, val []byte) []byte {
	req := new(Msg)
	req.SetQuestion("example.com.", TypeCAA)
	hdr, _ := req.Pack()
	hdr[2] = 0x84                           // QR=1, AA=1
	binary.BigEndian.PutUint16(hdr[6:8], 1) // ANCOUNT=1

	var rr bytes.Buffer
	rr.Write([]byte{0xc0, 0x0c}) // owner: example.com.
	binary.Write(&rr, binary.BigEndian, uint16(TypeCAA))
	binary.Write(&rr, binary.BigEndian, uint16(ClassINET))
	binary.Write(&rr, binary.BigEndian, uint32(60))
	binary.Write(&rr, binary.BigEndian, uint16(1+1+len(tag)+len(val)))
	rr.WriteByte(0) // Flag
	rr.WriteByte(byte(len(tag)))
	rr.WriteString(tag)
	rr.Write(val)
	return append(hdr, rr.Bytes()...)
}

func TestIssue1735_CAAUnpackPackBackslash(t *testing.T) {
	testCases := [][]byte{
		{0x01, 0x5c, 'a', 0x5c, '1', '2', '3', 0x02},
		{'\\', '\\', '\\'},
		{'"', 0x00, '\\', 0xff, '"'},
		{'a', 'b', 'c', '\\'},
		{},
		{0x5c},
		{0x5c, 'a'},
		{0x5c, '1', '2', '3'},
	}

	for _, orig := range testCases {
		wire := buildWireCAA("issue", orig)
		m := new(Msg)
		m.Compress = true
		if err := m.Unpack(wire); err != nil {
			t.Fatalf("Unpack failed for orig %x: %v", orig, err)
		}
		if len(m.Answer) != 1 {
			t.Fatalf("expected 1 answer for orig %x, got %d", orig, len(m.Answer))
		}

		repacked, err := m.Pack()
		if err != nil {
			t.Fatalf("Pack failed for orig %x: %v", orig, err)
		}
		if !bytes.Equal(wire, repacked) {
			t.Fatalf("wire mismatch for orig %x:\ngot:  %x\nwant: %x", orig, repacked, wire)
		}

		m2 := new(Msg)
		if err := m2.Unpack(repacked); err != nil {
			t.Fatalf("second Unpack failed for orig %x: %v", orig, err)
		}
		c1 := m.Answer[0].(*CAA)
		c2 := m2.Answer[0].(*CAA)
		if c1.Value != c2.Value {
			t.Fatalf("CAA value mismatch: %q vs %q", c1.Value, c2.Value)
		}

		// Verify zonefile String() and NewRR roundtrip
		str := c1.String()
		rr, err := NewRR(str)
		if err != nil {
			t.Fatalf("NewRR failed for %s: %v", str, err)
		}
		cParsed := rr.(*CAA)
		if cParsed.Value != c1.Value {
			t.Fatalf("parsed value mismatch: %q vs %q", cParsed.Value, c1.Value)
		}
	}
}

func TestIssue1735_CAALargeValue(t *testing.T) {
	sizes := []int{1026, 1100, 2048, 4096}
	for _, sz := range sizes {
		orig := bytes.Repeat([]byte{'A'}, sz)
		wire := buildWireCAA("issue", orig)

		m := new(Msg)
		m.Compress = true
		if err := m.Unpack(wire); err != nil {
			t.Fatalf("Unpack(%d bytes) failed: %v", sz, err)
		}

		repacked, err := m.Pack()
		if err != nil {
			t.Fatalf("Pack(%d bytes) failed: %v", sz, err)
		}
		if !bytes.Equal(wire, repacked) {
			t.Fatalf("wire mismatch for size %d", sz)
		}

		m2 := new(Msg)
		if err := m2.Unpack(repacked); err != nil {
			t.Fatalf("second Unpack(%d bytes) failed: %v", sz, err)
		}
		c := m2.Answer[0].(*CAA)
		if len(c.Value) != sz {
			t.Fatalf("expected value length %d, got %d", sz, len(c.Value))
		}
	}
}

func TestIssue1735_URIOctetBackslashAndLong(t *testing.T) {
	m := new(Msg)
	m.Answer = []RR{
		&URI{
			Hdr:      RR_Header{Name: "example.com.", Rrtype: TypeURI, Class: ClassINET, Ttl: 300},
			Priority: 10,
			Weight:   1,
			Target:   "https://example.com/test?a=1\\&b=2\\123",
		},
		&URI{
			Hdr:      RR_Header{Name: "example.com.", Rrtype: TypeURI, Class: ClassINET, Ttl: 300},
			Priority: 20,
			Weight:   2,
			Target:   strings.Repeat("x", 1200),
		},
	}

	packed, err := m.Pack()
	if err != nil {
		t.Fatalf("URI Pack failed: %v", err)
	}

	m2 := new(Msg)
	if err := m2.Unpack(packed); err != nil {
		t.Fatalf("URI Unpack failed: %v", err)
	}

	repacked, err := m2.Pack()
	if err != nil {
		t.Fatalf("second URI Pack failed: %v", err)
	}
	if !bytes.Equal(packed, repacked) {
		t.Fatalf("URI wire mismatch after roundtrip")
	}
}

func TestIssue1735_MultipleCAARecords(t *testing.T) {
	m := new(Msg)
	m.SetQuestion("example.com.", TypeCAA)
	m.Answer = []RR{
		&CAA{
			Hdr:   RR_Header{Name: "example.com.", Rrtype: TypeCAA, Class: ClassINET, Ttl: 300},
			Flag:  0,
			Tag:   "issue",
			Value: "letsencrypt.org",
		},
		&CAA{
			Hdr:   RR_Header{Name: "example.com.", Rrtype: TypeCAA, Class: ClassINET, Ttl: 300},
			Flag:  0,
			Tag:   "issuewild",
			Value: "sectigo.com; policy=ev",
		},
		&CAA{
			Hdr:   RR_Header{Name: "example.com.", Rrtype: TypeCAA, Class: ClassINET, Ttl: 300},
			Flag:  128,
			Tag:   "iodef",
			Value: "mailto:security@example.com",
		},
		&CAA{
			Hdr:   RR_Header{Name: "example.com.", Rrtype: TypeCAA, Class: ClassINET, Ttl: 300},
			Flag:  0,
			Tag:   "issue",
			Value: "custom\\\\escape\\\"test",
		},
	}

	packed, err := m.Pack()
	if err != nil {
		t.Fatalf("Pack multiple CAA records failed: %v", err)
	}

	m2 := new(Msg)
	if err := m2.Unpack(packed); err != nil {
		t.Fatalf("Unpack multiple CAA records failed: %v", err)
	}

	if len(m2.Answer) != len(m.Answer) {
		t.Fatalf("expected %d answers, got %d", len(m.Answer), len(m2.Answer))
	}

	for i := range m.Answer {
		orig := m.Answer[i].(*CAA)
		got := m2.Answer[i].(*CAA)
		if orig.Flag != got.Flag || orig.Tag != got.Tag || orig.Value != got.Value {
			t.Fatalf("[%d] mismatch: orig=%+v got=%+v", i, orig, got)
		}
	}

	repacked, err := m2.Pack()
	if err != nil {
		t.Fatalf("second Pack multiple CAA records failed: %v", err)
	}
	if !bytes.Equal(packed, repacked) {
		t.Fatalf("wire mismatch for multiple CAA records")
	}
}

func TestIssue1735_AllByteValues(t *testing.T) {
	// Value containing all 256 possible byte values (0x00 to 0xff)
	allBytes := make([]byte, 256)
	for i := 0; i < 256; i++ {
		allBytes[i] = byte(i)
	}

	wire := buildWireCAA("allbytes", allBytes)
	m := new(Msg)
	m.Compress = true
	if err := m.Unpack(wire); err != nil {
		t.Fatalf("Unpack failed for allBytes: %v", err)
	}

	repacked, err := m.Pack()
	if err != nil {
		t.Fatalf("Pack failed for allBytes: %v", err)
	}
	if !bytes.Equal(wire, repacked) {
		t.Fatalf("wire mismatch for allBytes")
	}

	m2 := new(Msg)
	if err := m2.Unpack(repacked); err != nil {
		t.Fatalf("second Unpack failed for allBytes: %v", err)
	}

	c1 := m.Answer[0].(*CAA)
	c2 := m2.Answer[0].(*CAA)
	if c1.Value != c2.Value {
		t.Fatalf("allBytes CAA value mismatch")
	}
}


