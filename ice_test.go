package ice

import (
	"io/ioutil"
	"net"
	"os"
	"path/filepath"
	"testing"

	"github.com/gortc/sdp"
)

func TestCandidate_Reset(t *testing.T) {
	b := Candidate{
		Foundation:  3862931549,
		ComponentID: 1,
		Priority:    2113937151,
		ConnectionAddress: ConnectionAddress{
			IP: net.ParseIP("192.168.220.128"),
		},
		Port:        56032,
		Type:        CandidateHost,
		NetworkCost: 50,
		Attributes: Attributes{
			Attribute{
				Key:   []byte("alpha"),
				Value: []byte("beta"),
			},
		},
	}
	c := Candidate{
		Foundation:  3862931549,
		ComponentID: 1,
		Priority:    2113937151,
		ConnectionAddress: ConnectionAddress{
			IP: net.ParseIP("192.168.220.128"),
		},
		Port:        56032,
		Type:        CandidateHost,
		NetworkCost: 50,
		Attributes: Attributes{
			Attribute{
				Key:   []byte("alpha"),
				Value: []byte("beta"),
			},
		},
	}
	c.Reset()
	if c.Equal(&b) {
		t.Fatal("should not equal")
	}
}

func TestCandidate_Equal(t *testing.T) {
	for _, tt := range []struct {
		name string
		a, b  Candidate
		equal bool
	}{
		{
			name: "Blank",
			a: Candidate{},
			b: Candidate{},
			equal: true,
		},
		{
			name: "Attributes",
			a: Candidate{},
			b: Candidate{Attributes: Attributes{{}}},
			equal: false,
		},
		{
			name: "Port",
			a: Candidate{},
			b: Candidate{Port: 10},
			equal: false,
		},
		{
			name: "Priority",
			a: Candidate{},
			b: Candidate{Priority: 10},
			equal: false,
		},
		{
			name: "Transport",
			a: Candidate{Transport: TransportUDP},
			b: Candidate{Transport: TransportUnknown},
			equal: false,
		},
		{
			name: "TransportValue",
			a: Candidate{},
			b: Candidate{TransportValue: []byte("v")},
			equal: false,
		},
		{
			name: "Foundation",
			a: Candidate{},
			b: Candidate{Foundation: 1},
			equal: false,
		},
		{
			name: "ComponentID",
			a: Candidate{},
			b: Candidate{ComponentID: 1},
			equal: false,
		},
		{
			name: "NetworkCost",
			a: Candidate{},
			b: Candidate{NetworkCost: 1},
			equal: false,
		},
		{
			name: "Generation",
			a: Candidate{},
			b: Candidate{Generation: 1},
			equal: false,
		},
		{
			name: "Type",
			a: Candidate{},
			b: Candidate{Type: 1},
			equal: false,
		},
	} {
		t.Run(tt.name, func(t *testing.T) {
			if tt.a.Equal(&tt.b) != tt.equal {
				t.Error("equality test failed")
			}
		})

	}
}

func loadData(tb testing.TB, name string) []byte {
	name = filepath.Join("testdata", name)
	f, err := os.Open(name)
	if err != nil {
		tb.Fatal(err)
	}
	defer func() {
		if errClose := f.Close(); errClose != nil {
			tb.Fatal(errClose)
		}
	}()
	v, err := ioutil.ReadAll(f)
	if err != nil {
		tb.Fatal(err)
	}
	return v
}

func TestConnectionAddress(t *testing.T) {
	data := loadData(t, "candidates_ex1.sdp")
	s, err := sdp.DecodeSession(data, nil)
	if err != nil {
		t.Fatal(err)
	}
	for _, c := range s {
		p := candidateParser{
			c:   new(Candidate),
			buf: c.Value,
		}
		if err = p.parse(); err != nil {
			t.Fatal(err)
		}
	}

	// a=candidate:3862931549 1 udp 2113937151 192.168.220.128 56032
	//     foundation ---┘    |  |      |            |          |
	//   component id --------┘  |      |            |          |
	//      transport -----------┘      |            |          |
	//       priority ------------------┘            |          |
	//  conn. address -------------------------------┘          |
	//           port ------------------------------------------┘
}

func TestParse(t *testing.T) {
	data := loadData(t, "candidates_ex1.sdp")
	s, err := sdp.DecodeSession(data, nil)
	if err != nil {
		t.Fatal(err)
	}
	expected := []Candidate{
		{
			Foundation:  3862931549,
			ComponentID: 1,
			Priority:    2113937151,
			ConnectionAddress: ConnectionAddress{
				IP: net.ParseIP("192.168.220.128"),
			},
			Port:        56032,
			Type:        CandidateHost,
			NetworkCost: 50,
			Attributes: Attributes{
				Attribute{
					Key:   []byte("alpha"),
					Value: []byte("beta"),
				},
			},
		},
	}
	tCases := []struct {
		input    []byte
		expected Candidate
	}{
		{s[0].Value, expected[0]}, // 0
	}

	for i, c := range tCases {
		parser := candidateParser{
			buf: c.input,
			c:   new(Candidate),
		}
		if err := parser.parse(); err != nil {
			t.Errorf("[%d]: unexpected error %s",
				i, err,
			)
		}
		if !c.expected.Equal(parser.c) {
			t.Errorf("[%d]: %v != %v (exp)",
				i, parser.c, c.expected,
			)
		}
	}
}

func BenchmarkParse(b *testing.B) {
	data := loadData(b, "candidates_ex1.sdp")
	s, err := sdp.DecodeSession(data, nil)
	if err != nil {
		b.Fatal(err)
	}
	b.ReportAllocs()
	value := s[0].Value
	p := candidateParser{
		c: new(Candidate),
	}
	for i := 0; i < b.N; i++ {
		p.buf = value
		if err = p.parse(); err != nil {
			b.Fatal(err)
		}
		p.c.Reset()
	}
}

func BenchmarkParseIP(b *testing.B) {
	v := []byte("127.0.0.2")
	var (
		result = make([]byte, net.IPv4len)
	)
	b.ReportAllocs()
	for i := 0; i < b.N; i++ {
		result = parseIP(result, v)
		result = result[:net.IPv4len]
	}
}
