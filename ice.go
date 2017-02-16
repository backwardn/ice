// Package ice implements RFC 5245
// Interactive Connectivity Establishment (ICE):
// A Protocol for Network Address Translator (NAT)
// Traversal for Offer/Answer Protocols.
package ice

import (
	"bytes"
	"fmt"
	"io"
	"net"
	"strconv"
)

// AddressType is type for ConnectionAddress.
type AddressType byte

// Possible address types.
const (
	AddressIPv4 AddressType = iota
	AddressIPv6
	AddressFQDN
)

func (a AddressType) String() string {
	switch a {
	case AddressIPv4:
		return "IPv4"
	case AddressIPv6:
		return "IPv6"
	case AddressFQDN:
		return "FQDN"
	default:
		panic("unexpected address type")
	}
}

// ConnectionAddress represents address that can be ipv4/6 or FQDN.
type ConnectionAddress struct {
	Host []byte
	IP   net.IP
	Type AddressType
}

// reset sets all fields to zero values.
func (a *ConnectionAddress) reset() {
	a.Host = a.Host[:0]
	for i := range a.IP {
		a.IP[i] = 0
	}
	a.Type = AddressIPv4
}

// Equal returns true if b equals to a.
func (a ConnectionAddress) Equal(b ConnectionAddress) bool {
	if a.Type != b.Type {
		return false
	}
	switch a.Type {
	case AddressFQDN:
		return bytes.Equal(a.Host, b.Host)
	default:
		return a.IP.Equal(b.IP)
	}
}

func (a ConnectionAddress) str() string {
	switch a.Type {
	case AddressFQDN:
		return string(a.Host)
	default:
		return a.IP.String()
	}
}

func (a ConnectionAddress) String() string {
	return a.str()
}

// CandidateType encodes the type of candidate. This specification
// defines the values "host", "srflx", "prflx", and "relay" for host,
// server reflexive, peer reflexive, and relayed candidates,
// respectively. The set of candidate types is extensible for the
// future.
type CandidateType byte

// Set of candidate types.
const (
	CandidateUnknown         CandidateType = iota
	CandidateHost                          // "host"
	CandidateServerReflexive               // "srflx"
	CandidatePeerReflexive                 // "prflx"
	CandidateRelay                         // "relay"
)

func (c CandidateType) String() string {
	switch c {
	case CandidateHost:
		return "host"
	case CandidateServerReflexive:
		return "server-reflexive"
	case CandidatePeerReflexive:
		return "peer-reflexive"
	case CandidateRelay:
		return "relay"
	default:
		return "unknown"
	}
}

const (
	candidateHost            = "host"
	candidateServerReflexive = "srflx"
	candidatePeerReflexive   = "prflx"
	candidateRelay           = "relay"
)

// Candidate is ICE candidate defined in RFC 5245 Section 21.1.1.
//
// This attribute is used with Interactive Connectivity
// Establishment (ICE), and provides one of many possible candidate
// addresses for communication. These addresses are validated with
// an end-to-end connectivity check using Session Traversal Utilities
// for NAT (STUN)).
//
// The candidate attribute can itself be extended. The grammar allows
// for new name/value pairs to be added at the end of the attribute. An
// implementation MUST ignore any name/value pairs it doesn't
// understand.
type Candidate struct {
	ConnectionAddress ConnectionAddress
	Port              int
	Transport         TransportType
	TransportValue    []byte // if failed to describe via TransportType
	Foundation        int
	ComponentID       int
	Priority          int
	Type              CandidateType
	RelatedAddress    ConnectionAddress
	RelatedPort       int
	Attributes        Attributes
}

// reset sets all fields to zero values.
func (c *Candidate) reset() {
	c.ConnectionAddress.reset()
	c.RelatedAddress.reset()
	c.RelatedPort = 0
	c.Transport = TransportUnknown
	c.TransportValue = c.TransportValue[:0]
	c.Attributes = c.Attributes[:0]
}

// Equal returns true if b candidate is equal to c.
func (c Candidate) Equal(b *Candidate) bool {
	if !c.ConnectionAddress.Equal(b.ConnectionAddress) {
		return false
	}
	if c.Port != b.Port {
		return false
	}
	if c.Transport != b.Transport {
		return false
	}
	if !bytes.Equal(c.TransportValue, b.TransportValue) {
		return false
	}
	if c.Foundation != b.Foundation {
		return false
	}
	if c.ComponentID != b.ComponentID {
		return false
	}
	if c.Priority != b.Priority {
		return false
	}
	if c.Type != b.Type {
		return false
	}
	if !c.Attributes.Equal(b.Attributes) {
		return false
	}
	return true
}

// Attribute is key-value pair.
type Attribute struct {
	Key   []byte
	Value []byte
}

// Attributes is list of attributes.
type Attributes []Attribute

// Value returns first attribute value with key k or
// nil of none found.
func (a Attributes) Value(k []byte) []byte {
	for _, attribute := range a {
		if bytes.Equal(attribute.Key, k) {
			return attribute.Value
		}
	}
	return nil
}

func (a Attributes) Equal(b Attributes) bool {
	if len(a) != len(b) {
		return false
	}
	for _, attr := range a {
		v := b.Value(attr.Key)
		if !bytes.Equal(v, attr.Value) {
			return false
		}
	}
	for _, attr := range b {
		v := a.Value(attr.Key)
		if !bytes.Equal(v, attr.Value) {
			return false
		}
	}
	return true
}

func (a Attribute) String() string {
	return fmt.Sprintf("%s:%s", a.Key, a.Value)
}

// TransportType is transport type for candidate.
type TransportType byte

// Supported transport types.
const (
	TransportUDP TransportType = iota
	TransportUnknown
)

func (t TransportType) String() string {
	switch t {
	case TransportUDP:
		return "UDP"
	default:
		return "Unknown"
	}
}

// candidateParser should parse []byte into Candidate.
//
// a=candidate:3862931549 1 udp 2113937151 192.168.220.128 56032 typ host generation 0 network-cost 50
//     foundation ---┘    |  |      |            |          |
//   component id --------┘  |      |            |          |
//      transport -----------┘      |            |          |
//       priority ------------------┘            |          |
//  conn. address -------------------------------┘          |
//           port ------------------------------------------┘
type candidateParser struct {
	buf []byte
	c   *Candidate
}

const sp = ' '

const (
	mandatoryElements = 6
)

func parseInt(v []byte) (int, error) {
	return strconv.Atoi(string(v))
}

func (p *candidateParser) parseFoundation(v []byte) error {
	i, err := parseInt(v)
	if err != nil {
		return &attrParseError{"foundation", err}
	}
	p.c.Foundation = i
	return nil
}

func (p *candidateParser) parseComponentID(v []byte) error {
	i, err := parseInt(v)
	if err != nil {
		return &attrParseError{"component id", err}
	}
	p.c.ComponentID = i
	return nil
}

func (p *candidateParser) parsePriority(v []byte) error {
	i, err := parseInt(v)
	if err != nil {
		return &attrParseError{"priority", err}
	}
	p.c.Priority = i
	return nil
}

func (p *candidateParser) parsePort(v []byte) error {
	i, err := parseInt(v)
	if err != nil {
		return attrParseError{"port", err}
	}
	p.c.Port = i
	return nil
}

func (p *candidateParser) parseRelatedPort(v []byte) error {
	i, err := parseInt(v)
	if err != nil {
		return attrParseError{"rel-port", err}
	}
	p.c.RelatedPort = i
	return nil
}

func parseIP(dst net.IP, v []byte) net.IP {
	ip := net.ParseIP(string(v))
	for _, c := range ip {
		dst = append(dst, c)
	}
	return dst
}

func (candidateParser) parseAddress(v []byte, target *ConnectionAddress) error {
	target.IP = parseIP(target.IP, v)
	if target.IP == nil {
		target.Host = v
		target.Type = AddressFQDN
		return nil
	}
	target.Type = AddressIPv6
	if target.IP.To4() != nil {
		target.Type = AddressIPv4
	}
	return nil
}

func (p *candidateParser) parseConnectionAddress(v []byte) error {
	return p.parseAddress(v, &p.c.ConnectionAddress)
}

func (p *candidateParser) parseRelatedAddress(v []byte) error {
	return p.parseAddress(v, &p.c.RelatedAddress)
}

func (p *candidateParser) parseTransport(v []byte) error {
	if bytes.Equal([]byte("udp"), bytes.ToLower(v)) {
		p.c.Transport = TransportUDP
	} else {
		p.c.Transport = TransportUnknown
		p.c.TransportValue = v
	}
	return nil
}

// possible attribute keys.
const (
	aType           = "typ"
	aRelatedAddress = "raddr"
	aRelatedPort    = "rport"
)

func (p *candidateParser) parseAttribute(a Attribute) error {
	switch string(a.Key) {
	case aType:
		return p.parseType(a.Value)
	case aRelatedAddress:
		return p.parseRelatedAddress(a.Value)
	case aRelatedPort:
		return p.parseRelatedPort(a.Value)
	default:
		p.c.Attributes = append(p.c.Attributes, a)
		return nil
	}
}

type parseFn func(v []byte) error

const (
	minBufLen = 10
)

type ParseError struct {
	Position int
	Err      error
}

type attrParseError struct {
	part  string
	cause error
}

func (e attrParseError) Error() string {
	return fmt.Sprintf("bad %s: %s", e.part, e.cause)
}

func (e ParseError) Error() string {
	return fmt.Sprintf("parse error at %d byte: %s", e.Position, e.Err)
}

// parse populates internal Candidate from buffer.
func (p *candidateParser) parse() error {
	if len(p.buf) < minBufLen {
		return io.ErrUnexpectedEOF
	}
	// special cases for raw value support:
	if p.buf[0] == 'a' {
		p.buf = bytes.TrimPrefix(p.buf, []byte("a="))
	}
	if p.buf[0] == 'c' {
		p.buf = bytes.TrimPrefix(p.buf, []byte("candidate:"))
	}
	// pos is current position
	// l is value length
	// last is last character offset
	// of mandatory elements
	var pos, l, last int
	fns := []parseFn{
		p.parseFoundation,        // 0
		p.parseComponentID,       // 1
		p.parseTransport,         // 2
		p.parsePriority,          // 3
		p.parseConnectionAddress, // 4
		p.parsePort,              // 5
	}
	for i, c := range p.buf {
		if pos > mandatoryElements-1 {
			// Saving offset.
			last = i
			break
		}
		if c != sp {
			// Non-space character.
			l++
			continue
		}
		// Space character reached.
		if err := fns[pos](p.buf[i-l : i]); err != nil {
			return &ParseError{
				Position: i,
				Err:      err,
			}
		}
		pos++ // next element
		l = 0 // reset length of element
	}
	if last == 0 {
		// No non-mandatory elements.
		return nil
	}
	// Offsets:
	var (
		start  int // key start
		end    int // key end
		vStart int // value start
	)
	// Subslicing to simplify offset calculation.
	buf := p.buf[last-1:]
	// Saving every k:v pair ignoring spaces.
	for i, c := range buf {
		if c != sp && i != len(buf)-1 {
			// Char is non-space or end of buffer.
			if start == 0 {
				// Key not started.
				start = i
				continue
			}
			if vStart == 0 && end != 0 {
				// value not started and key ended.
				vStart = i
			}
			continue
		}
		// Char is space or end of buf reached.
		if start == 0 {
			// Key not started, skipping.
			continue
		}
		if end == 0 {
			// Key ended, saving offset.
			end = i
			continue
		}
		if vStart == 0 {
			// Value not started, skipping.
			continue
		}
		if i == len(buf)-1 && buf[len(buf)-1] != sp {
			// Fix for end of buf.
			i = len(buf)
		}
		// Value ended, saving attribute.
		a := Attribute{
			Key:   buf[start:end],
			Value: buf[vStart:i],
		}
		if err := p.parseAttribute(a); err != nil {
			return &ParseError{
				Err:      err,
				Position: i + last,
			}
		}
		// Reset offset.
		vStart = 0
		end = 0
		start = 0
	}
	return nil
}

func (p *candidateParser) parseType(v []byte) error {
	switch string(v) {
	case candidateHost:
		p.c.Type = CandidateHost
	case candidatePeerReflexive:
		p.c.Type = CandidatePeerReflexive
	case candidateRelay:
		p.c.Type = CandidateRelay
	case candidateServerReflexive:
		p.c.Type = CandidateServerReflexive
	default:
		return fmt.Errorf("unknown candidate %q", v)
	}
	return nil
}

// ParseCandidate parses v into c and returns error if any.
func ParseCandidate(v []byte, c *Candidate) error {
	p := candidateParser{
		buf: v,
		c:   c,
	}
	err := p.parse()
	return err
}
