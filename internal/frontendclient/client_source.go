//go:build aegvium_frontend_source

// Adapted from private Vectivium e28959892903225887d855677c307712a59ce071; see LICENSE.Vectivium.
// No public relicensing is made.
package frontendclient

import (
	"bytes"
	"context"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"io"
	"net"
	"net/netip"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/gonz0w/aegvium/internal/pairmodel"
)

var ErrUnavailable = errors.New("inspector pair preparation unavailable")

// Materials is copied local configuration, not generation/history authority.
// No paths, connections, Peer, TLS state, provider or proof Boolean is accepted.
type Materials struct {
	Descriptor, CertificatePEM, PrivateKeyPEM []byte
	InspectorRootDER, FrontendRootDER         []byte
	FrontendRole                              string
}

// Source copies share one private attempt and actual endpoint ownership.
type Source struct{ state *sourceState }

// PreparedMatch reports a past control comparison after local close returned.
// Nothing accepts this object as a current owner, Ready or forwarding capability.
type PreparedMatch struct {
	tuple    [104]byte
	complete bool
}

func (m PreparedMatch) Tuple() ([104]byte, bool) { return m.tuple, m.complete }

type pairConfig struct {
	tuple                           [104]byte
	address, serverName, clientName string
	port                            uint16
	profile, dataAddress            string
	dataPort                        uint16
	serverAnchor, clientAnchor      [32]byte
	roles                           map[string]bool
}

type validity struct{ from, until time.Time }

func (v validity) current(now time.Time) bool {
	return !v.from.IsZero() && !now.Before(v.from) && now.Before(v.until)
}

type sourceState struct {
	mu                                                               sync.Mutex
	ctx                                                              context.Context
	cancel                                                           context.CancelFunc
	started, total, parentUntil                                      time.Time
	constructed, attempted, retired, uncertain, certificateRequested bool
	pair                                                             *pairConfig
	config                                                           *tls.Config
	certificate                                                      tls.Certificate
	clientValidity, serverValidity                                   validity
	endpoint                                                         *ownedEndpoint
	connection                                                       *tls.Conn
	request                                                          []byte
	written                                                          int
	header, response                                                 []byte
}

var construction struct {
	sync.Mutex
	attempted bool
	owner     *sourceState
}

// NewSource consumes the process attempt before even numeric input admission.
// It performs actual crypto only when explicitly called in this source build.
// Tests must not call it. An error returns the retained owner when one exists.
func NewSource(ctx context.Context, input Materials) (out *Source, err error) {
	construction.Lock()
	if construction.attempted {
		construction.Unlock()
		return nil, ErrUnavailable
	}
	construction.attempted = true
	now := time.Now()
	s := &sourceState{started: now, total: now.Add(2 * time.Second)}
	construction.owner = s
	construction.Unlock()
	out = &Source{state: s}
	complete := false
	defer func() {
		if !complete {
			_ = recover()
			s.retire()
			err = ErrUnavailable
		}
	}()
	// Bounds precede every copy, parser allocation and cryptographic operation.
	if ctx == nil || !materialBounds(input) {
		return out, ErrUnavailable
	}
	s.parentUntil, _ = ctx.Deadline()
	s.ctx, s.cancel = context.WithCancel(ctx)
	if !s.live() {
		return out, ErrUnavailable
	}
	descriptor := bytes.Clone(input.Descriptor)
	certPEM, keyPEM := bytes.Clone(input.CertificatePEM), bytes.Clone(input.PrivateKeyPEM)
	serverDER, clientDER := bytes.Clone(input.InspectorRootDER), bytes.Clone(input.FrontendRootDER)
	pair, parseErr := parsePair(descriptor, input.FrontendRole)
	if parseErr != nil || !s.live() || sha256.Sum256(serverDER) != pair.serverAnchor || sha256.Sum256(clientDER) != pair.clientAnchor || !lexicalMaterial(certPEM, keyPEM) {
		return out, ErrUnavailable
	}
	s.pair = pair
	serverRoot, parseErr := x509.ParseCertificate(serverDER)
	if parseErr != nil || !s.live() {
		return out, ErrUnavailable
	}
	clientRoot, parseErr := x509.ParseCertificate(clientDER)
	if parseErr != nil || !s.live() {
		return out, ErrUnavailable
	}
	cert, parseErr := tls.X509KeyPair(certPEM, keyPEM)
	if parseErr != nil || len(cert.Certificate) < 1 || len(cert.Certificate) > 8 || !s.live() {
		return out, ErrUnavailable
	}
	leaf, parseErr := x509.ParseCertificate(cert.Certificate[0])
	if parseErr != nil || !leafRole(leaf, pair, false) || !s.live() {
		return out, ErrUnavailable
	}
	intermediates := x509.NewCertPool()
	for _, der := range cert.Certificate[1:] {
		c, parseErr := x509.ParseCertificate(der)
		if parseErr != nil || !s.live() {
			return out, ErrUnavailable
		}
		intermediates.AddCert(c)
	}
	clientRoots := x509.NewCertPool()
	clientRoots.AddCert(clientRoot)
	chains, verifyErr := leaf.Verify(x509.VerifyOptions{Roots: clientRoots, Intermediates: intermediates, DNSName: pair.clientName, KeyUsages: []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth}, CurrentTime: time.Now()})
	if verifyErr != nil || !s.live() {
		return out, ErrUnavailable
	}
	v, ok := pinnedValidity(chains, pair.clientAnchor, time.Now())
	if !ok {
		return out, ErrUnavailable
	}
	cert.Leaf = leaf
	s.certificate = cert
	s.clientValidity = v
	serverRoots := x509.NewCertPool()
	serverRoots.AddCert(serverRoot)
	s.config = &tls.Config{MinVersion: tls.VersionTLS13, MaxVersion: tls.VersionTLS13, ServerName: pair.serverName, RootCAs: serverRoots, NextProtos: []string{"http/1.1"}, SessionTicketsDisabled: true, Renegotiation: tls.RenegotiateNever, GetClientCertificate: s.clientCertificate}
	if !s.live() {
		return out, ErrUnavailable
	}
	s.constructed = true
	complete = true
	return out, nil
}

func materialBounds(m Materials) bool {
	return len(m.Descriptor) > 0 && len(m.Descriptor) <= 8192 && len(m.FrontendRole) > 0 && len(m.FrontendRole) <= 253 && dns(m.FrontendRole) &&
		len(m.CertificatePEM) > 0 && len(m.CertificatePEM) <= 65536 && len(m.PrivateKeyPEM) > 0 && len(m.PrivateKeyPEM) <= 16384 &&
		len(m.InspectorRootDER) > 0 && len(m.InspectorRootDER) <= 16384 && len(m.FrontendRootDER) > 0 && len(m.FrontendRootDER) <= 16384
}

func parsePair(raw []byte, role string) (*pairConfig, error) {
	d, err := parseDescriptor(raw)
	if err != nil || !dns(role) {
		return nil, ErrUnavailable
	}
	p, err := d.Projection()
	if err != nil || len(p.Routes) == 0 {
		return nil, ErrUnavailable
	}
	if !(p.Profile == "M2-H1/1" || p.Profile == "M2-H1/3") {
		return nil, ErrUnavailable
	}
	first := p.Routes[0]
	// Legacy InspectorAddress/Port always mean CONTROL. Only AGPAIR2 has an
	// explicit DATA tuple; no caller may infer one from AGPAIR1 or a control match.
	out := &pairConfig{address: first.InspectorAddress, serverName: first.InspectorName, clientName: role, port: first.InspectorPort, profile: p.Profile, dataAddress: first.DataAddress, dataPort: first.DataPort, serverAnchor: first.ServerAnchor, clientAnchor: first.FrontendAnchor, roles: map[string]bool{}}
	if p.Profile == "M2-H1/1" && (out.dataAddress != "" || out.dataPort != 0) || p.Profile == "M2-H1/3" && (out.dataAddress == "" || out.dataPort == 0 || out.address == out.dataAddress && out.port == out.dataPort) {
		return nil, ErrUnavailable
	}
	if role == out.serverName {
		return nil, ErrUnavailable
	}
	for _, r := range p.Routes {
		if r.InspectorAddress != out.address || r.InspectorPort != out.port || r.DataAddress != out.dataAddress || r.DataPort != out.dataPort || r.InspectorName != out.serverName || r.ServerAnchor != out.serverAnchor || r.FrontendAnchor != out.clientAnchor {
			return nil, ErrUnavailable
		}
		allowed := false
		for _, name := range r.FrontendPeers {
			out.roles[name] = true
			allowed = allowed || name == role
			if name == out.serverName {
				return nil, ErrUnavailable
			}
		}
		if !allowed {
			return nil, ErrUnavailable
		}
	}
	digest := sha256.Sum256(d.Bytes())
	contract := sha256.Sum256([]byte(p.Profile))
	copy(out.tuple[:8], "AGCHECK1")
	copy(out.tuple[8:40], p.Generation)
	copy(out.tuple[40:72], digest[:])
	copy(out.tuple[72:], contract[:])
	return out, nil
}

// The actual DialContext uses only this validated local CONTROL tuple. DATA is
// independently bound in the full descriptor digest, never a fallback target.
func controlEndpoint(p *pairConfig) string {
	if p == nil {
		return ""
	}
	return net.JoinHostPort(p.address, strconv.Itoa(int(p.port)))
}

func lexicalMaterial(cert, key []byte) bool {
	begins := bytes.Count(cert, []byte("-----BEGIN "))
	if begins < 1 || begins > 8 {
		return false
	}
	count := 0
	for len(bytes.TrimSpace(cert)) != 0 {
		cert = bytes.TrimSpace(cert)
		if !bytes.HasPrefix(cert, []byte("-----BEGIN CERTIFICATE-----")) {
			return false
		}
		b, rest := pem.Decode(cert)
		if b == nil || b.Type != "CERTIFICATE" || len(b.Headers) != 0 {
			return false
		}
		count++
		if count > 8 {
			return false
		}
		cert = rest
	}
	if count != begins || bytes.Count(key, []byte("-----BEGIN ")) != 1 {
		return false
	}
	key = bytes.TrimSpace(key)
	b, rest := pem.Decode(key)
	return b != nil && bytes.HasPrefix(key, []byte("-----BEGIN "+b.Type+"-----")) && len(b.Headers) == 0 && len(bytes.TrimSpace(rest)) == 0 && (b.Type == "PRIVATE KEY" || b.Type == "RSA PRIVATE KEY" || b.Type == "EC PRIVATE KEY")
}

func leafRole(c *x509.Certificate, p *pairConfig, server bool) bool {
	if c == nil || p == nil || c.IsCA || len(c.ExtKeyUsage) != 1 || len(c.UnknownExtKeyUsage) != 0 {
		return false
	}
	want, usage := p.clientName, x509.ExtKeyUsageClientAuth
	if server {
		want, usage = p.serverName, x509.ExtKeyUsageServerAuth
	}
	if c.ExtKeyUsage[0] != usage {
		return false
	}
	found := false
	for _, name := range c.DNSNames {
		if !dns(name) || server && p.roles[name] || !server && (name == p.serverName || p.roles[name] && name != p.clientName) {
			return false
		}
		found = found || name == want
	}
	return found
}

func pinnedValidity(chains [][]*x509.Certificate, pin [32]byte, now time.Time) (validity, bool) {
	for _, chain := range chains {
		if len(chain) == 0 || chain[len(chain)-1] == nil || sha256.Sum256(chain[len(chain)-1].Raw) != pin {
			continue
		}
		var v validity
		valid := true
		for i, c := range chain {
			if c == nil {
				valid = false
				break
			}
			if i == 0 || c.NotBefore.After(v.from) {
				v.from = c.NotBefore
			}
			if i == 0 || c.NotAfter.Before(v.until) {
				v.until = c.NotAfter
			}
		}
		if valid && v.current(now) {
			return v, true
		}
	}
	return validity{}, false
}

// clockCurrent is private: callers cannot substitute a clock or lifetime.
func clockCurrent(now, start, total, parent time.Time) bool {
	return !now.Before(start) && beforeDeadline(now, total) && (parent.IsZero() || beforeDeadline(now, parent))
}
func beforeDeadline(now, until time.Time) bool { return now.Before(until) }
func (s *sourceState) liveLocked(now time.Time) bool {
	return s.ctx != nil && s.ctx.Err() == nil && !s.retired && !s.uncertain &&
		clockCurrent(now, s.started, s.total, s.parentUntil) &&
		(s.clientValidity.from.IsZero() || s.clientValidity.current(now)) &&
		(s.serverValidity.from.IsZero() || s.serverValidity.current(now))
}
func (s *sourceState) live() bool {
	if s == nil {
		return false
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.liveLocked(time.Now())
}
func earlier(a, b time.Time) time.Time {
	if a.Before(b) {
		return a
	}
	return b
}
func (s *sourceState) until(stage time.Time) time.Time {
	s.mu.Lock()
	defer s.mu.Unlock()
	until := earlier(stage, s.total)
	if !s.parentUntil.IsZero() {
		until = earlier(until, s.parentUntil)
	}
	return until
}
func (s *sourceState) clientCertificate(info *tls.CertificateRequestInfo) (*tls.Certificate, error) {
	if info == nil || !s.live() {
		return nil, ErrUnavailable
	}
	s.mu.Lock()
	if s.certificateRequested {
		s.mu.Unlock()
		return nil, ErrUnavailable
	}
	s.certificateRequested = true
	s.mu.Unlock()
	if info.SupportsCertificate(&s.certificate) != nil || !s.live() {
		return nil, ErrUnavailable
	}
	return &s.certificate, nil
}
func (s *sourceState) verifyServer() bool {
	state := s.connection.ConnectionState()
	s.mu.Lock()
	requested := s.certificateRequested
	s.mu.Unlock()
	if !requested || !state.HandshakeComplete || state.DidResume || state.Version != tls.VersionTLS13 || state.NegotiatedProtocol != "http/1.1" || len(state.PeerCertificates) == 0 || !leafRole(state.PeerCertificates[0], s.pair, true) {
		return false
	}
	v, ok := pinnedValidity(state.VerifiedChains, s.pair.serverAnchor, time.Now())
	if !ok || !s.live() {
		return false
	}
	s.mu.Lock()
	s.serverValidity = v
	s.mu.Unlock()
	return s.live()
}
func (s *sourceState) retire() {
	if s == nil {
		return
	}
	s.mu.Lock()
	s.retired = true
	cancel := s.cancel
	s.cancel = nil
	s.mu.Unlock()
	if cancel != nil {
		cancel()
	}
}
func (s *Source) RetireSource() {
	if s != nil {
		s.state.retire()
	}
}

// finishPrepared linearizes the historical decision with retirement. A later
// RetireSource cannot revoke past data; retirement before this barrier refuses.
// Only Match passes actual transport facts. This helper creates no owner authority.
func (s *sourceState) finishPrepared(complete, closed bool) (PreparedMatch, error) {
	s.mu.Lock()
	now := time.Now()
	ok := complete && closed && s.constructed && s.attempted && s.pair != nil &&
		s.certificateRequested && s.clientValidity.current(now) && s.serverValidity.current(now) && s.liveLocked(now)
	result, err := PreparedMatch{}, ErrUnavailable
	if ok {
		result, err = PreparedMatch{tuple: s.pair.tuple, complete: true}, nil
	}
	s.retired = true
	cancel := s.cancel
	s.cancel = nil
	s.mu.Unlock()
	if cancel != nil {
		cancel()
	}
	return result, err
}

// MatchPreparedSource uses only its actual dial and TLS client. No test/provider
// can substitute authenticated state. Errors retain the original owner.
func (source *Source) MatchPreparedSource() (result PreparedMatch, err error) {
	if source == nil || source.state == nil {
		return result, ErrUnavailable
	}
	s := source.state
	s.mu.Lock()
	if !s.constructed || s.attempted || s.retired || s.uncertain {
		s.mu.Unlock()
		return result, ErrUnavailable
	}
	s.attempted = true
	s.mu.Unlock()
	complete := false
	defer func() {
		if recover() != nil {
			s.mu.Lock()
			s.uncertain = true
			s.mu.Unlock()
			complete = false
		}
		closed := false
		if s.endpoint != nil {
			closed = s.endpoint.finalize()
		}
		result, err = s.finishPrepared(complete, closed)
	}()
	until := s.until(s.started.Add(time.Second))
	if !s.live() || !beforeDeadline(time.Now(), until) {
		return result, ErrUnavailable
	}
	dialer := net.Dialer{Deadline: until, KeepAlive: -1}
	raw, dialErr := dialer.DialContext(s.ctx, "tcp", controlEndpoint(s.pair))
	if raw != nil {
		s.endpoint = &ownedEndpoint{connection: raw}
	}
	if dialErr != nil || s.endpoint == nil || !s.live() || s.endpoint.SetDeadline(until) != nil || !s.live() {
		return result, ErrUnavailable
	}
	s.connection = tls.Client(s.endpoint, s.config)
	handshakeCtx, cancel := context.WithDeadline(s.ctx, until)
	handshakeErr := s.connection.HandshakeContext(handshakeCtx)
	cancel()
	if handshakeErr != nil || !s.live() || !beforeDeadline(time.Now(), until) || !s.verifyServer() {
		return result, ErrUnavailable
	}
	until = s.until(time.Now().Add(time.Second))
	if !s.live() || !beforeDeadline(time.Now(), until) || s.connection.SetDeadline(until) != nil || !s.live() {
		return result, ErrUnavailable
	}
	s.request = controlRequest(s.pair)
	if !writeControl(s, s.connection, until, s.request) {
		return result, ErrUnavailable
	}
	if !readPreparedResponse(s, s.connection, until, s.pair) {
		return result, ErrUnavailable
	}
	complete = true
	return result, nil
}

const successHeader = "HTTP/1.1 200 OK\r\nContent-Length: 104\r\nConnection: close\r\n\r\n"

func readPreparedResponse(s *sourceState, r io.Reader, until time.Time, p *pairConfig) bool {
	if s == nil || p == nil {
		return false
	}
	s.header = readControlHeader(s, r, until)
	if !bytes.Equal(s.header, []byte(successHeader)) {
		return false
	}
	s.response = make([]byte, 104)
	complete, ended := readControlExact(s, r, until, s.response)
	if !complete || !bytes.Equal(s.response, p.tuple[:]) {
		return false
	}
	if ended {
		return s.live() && beforeDeadline(time.Now(), until)
	}
	var extra [1]byte
	if !s.live() || !beforeDeadline(time.Now(), until) {
		return false
	}
	n, err := r.Read(extra[:])
	return n == 0 && err == io.EOF && s.live() && beforeDeadline(time.Now(), until)
}
func controlRequest(p *pairConfig) []byte {
	if p == nil {
		return nil
	}
	header := "POST /_aegvium/m2-h1-1/pair HTTP/1.1\r\nHost: " + p.serverName + ":" + strconv.Itoa(int(p.port)) + "\r\nContent-Length: 104\r\nConnection: close\r\n\r\n"
	return append([]byte(header), p.tuple[:]...)
}

// EOF is retained with the final bytes; non-EOF errors never complete a read.
func readControlExact(s *sourceState, r io.Reader, until time.Time, out []byte) (complete, ended bool) {
	at, empty := 0, 0
	for at < len(out) {
		if !s.live() || !beforeDeadline(time.Now(), until) {
			return false, false
		}
		n, err := r.Read(out[at:])
		if n < 0 || n > len(out)-at || !s.live() || !beforeDeadline(time.Now(), until) {
			return false, false
		}
		at += n
		if err != nil {
			return err == io.EOF && at == len(out), err == io.EOF
		}
		if n == 0 {
			empty++
			if empty >= 4 {
				return false, false
			}
		} else {
			empty = 0
		}
	}
	return s.live() && beforeDeadline(time.Now(), until), false
}
func readControlHeader(s *sourceState, r io.Reader, until time.Time) []byte {
	out := make([]byte, 0, 4096)
	var one [1]byte
	for len(out) < 4096 {
		if complete, ended := readControlExact(s, r, until, one[:]); !complete || ended {
			return out
		}
		out = append(out, one[0])
		if bytes.HasSuffix(out, []byte("\r\n\r\n")) {
			return out
		}
	}
	return out
}
func writeControl(s *sourceState, w io.Writer, until time.Time, in []byte) bool {
	empty := 0
	for len(in) > 0 {
		if !s.live() || !beforeDeadline(time.Now(), until) {
			return false
		}
		n, err := w.Write(in)
		if n >= 0 && n <= len(in) {
			s.written += n
		}
		if n < 0 || n > len(in) || err != nil || !s.live() || !beforeDeadline(time.Now(), until) {
			return false
		}
		if n == 0 {
			empty++
			if empty >= 4 {
				return false
			}
		} else {
			empty = 0
			in = in[n:]
		}
	}
	return s.live() && beforeDeadline(time.Now(), until)
}

// Reuse Aegvium's exact immutable descriptor parser, not a second wire model.
func parseDescriptor(raw []byte) (*pairmodel.Descriptor, error) { return pairmodel.Parse(raw) }
func dns(s string) bool {
	if len(s) < 1 || len(s) > 253 || strings.HasSuffix(s, ".") {
		return false
	}
	if _, err := netip.ParseAddr(s); err == nil {
		return false
	}
	for _, label := range strings.Split(s, ".") {
		if len(label) < 1 || len(label) > 63 || label[0] == '-' || label[len(label)-1] == '-' {
			return false
		}
		for _, c := range []byte(label) {
			if !(c >= 'a' && c <= 'z' || c >= '0' && c <= '9' || c == '-') {
				return false
			}
		}
	}
	return true
}
