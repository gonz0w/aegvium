// SPDX-License-Identifier: BSD-3-Clause
// Package requestctx records bounded M2-C01 contexts. It performs no inspection,
// authentication, network operation or raw-wire parsing and grants no permission.
package requestctx

import (
	"context"
	"errors"
	"mime"
	"net/netip"
	"strconv"
	"strings"
	"sync"
)

const (
	MaxRoutes  = 8
	MaxFields  = 64
	MaxBody    = 4096
	MaxTarget  = 2048
	MaxRecords = 4
)

var (
	ErrInput      = errors.New("invalid context input")
	ErrPeer       = errors.New("unavailable authenticated peer")
	ErrAuthority  = errors.New("context route or authority mismatch")
	ErrGeneration = errors.New("context generation mismatch")
	ErrRetired    = errors.New("context snapshot retired")
	ErrCapacity   = errors.New("context capacity reached")
)

// Peer has no production constructor in this inert slice. A future reviewed
// transport adapter must derive it from verified TLS, never headers or a boolean.
// The zero value cannot record a context. Package-local tests inject fixtures.
type Peer struct{ identity string }

// Route is operator-owned input, not a public configuration or backend address.
type Route struct {
	ID, PublicName, PolicyPin string
	Port                      uint16
	FrontendPeers             []string
}

type route struct {
	name, pin string
	port      uint16
	peers     map[string]bool
}

// Snapshot owns copied route configuration and one process-local generation.
// The operator/next adapter must guarantee fresh generation tokens across starts.
type Snapshot struct {
	mu         sync.Mutex
	retired    bool
	generation string
	profile    string // Immutable local descriptor choice, never selected by input.
	routes     map[string]route
	admission  chan struct{}
}

type Field struct{ Name, Value string }

// Request contains already parsed values and a complete caller-owned body.
// The caller must not mutate slices during Record. Normalized/lost wire fields
// cannot be recovered here, and body completeness cannot be proved by this DTO.
type Request struct {
	Protocol, Method, Target string
	Fields                   []Field
	Body                     []byte
}

// Record is a detached context projection, never an allow verdict or authority
// to call a backend. Its slices are fresh copies whenever returned to a caller.
type Record struct {
	Peer, Route, Generation, PolicyPin, RequestID, SNI, Client string
	Protocol, Method, Authority, Target                        string
	Fields                                                     []Field
	Body                                                       []byte
	// Public frontend observations under H1/3 only; detached data, not proof
	// of the frontend connection or permission to inspect/forward.
	Remote, Local netip.AddrPort
}

// Recorder retains at most four contexts without eviction or a callback. There
// is no consumer I/O, background task or unbounded application waiting queue.
type Recorder struct {
	mu   sync.Mutex
	rows []Record
}

func NewSnapshot(generation string, config []Route) (*Snapshot, error) {
	return newSnapshotProfile(generation, config, "M2-H1/1")
}

func newSnapshotProfile(generation string, config []Route, profile string) (*Snapshot, error) {
	if !hex(generation, 32) || len(config) == 0 || len(config) > MaxRoutes || (profile != "M2-H1/1" && profile != "M2-H1/3") {
		return nil, ErrInput
	}
	s := &Snapshot{generation: strings.Clone(generation), profile: profile, routes: make(map[string]route), admission: make(chan struct{}, MaxRecords)}
	authorities := map[string]bool{}
	budget := len(generation)
	for _, c := range config {
		if !identifier(c.ID, 32, false) || !dns(c.PublicName) || c.Port == 0 || !hex(c.PolicyPin, 64) || len(c.FrontendPeers) == 0 || len(c.FrontendPeers) > 8 {
			return nil, ErrInput
		}
		key := c.PublicName + ":" + strconv.Itoa(int(c.Port))
		if _, exists := s.routes[c.ID]; exists || authorities[key] {
			return nil, ErrInput
		}
		peers := make(map[string]bool)
		budget += len(c.ID) + len(c.PublicName) + len(c.PolicyPin) + 5
		for _, name := range c.FrontendPeers {
			if !dns(name) || peers[name] {
				return nil, ErrInput
			}
			peers[strings.Clone(name)] = true
			budget += len(name)
		}
		if budget > 8192 {
			return nil, ErrInput
		}
		s.routes[strings.Clone(c.ID)] = route{strings.Clone(c.PublicName), strings.Clone(c.PolicyPin), c.Port, peers}
		authorities[key] = true
	}
	return s, nil
}

// Retire serializes with recording. Previously returned records remain inert
// historical data; none is a durable lease or permission surviving retirement.
func (s *Snapshot) Retire() {
	if s == nil {
		return
	}
	s.mu.Lock()
	s.retired = true
	s.mu.Unlock()
}

func (s *Snapshot) Record(ctx context.Context, peer Peer, input Request, dst *Recorder) error {
	if s == nil || ctx == nil || dst == nil {
		return ErrInput
	}
	if !dns(peer.identity) {
		return ErrPeer
	}
	if err := ctx.Err(); err != nil {
		return err
	}
	select {
	case s.admission <- struct{}{}:
		defer func() { <-s.admission }()
	default:
		return ErrCapacity
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.retired {
		return ErrRetired
	}
	if err := ctx.Err(); err != nil {
		return err
	}
	row, err := s.project(peer, input)
	if err != nil {
		return err
	}
	dst.mu.Lock()
	defer dst.mu.Unlock()
	// Recheck at the only publication point, after any recorder contention.
	if err := ctx.Err(); err != nil {
		return err
	}
	if len(dst.rows) >= MaxRecords {
		return ErrCapacity
	}
	dst.rows = append(dst.rows, row)
	return nil
}

func (r *Recorder) Records() []Record {
	if r == nil {
		return nil
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	out := make([]Record, len(r.rows))
	for i, row := range r.rows {
		row.Fields = append([]Field(nil), row.Fields...)
		row.Body = append([]byte(nil), row.Body...)
		out[i] = row
	}
	return out
}

func (s *Snapshot) project(peer Peer, in Request) (Record, error) {
	var zero Record
	connectionName := "aegvium-client"
	if s.profile == "M2-H1/3" {
		connectionName = "aegvium-connection"
	} else if s.profile != "M2-H1/1" {
		return zero, ErrInput
	}
	if in.Protocol != "HTTP/1.1" || (in.Method != "GET" && in.Method != "HEAD" && in.Method != "POST") || len(in.Body) > MaxBody || len(in.Fields) > MaxFields || !target(in.Target) {
		return zero, ErrInput
	}
	meta := make(map[string]string, 6)
	single := make(map[string]string, 4)
	public := make([]Field, 0, len(in.Fields))
	publicBytes := len(in.Method) + 1 + len(in.Target) + len(" HTTP/1.1\r\n") + 2
	contextBytes := 0
	for _, f := range in.Fields {
		if !fieldName(f.Name) || !fieldValue(f.Value) {
			return zero, ErrInput
		}
		name := strings.ToLower(f.Name)
		n := len(f.Name) + 2 + len(f.Value) + 2
		if strings.HasPrefix(name, "aegvium-") {
			switch name {
			case "aegvium-contract", "aegvium-route", "aegvium-generation", "aegvium-request", "aegvium-sni", connectionName:
			default:
				return zero, ErrInput
			}
			if _, exists := meta[name]; exists {
				return zero, ErrInput
			}
			meta[name] = f.Value
			contextBytes += n
		} else {
			if name == "forwarded" || name == "x-real-ip" || strings.HasPrefix(name, "x-forwarded-") {
				return zero, ErrInput
			}
			switch name {
			case "transfer-encoding", "content-encoding", "trailer", "te", "expect", "upgrade", "proxy-connection", "keep-alive":
				return zero, ErrInput
			case "host", "content-length", "content-type", "connection":
				if _, exists := single[name]; exists {
					return zero, ErrInput
				}
				single[name] = f.Value
			}
			if name == "x-amz-content-sha256" && strings.HasPrefix(f.Value, "STREAMING-") {
				return zero, ErrInput
			}
			public = append(public, Field{strings.Clone(f.Name), strings.Clone(f.Value)})
			publicBytes += n
		}
		if publicBytes > 4096 || contextBytes > 1024 || publicBytes+contextBytes > 5120 {
			return zero, ErrInput
		}
	}
	if len(meta) != 6 || meta["aegvium-contract"] != s.profile || !identifier(meta["aegvium-route"], 32, false) || !identifier(meta["aegvium-request"], 64, true) || !dns(meta["aegvium-sni"]) {
		return zero, ErrInput
	}
	var client netip.Addr
	var remote, local netip.AddrPort
	if s.profile == "M2-H1/3" {
		var ok bool
		remote, local, ok = parseConnection(meta[connectionName])
		if !ok {
			return zero, ErrInput
		}
		client = remote.Addr()
	} else {
		var err error
		client, err = netip.ParseAddr(meta[connectionName])
		if err != nil || !client.Is4() || client.String() != meta[connectionName] {
			return zero, ErrInput
		}
	}
	if meta["aegvium-generation"] != s.generation {
		return zero, ErrGeneration
	}
	r, ok := s.routes[meta["aegvium-route"]]
	if !ok {
		return zero, ErrAuthority
	}
	if !r.peers[peer.identity] {
		return zero, ErrPeer
	}
	if meta["aegvium-sni"] != r.name || !authority(single["host"], r.name, r.port) {
		return zero, ErrAuthority
	}
	if connection, exists := single["connection"]; exists && !strings.EqualFold(connection, "close") {
		return zero, ErrInput
	}
	length, exists := single["content-length"]
	if in.Method == "POST" && !exists {
		return zero, ErrInput
	}
	if exists {
		n, err := strconv.ParseUint(length, 10, 32)
		if err != nil || strconv.FormatUint(n, 10) != length || n != uint64(len(in.Body)) {
			return zero, ErrInput
		}
	}
	if in.Method != "POST" && len(in.Body) != 0 {
		return zero, ErrInput
	}
	if in.Method == "POST" {
		media, attrs, err := mime.ParseMediaType(single["content-type"])
		if err != nil || (media != "application/json" && media != "application/x-www-form-urlencoded") || len(attrs) > 1 || (len(attrs) == 1 && !strings.EqualFold(attrs["charset"], "utf-8")) {
			return zero, ErrInput
		}
	}
	return Record{Peer: strings.Clone(peer.identity), Route: strings.Clone(meta["aegvium-route"]), Generation: s.generation, PolicyPin: r.pin, RequestID: strings.Clone(meta["aegvium-request"]), SNI: r.name, Client: client.String(), Remote: remote, Local: local, Protocol: strings.Clone(in.Protocol), Method: strings.Clone(in.Method), Authority: strings.Clone(single["host"]), Target: strings.Clone(in.Target), Fields: public, Body: append([]byte(nil), in.Body...)}, nil
}

func hex(s string, n int) bool {
	if len(s) != n {
		return false
	}
	for _, c := range []byte(s) {
		if !(c >= '0' && c <= '9' || c >= 'a' && c <= 'f') {
			return false
		}
	}
	return true
}

func identifier(s string, n int, correlation bool) bool {
	if len(s) == 0 || len(s) > n {
		return false
	}
	for i, c := range []byte(s) {
		if c >= 'a' && c <= 'z' || (i > 0 || correlation) && (c >= '0' && c <= '9' || c == '_') || correlation && (c >= 'A' && c <= 'Z' || c == '-') {
			continue
		}
		return false
	}
	return true
}

func dns(s string) bool {
	if len(s) == 0 || len(s) > 253 || strings.HasSuffix(s, ".") || strings.ToLower(s) != s {
		return false
	}
	if _, err := netip.ParseAddr(s); err == nil {
		return false
	}
	for _, label := range strings.Split(s, ".") {
		if len(label) == 0 || len(label) > 63 || label[0] == '-' || label[len(label)-1] == '-' {
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

func authority(value, name string, port uint16) bool {
	host, p, explicit := strings.Cut(value, ":")
	if strings.ToLower(host) != name {
		return false
	}
	if !explicit {
		return port == 443
	}
	return p == strconv.Itoa(int(port))
}

func target(s string) bool {
	if len(s) == 0 || len(s) > MaxTarget || s[0] != '/' {
		return false
	}
	for i := 0; i < len(s); i++ {
		if s[i] < 0x21 || s[i] > 0x7e || s[i] == '#' {
			return false
		}
		if s[i] == '%' {
			if i+2 >= len(s) {
				return false
			}
			for _, c := range []byte(s[i+1 : i+3]) {
				if !(c >= '0' && c <= '9' || c >= 'a' && c <= 'f' || c >= 'A' && c <= 'F') {
					return false
				}
			}
			i += 2
		}
	}
	return true
}

func fieldName(s string) bool {
	if len(s) == 0 || len(s) > 128 {
		return false
	}
	for _, c := range []byte(s) {
		if !(c >= 'a' && c <= 'z' || c >= 'A' && c <= 'Z' || c >= '0' && c <= '9' || strings.ContainsRune("!#$%&'*+-.^_`|~", rune(c))) {
			return false
		}
	}
	return true
}

func fieldValue(s string) bool {
	if len(s) > 4096 {
		return false
	}
	for _, c := range []byte(s) {
		if c != '\t' && (c < 0x20 || c > 0x7e) {
			return false
		}
	}
	return true
}
