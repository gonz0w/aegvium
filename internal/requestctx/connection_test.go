// SPDX-License-Identifier: BSD-3-Clause
package requestctx

import (
	"context"
	"encoding/json"
	"os"
	"strings"
	"testing"
)

type connectionOracles struct {
	Canonical struct {
		Fields           []struct{ Name, Value string }
		ContextWireBytes int `json:"context_wire_bytes"`
	} `json:"canonical"`
	Max struct {
		Fields    []struct{ Name, Value string }
		WireBytes int `json:"wire_bytes"`
	} `json:"max_context"`
	Valid []struct {
		Value         string
		Remote, Local []json.RawMessage
	} `json:"canonical_connection_value_oracles"`
	Reject []struct{ ID, Value string } `json:"reject_value_oracles"`
}

func connectionFixture(t *testing.T) connectionOracles {
	t.Helper()
	b, e := os.ReadFile("testdata/connection_facts.json")
	var f connectionOracles
	if e != nil || json.Unmarshal(b, &f) != nil {
		t.Fatal("independent connection literals")
	}
	return f
}

func TestConnectionCanonicalLiterals(t *testing.T) {
	f := connectionFixture(t)
	for _, row := range f.Valid {
		r, l, ok := parseConnection(row.Value)
		if !ok {
			t.Fatal("canonical literal refused")
		}
		var remoteIP, localIP string
		var remotePort, localPort uint16
		if json.Unmarshal(row.Remote[0], &remoteIP) != nil || json.Unmarshal(row.Remote[1], &remotePort) != nil || json.Unmarshal(row.Local[0], &localIP) != nil || json.Unmarshal(row.Local[1], &localPort) != nil {
			t.Fatal("oracle shape")
		}
		if r.Addr().String() != remoteIP || r.Port() != remotePort || l.Addr().String() != localIP || l.Port() != localPort {
			t.Fatal("connection field swap or rewrite")
		}
	}
	for _, row := range f.Reject {
		t.Run(row.ID, func(t *testing.T) {
			if _, _, ok := parseConnection(row.Value); ok {
				t.Fatal("noncanonical connection accepted")
			}
		})
	}
	for _, v := range []string{"", strings.Repeat("a", 44), "1.2.3.4:1/1.2.3.5:00001", "1.2.3.4:1/::ffff:1.2.3.5:1"} {
		if _, _, ok := parseConnection(v); ok {
			t.Fatal("invalid connection accepted")
		}
	}
	// Syntax alone does not invent an address-range policy or a socket claim.
	if _, _, ok := parseConnection("0.0.0.0:1/0.0.0.0:1"); !ok {
		t.Fatal("new address-range policy")
	}
}

func connectionRequest(t *testing.T) Request {
	t.Helper()
	f := connectionFixture(t)
	in := Request{Protocol: "HTTP/1.1", Method: "GET", Target: "/a//b%2Fc?x=1&x=2", Fields: []Field{{"Host", "app.example.test"}, {"X-Signed", "alpha+beta=="}}}
	for _, field := range f.Canonical.Fields {
		in.Fields = append(in.Fields, Field{field.Name, field.Value})
	}
	return in
}

func TestConnectionContextUsesLocalProfileAndStripsReserved(t *testing.T) {
	s, _, _ := pair2Fixture(t, "same_address_distinct_ports")
	in := connectionRequest(t)
	var dst Recorder
	if err := s.context.Record(context.Background(), Peer{identity: "front-a.internal.test"}, in, &dst); err != nil {
		t.Fatal(err)
	}
	rows := dst.Records()
	if len(rows) != 1 || len(rows[0].Fields) != 2 || rows[0].Remote.String() != "198.51.100.7:49152" || rows[0].Local.String() != "10.0.0.4:8443" || rows[0].Client != "198.51.100.7" || rows[0].Authority != "app.example.test" || rows[0].Target != in.Target {
		t.Fatal("engine facts/public fidelity/stripping")
	}
	for _, f := range rows[0].Fields {
		if strings.HasPrefix(strings.ToLower(f.Name), "aegvium-") {
			t.Fatal("reserved field leaked")
		}
	}
	// Public authority443 stays independent of the actual local socket8443.
	old, _, _ := pairFixture(t)
	if old.context.Record(context.Background(), Peer{identity: "front-a.internal.test"}, in, &Recorder{}) == nil {
		t.Fatal("wire selected new profile on old snapshot")
	}
	if s.context.Record(context.Background(), Peer{}, in, &Recorder{}) != ErrPeer {
		t.Fatal("parsed facts minted Peer")
	}
	for _, change := range []func(*Request){
		func(r *Request) { r.Fields[2].Value = "M2-H1/1" },
		func(r *Request) { r.Fields[7].Name = "Aegvium-Client"; r.Fields[7].Value = "198.51.100.7" },
		func(r *Request) { r.Fields = append(r.Fields, Field{"Aegvium-Client", "198.51.100.7"}) },
		func(r *Request) { r.Fields = append(r.Fields, Field{"aegvium-connection", r.Fields[7].Value}) },
		func(r *Request) { r.Fields = r.Fields[:7] },
		func(r *Request) { r.Fields[4].Value = "fedcba9876543210fedcba9876543210" },
		func(r *Request) { r.Fields[7].Value += " " },
		func(r *Request) { r.Fields = append(r.Fields, Field{"Aegvium-Local-Port", "8443"}) },
	} {
		bad := connectionRequest(t)
		change(&bad)
		if s.context.Record(context.Background(), Peer{identity: "front-a.internal.test"}, bad, &Recorder{}) == nil {
			t.Fatal("invalid context accepted")
		}
	}
}

func TestConnectionUnchangedFieldAndByteBudgets(t *testing.T) {
	f := connectionFixture(t)
	count := func(fields []struct{ Name, Value string }) int {
		n := 0
		for _, f := range fields {
			n += len(f.Name) + 2 + len(f.Value) + 2
		}
		return n
	}
	if count(f.Canonical.Fields) != 218 || f.Canonical.ContextWireBytes != 218 || count(f.Max.Fields) != 546 || f.Max.WireBytes != 546 || 4096+count(f.Max.Fields) != 4642 || MaxFields != 64 {
		t.Fatal("independent context byte/slot limit drift")
	}
	s, _, _ := pair2Fixture(t, "same_address_distinct_ports")
	in := connectionRequest(t)
	for len(in.Fields) < 64 {
		in.Fields = append(in.Fields, Field{"X-A", "b"})
	}
	if s.context.Record(context.Background(), Peer{identity: "front-a.internal.test"}, in, &Recorder{}) != nil {
		t.Fatal("58 application fields no longer fit")
	}
	in.Fields = append(in.Fields, Field{"X-B", "c"})
	if s.context.Record(context.Background(), Peer{identity: "front-a.internal.test"}, in, &Recorder{}) == nil {
		t.Fatal("65th total field accepted")
	}
}
