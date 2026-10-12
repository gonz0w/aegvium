// SPDX-License-Identifier: BSD-3-Clause
package spike

import (
	"bufio"
	"errors"
	"io"
	"net/netip"
	"strings"
	"testing"
	"testing/iotest"
)

const proxyPrefix = "PROXY TCP4 192.0.2.10 127.0.0.1 54321 18084\r\n"

func TestProxyV1Accepted(t *testing.T) {
	for _, tc := range []struct {
		name, prefix, remainder, source, destination string
		fragmented                                   bool
	}{
		{"coalesced", proxyPrefix, "POST /allowed HTTP/1.1\r\nContent-Length: 4\r\n\r\nbody", "192.0.2.10:54321", "127.0.0.1:18084", false},
		{"one-byte", proxyPrefix, "GET /allowed HTTP/1.1\r\n\r\n", "192.0.2.10:54321", "127.0.0.1:18084", true},
		{"two-requests", proxyPrefix, "GET /a HTTP/1.1\r\n\r\nGET /b HTTP/1.1\r\n\r\n", "192.0.2.10:54321", "127.0.0.1:18084", false},
		{"maximum", "PROXY TCP4 255.255.255.255 255.255.255.255 65535 65535\r\n", "sentinel", "255.255.255.255:65535", "255.255.255.255:65535", false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			var input io.Reader = strings.NewReader(tc.prefix + tc.remainder)
			if tc.fragmented {
				input = iotest.OneByteReader(input)
			}
			reader := bufio.NewReader(input)
			identity, err := readProxyV1(reader, netip.MustParseAddrPort(tc.destination))
			if err != nil || identity.source.String() != tc.source || identity.destination.String() != tc.destination {
				t.Fatalf("identity=%v err=%v", identity, err)
			}
			remainder, err := io.ReadAll(reader)
			if err != nil || string(remainder) != tc.remainder {
				t.Fatalf("remainder=%q err=%v", remainder, err)
			}
			if tc.name == "maximum" && len(tc.prefix) != proxyV1Maximum {
				t.Fatal("maximum boundary not exercised")
			}
		})
	}
}

func TestProxyV1Rejected(t *testing.T) {
	for _, tc := range []struct{ name, wire string }{
		{"missing", "HEAD /_aegvium/ready HTTP/1.1\r\n\r\n"},
		{"truncated", strings.TrimSuffix(proxyPrefix, "\r\n")},
		{"overlong", strings.Repeat("x", 57) + "\r\n"},
		{"bare-lf", strings.ReplaceAll(proxyPrefix, "\r\n", "\n")},
		{"magic", strings.Replace(proxyPrefix, "PROXY", "PROXI", 1)},
		{"family", strings.Replace(proxyPrefix, "TCP4", "TCP6", 1)},
		{"unknown", "PROXY UNKNOWN\r\n"},
		{"v2", "\r\n\r\n\x00\r\nQUIT\n\x21\x11\x00\x0c"},
		{"source", strings.Replace(proxyPrefix, "192.0.2.10", "999.0.2.10", 1)},
		{"destination", strings.Replace(proxyPrefix, "127.0.0.1", "127.0.0.999", 1)},
		{"leading-zero-address", strings.Replace(proxyPrefix, "192.0.2.10", "192.00.2.10", 1)},
		{"mapped-ipv6", strings.Replace(proxyPrefix, "192.0.2.10", "::ffff:192.0.2.10", 1)},
		{"zero-port", strings.Replace(proxyPrefix, "54321", "0", 1)},
		{"overflow-port", strings.Replace(proxyPrefix, "54321", "65536", 1)},
		{"leading-zero-port", strings.Replace(proxyPrefix, "54321", "054321", 1)},
		{"signed-port", strings.Replace(proxyPrefix, "54321", "+54321", 1)},
		{"duplicate-space", strings.Replace(proxyPrefix, "TCP4 ", "TCP4  ", 1)},
		{"tab", strings.Replace(proxyPrefix, "TCP4 ", "TCP4\t", 1)},
		{"extra-field", strings.Replace(proxyPrefix, "\r\n", " extra\r\n", 1)},
		{"wrong-destination", strings.Replace(proxyPrefix, "18084", "18085", 1)},
	} {
		t.Run(tc.name, func(t *testing.T) {
			// One-byte reads make consumption observable without bufio read-ahead.
			input := &countedProxyReader{reader: iotest.OneByteReader(strings.NewReader(tc.wire))}
			identity, err := readProxyV1(bufio.NewReader(input), netip.MustParseAddrPort("127.0.0.1:18084"))
			if err == nil || identity != (proxyIdentity{}) {
				t.Fatalf("rejected input returned identity=%v err=%v", identity, err)
			}
			if input.bytes > proxyV1Maximum {
				t.Fatalf("consumed %d prefix bytes", input.bytes)
			}
		})
	}
}

type countedProxyReader struct {
	reader io.Reader
	bytes  int
}

func (r *countedProxyReader) Read(p []byte) (int, error) {
	n, err := r.reader.Read(p)
	r.bytes += n
	return n, err
}

func TestProxyV1ReadFailure(t *testing.T) {
	failure := errors.New("synthetic prefix failure")
	reader := bufio.NewReader(io.MultiReader(strings.NewReader("PROXY TCP4 "), iotest.ErrReader(failure)))
	identity, err := readProxyV1(reader, netip.MustParseAddrPort("127.0.0.1:18084"))
	if !errors.Is(err, failure) || identity != (proxyIdentity{}) {
		t.Fatalf("identity=%v err=%v", identity, err)
	}
}
