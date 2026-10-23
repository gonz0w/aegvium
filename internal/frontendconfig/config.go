// Adapted from privately held Vectivium source; see LICENSE.Vectivium.
// No public relicensing is made.
// Package frontendconfig compiles fixed offline stock-HAProxy configuration.
// It never authenticates a peer or grants launch/serving authority.
package frontendconfig

import (
	"bytes"
	"crypto/sha256"
	"errors"
	"net"
	"net/netip"
	"strconv"
	"strings"

	"github.com/gonz0w/aegvium/internal/pairmodel"
)

var ErrInput = errors.New("invalid bundled frontend configuration")

// Candidate is detached exact configuration, never an owner or ready handle.
// Only the fixed offline placement consumes it; mutable input cannot alter it.
type Candidate struct {
	config                       []byte
	digest                       [32]byte
	serverAnchor, frontendAnchor [32]byte
}

func (c Candidate) Bytes() []byte                        { return bytes.Clone(c.config) }
func (c Candidate) Digest() [32]byte                     { return c.digest }
func (c Candidate) Anchors() (server, frontend [32]byte) { return c.serverAnchor, c.frontendAnchor }

// Compile accepts only the jointly frozen DATA descriptor and one role allowed
// by EVERY route. The only target is its common inspector DATA endpoint. Public
// listener configuration is explicit; it is not inferred from Host or CONTROL.
func Compile(descriptor []byte, role, listen string) (Candidate, error) {
	d, err := pairmodel.Parse(descriptor)
	if err != nil {
		return Candidate{}, ErrInput
	}
	projection, err := d.Projection()
	if err != nil || projection.Profile != "M2-H1/3" || len(projection.Routes) == 0 {
		return Candidate{}, ErrInput
	}
	first := projection.Routes[0]
	for _, r := range projection.Routes {
		allowed := false
		for _, peer := range r.FrontendPeers {
			if role == peer {
				allowed = true
			}
		}
		if !allowed || r.InspectorAddress != first.InspectorAddress || r.InspectorPort != first.InspectorPort ||
			r.DataAddress != first.DataAddress || r.DataPort != first.DataPort || r.InspectorName != first.InspectorName ||
			r.ServerAnchor != first.ServerAnchor || r.FrontendAnchor != first.FrontendAnchor {
			return Candidate{}, ErrInput
		}
	}
	endpoint, err := netip.ParseAddrPort(listen)
	if err != nil || !endpoint.Addr().Is4() || endpoint.Addr().IsUnspecified() || endpoint.Addr().IsMulticast() ||
		endpoint.Addr().String() == "255.255.255.255" || endpoint.Port() == 0 || endpoint.String() != listen {
		return Candidate{}, ErrInput
	}
	if listen == net.JoinHostPort(first.InspectorAddress, strconv.Itoa(int(first.InspectorPort))) ||
		listen == net.JoinHostPort(first.DataAddress, strconv.Itoa(int(first.DataPort))) {
		return Candidate{}, ErrInput
	}
	var out strings.Builder
	out.WriteString(`# Unqualified Aegvium standalone source; installed activation remains refused.
global
  user _haproxy
  group _haproxy
  chroot /var/empty
  nbthread 1
  maxconn 4
  ssl-load-extra-files none
  tune.bufsize 16384
  set-var proc.vw_seq int(0)

defaults
  mode http
  timeout connect 1s
  timeout client 2s
  timeout server 4s
  timeout http-request 1s
  timeout queue 1ms
  retries 0
  option httpclose

frontend vw_public
`)
	out.WriteString("  bind " + listen + " ssl crt /etc/aegvium/frontend/public.pem strict-sni alpn http/1.1 ssl-min-ver TLSv1.2 ssl-max-ver TLSv1.3\n")
	out.WriteString(`  maxconn 4
  tcp-request inspect-delay 1s
  # Capture only actual public frontend observations. No address rewrite rules.
  tcp-request content set-var(sess.vw_remote) fc_src
  tcp-request content set-var(sess.vw_rport) fc_src_port
  tcp-request content set-var(sess.vw_local) fc_dst
  tcp-request content set-var(sess.vw_lport) fc_dst_port
  tcp-request content set-var(sess.vw_sni) ssl_fc_sni
  tcp-request content reject unless { var(sess.vw_remote) -m ip 0.0.0.0/0 }
  tcp-request content reject unless { var(sess.vw_local) -m ip 0.0.0.0/0 }
  tcp-request content reject unless { var(sess.vw_rport) ge 1 } { var(sess.vw_rport) le 65535 }
  tcp-request content reject unless { var(sess.vw_lport) ge 1 } { var(sess.vw_lport) le 65535 }
  tcp-request content reject unless { var(sess.vw_sni) -m found }
`)
	// No HTTP fetch precedes this complete original-prefix guard.
	for _, line := range strings.Split(strings.TrimSuffix(rawGuard(), "\n"), "\n") {
		out.WriteString("  " + line + "\n")
	}
	out.WriteString(`  http-request deny unless { req.ver -m str 1.1 }
  http-request deny unless { method -m str GET HEAD POST }
  http-request deny unless { url -m beg / }
  http-request deny if { url,length gt 2048 }
  http-request deny if { req.hdr_names -m reg -i '(^|,)(aegvium-|forwarded(,|$)|x-forwarded-|x-real-ip(,|$))' }
  http-request deny unless { req.fhdr_cnt(host) eq 1 }
  http-request unset-var(txn.vw_route)
`)
	for _, r := range projection.Routes {
		host := strings.ReplaceAll(r.PublicName, ".", "[.]")
		port := ":" + strconv.Itoa(int(r.PublicPort))
		if r.PublicPort == 443 {
			port = "(:443)?"
		}
		out.WriteString("  http-request set-var(txn.vw_route) str(" + r.ID + ") if { var(sess.vw_sni) -m str " + r.PublicName + " } { req.fhdr(host) -m reg -i '^" + host + port + "$' }\n")
	}
	out.WriteString(`  http-request return status 421 unless { var(txn.vw_route) -m found }
  http-request deny if { req.body_size gt 4096 }
  http-request deny if !{ method -m str POST } { req.body_size gt 0 }
  http-request deny if { method -m str POST } !{ req.fhdr_cnt(content-length) eq 1 }
  http-request wait-for-body time 2s at-least 4096
  http-request unset-var(txn.vw_size)
  http-request set-var(txn.vw_size) req.body_size
  http-request deny unless { var(txn.vw_size) -m found }
  http-request deny if { var(txn.vw_size) gt 4096 }
  http-request deny unless { req.body_len,sub(txn.vw_size) eq 0 }
  # Aeg still owns strict media/framing/complete inspection and origin admission.
  # Single-thread, non-yielding sequence block. Failures never reuse an ID.
  http-request unset-var(txn.vw_previous)
  http-request unset-var(txn.vw_seq)
  http-request set-var(txn.vw_previous) var(proc.vw_seq)
  http-request return status 503 unless { var(txn.vw_previous) -m found }
  http-request return status 503 if { var(txn.vw_previous) lt 0 }
  http-request return status 503 if { var(txn.vw_previous) ge 9223372036854775807 }
  http-request set-var(proc.vw_seq) var(txn.vw_previous),add(1)
  http-request set-var(txn.vw_seq) var(proc.vw_seq)
  http-request return status 503 unless { var(txn.vw_seq) -m found }
  http-request return status 503 unless { var(txn.vw_seq),sub(txn.vw_previous) eq 1 }
  http-request set-header Aegvium-Contract M2-H1/3
`)
	out.WriteString("  http-request set-header Aegvium-Generation " + projection.Generation + "\n")
	out.WriteString("  http-request set-header Aegvium-Request " + projection.Generation + "-%[var(txn.vw_seq)]\n")
	out.WriteString(`  http-request set-header Aegvium-Route %[var(txn.vw_route)]
  http-request set-header Aegvium-SNI %[var(sess.vw_sni)]
  http-request set-header Aegvium-Connection %[var(sess.vw_remote)]:%[var(sess.vw_rport)]/%[var(sess.vw_local)]:%[var(sess.vw_lport)]
  default_backend vw_inspector

backend vw_inspector
  mode http
  option httpclose
  http-reuse never
  retries 0
`)
	out.WriteString("  server inspector " + net.JoinHostPort(first.DataAddress, strconv.Itoa(int(first.DataPort))) + " ssl verify required ca-file /etc/aegvium/frontend/inspector-root.pem crt /etc/aegvium/frontend/frontend.pem sni str(" + first.InspectorName + ") verifyhost " + first.InspectorName + " alpn http/1.1 proto h1 ssl-min-ver TLSv1.3 ssl-max-ver TLSv1.3 no-ssl-reuse\n")
	if out.Len() > 32768 {
		return Candidate{}, ErrInput
	}
	raw := []byte(out.String())
	return Candidate{config: raw, digest: sha256.Sum256(raw), serverAnchor: first.ServerAnchor, frontendAnchor: first.FrontendAnchor}, nil
}
