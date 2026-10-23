// Adapted from privately held Vectivium source; see LICENSE.Vectivium.
// No public relicensing is made.
package frontendconfig

import "strings"

// These PCRE2 patterns consume ASCII hex pairs, never a raw BIN-to-STR cast.
// Every alternative consumes exactly one original byte; all groups except the
// explicit header capture are noncapturing. Field-name case is ORIGINAL case.
const (
	valueByte = `(?:09|[2-6][0-9a-f]|7[0-9a-e]|[89a-f][0-9a-f])`
	clByte    = `(?:09|2[0-9abdef]|[3-6][0-9a-f]|7[0-9a-e]|[89a-f][0-9a-f])`
	tokenByte = `(?:21|2[3-7abde]|3[0-9]|4[1-9a-f]|5[0-9aef]|60|6[1-9a-f]|7[0-9ace])`
	lineEnd   = `0d0a`
)

func fieldName(name string) string {
	const digits = "0123456789abcdef"
	var out strings.Builder
	for _, c := range []byte(name) {
		if c >= 'a' && c <= 'z' {
			u := c - ('a' - 'A')
			out.WriteString("(?:")
			out.WriteByte(digits[u>>4])
			out.WriteByte(digits[u&15])
			out.WriteByte('|')
			out.WriteByte(digits[c>>4])
			out.WriteByte(digits[c&15])
			out.WriteByte(')')
		} else {
			out.WriteByte(digits[c>>4])
			out.WriteByte(digits[c&15])
		}
	}
	return out.String()
}

func patterns() (complete, capture, allowed string) {
	request := valueByte + "+" + lineEnd
	header := tokenByte + "+3a" + valueByte + "*" + lineEnd
	prefix := request + "(?:" + header + ")*" + lineEnd
	cl := fieldName("content-length")
	names := []string{cl}
	for _, name := range []string{"transfer-encoding", "content-encoding", "trailer", "expect", "upgrade"} {
		names = append(names, fieldName(name))
	}
	// A failed regex can never pass this positive gate. Ordinary fields cannot
	// be CL/forbidden fields; at most one comma-free CL may appear anywhere.
	ordinary := "(?!(?:" + strings.Join(names, "|") + ")3a)" + header
	clLine := cl + "3a" + clByte + "*" + lineEnd
	policy := request + "(?:" + ordinary + ")*(?:" + clLine + "(?:" + ordinary + ")*)?" + lineEnd
	return "^" + prefix, "^(" + prefix + ").*", "^" + policy + "$"
}

// rawGuard returns only unlinked local-frontend rule source. It is not a
// complete configuration or admission proof. Enclosing reviewed source must bind
// TLS/h1-only TCP mux, finite inspect/parent clocks, >=8193-byte scratch, routes,
// body/context/identity policy, resource accounting and native no-second-effect
// evidence. General frontend keep-alive/h2 is unaffected by this internal slice.
func rawGuard() string {
	complete, capture, allowed := patterns()
	return `# Candidate M2-H1/1 initial-header guard; NOT qualified or CLI-linked.
# One explicit LOCAL TCP frontend list; no earlier HTTP fetch/defaults capture.
# Enclosing source supplies finite inspect/parent deadlines and scratch >=8193.
mode tcp
option httpclose
acl vw_h1_complete var(sess.vw_h1_raw) -m reg '` + complete + `'
acl vw_h1_allowed var(sess.vw_h1_head) -m reg '` + allowed + `'
acl vw_h1_hex_ok var(sess.vw_h1_raw),length,sub(sess.vw_h1_expect) eq 0
tcp-request content reject if { var(sess.vw_h1_seen) -m found }
tcp-request content reject if { req.len eq 0 } WAIT_END
tcp-request content unset-var(sess.vw_h1_count)
tcp-request content unset-var(sess.vw_h1_expect)
tcp-request content unset-var(sess.vw_h1_raw)
tcp-request content unset-var(sess.vw_h1_head)
tcp-request content set-var(sess.vw_h1_count) req.len
tcp-request content set-var(sess.vw_h1_count) int(4096) if { var(sess.vw_h1_count) gt 4096 }
tcp-request content reject unless { var(sess.vw_h1_count) -m found }
tcp-request content set-var(sess.vw_h1_expect) var(sess.vw_h1_count),mul(2)
tcp-request content reject unless { var(sess.vw_h1_expect) -m found }
tcp-request content set-var(sess.vw_h1_raw) req.payload(0,0),bytes(0,4096),hex,lower
tcp-request content reject unless { var(sess.vw_h1_raw) -m found }
tcp-request content reject unless vw_h1_hex_ok
tcp-request content reject if !vw_h1_complete WAIT_END
tcp-request content set-var(sess.vw_h1_head) 'var(sess.vw_h1_raw),regsub("` + capture + `","\1")'
tcp-request content reject unless { var(sess.vw_h1_head) -m found }
tcp-request content reject unless vw_h1_allowed
tcp-request content set-var(sess.vw_h1_seen) int(1)
tcp-request content reject unless { var(sess.vw_h1_seen) -m found }
tcp-request content switch-mode http proto h1
tcp-request content reject
http-request deny unless { http_first_req }
http-request deny if { req.hdr(transfer-encoding) -m found }
# No backend/Ready/allow: full M2 route/body/context/byte policy remains required.
`
}
