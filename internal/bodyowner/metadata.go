// SPDX-License-Identifier: BSD-3-Clause
package bodyowner

import (
	"mime"
	"net/netip"
	"strconv"
	"strings"

	"github.com/gonz0w/aegvium/internal/requestctx"
)

// engineInput is private copied data, not C01 peer/route/framing authority. A
// authenticated DATA receiver retains its own authority and resource join.
type engineInput struct {
	id, sni, protocol, method, target, policyPin string
	client, server                               netip.AddrPort
	publicPort                                   uint16
	fields                                       []requestctx.Field
}

func copyEngineInput(in engineInput, length int) (*engineInput, error) {
	if in.policyPin != "" && !enginePolicyPin(in.policyPin) {
		return nil, ErrInput
	}
	if !in.client.IsValid() || !in.server.IsValid() || !in.client.Addr().Is4() || !in.server.Addr().Is4() || in.client.Port() == 0 || in.server.Port() == 0 || in.publicPort == 0 || !engineDNS(in.sni) || !engineID(in.id) || in.protocol != "HTTP/1.1" || (in.method != "GET" && in.method != "HEAD" && in.method != "POST") || !engineTarget(in.target) || len(in.fields) > requestctx.MaxFields || length < 0 || length > MaxBody {
		return nil, ErrInput
	}
	if in.method != "POST" && length != 0 {
		return nil, ErrInput
	}
	copyInput := in
	copyInput.id, copyInput.sni = strings.Clone(in.id), strings.Clone(in.sni)
	copyInput.policyPin = strings.Clone(in.policyPin)
	copyInput.protocol, copyInput.method, copyInput.target = strings.Clone(in.protocol), strings.Clone(in.method), strings.Clone(in.target)
	copyInput.fields = make([]requestctx.Field, 0, len(in.fields))
	single := make(map[string]string, 4)
	budget := len(in.method) + 1 + len(in.target) + len(" HTTP/1.1\r\n") + 2
	for _, field := range in.fields {
		if !engineFieldName(field.Name) || !engineFieldValue(field.Value) {
			return nil, ErrInput
		}
		name := strings.ToLower(field.Name)
		if strings.HasPrefix(name, "aegvium-") || name == "forwarded" || name == "x-real-ip" || strings.HasPrefix(name, "x-forwarded-") {
			return nil, ErrInput
		}
		switch name {
		case "transfer-encoding", "content-encoding", "trailer", "te", "expect", "upgrade", "proxy-connection", "keep-alive":
			return nil, ErrInput
		case "host", "content-length", "content-type", "connection":
			if _, exists := single[name]; exists {
				return nil, ErrInput
			}
			single[name] = field.Value
		}
		if name == "x-amz-content-sha256" && strings.HasPrefix(field.Value, "STREAMING-") {
			return nil, ErrInput
		}
		budget += len(field.Name) + 2 + len(field.Value) + 2
		if budget > 4096 {
			return nil, ErrInput
		}
		copyInput.fields = append(copyInput.fields, requestctx.Field{Name: strings.Clone(field.Name), Value: strings.Clone(field.Value)})
	}
	host, port, explicit := strings.Cut(single["host"], ":")
	if strings.ToLower(host) != in.sni || explicit && port != strconv.Itoa(int(in.publicPort)) || !explicit && in.publicPort != 443 {
		return nil, ErrInput
	}
	if connection, exists := single["connection"]; exists && !strings.EqualFold(connection, "close") {
		return nil, ErrInput
	}
	text, exists := single["content-length"]
	if in.method == "POST" && !exists {
		return nil, ErrInput
	}
	if exists && text != strconv.Itoa(length) {
		return nil, ErrInput
	}
	if in.method == "POST" {
		media, attrs, err := mime.ParseMediaType(single["content-type"])
		if err != nil || (media != "application/json" && media != "application/x-www-form-urlencoded") || len(attrs) > 1 || len(attrs) == 1 && !strings.EqualFold(attrs["charset"], "utf-8") {
			return nil, ErrInput
		}
	}
	return &copyInput, nil
}

func enginePolicyPin(s string) bool {
	if len(s) != 64 {
		return false
	}
	for _, c := range []byte(s) {
		if !(c >= '0' && c <= '9' || c >= 'a' && c <= 'f') {
			return false
		}
	}
	return true
}

func engineID(s string) bool {
	if len(s) == 0 || len(s) > 64 {
		return false
	}
	for _, c := range []byte(s) {
		if !(c >= 'a' && c <= 'z' || c >= 'A' && c <= 'Z' || c >= '0' && c <= '9' || c == '_' || c == '-') {
			return false
		}
	}
	return true
}

func engineDNS(s string) bool {
	if len(s) == 0 || len(s) > 253 || strings.ToLower(s) != s || strings.HasSuffix(s, ".") {
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

func engineTarget(s string) bool {
	if len(s) == 0 || len(s) > requestctx.MaxTarget || s[0] != '/' {
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

func engineFieldName(s string) bool {
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

func engineFieldValue(s string) bool {
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
