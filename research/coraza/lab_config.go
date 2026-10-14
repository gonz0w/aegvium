// SPDX-License-Identifier: BSD-3-Clause
package spike

import (
	"bytes"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"errors"
	"io"
	"net/netip"
	"net/url"
	"os"
	"path/filepath"
	"strings"
)

const LabConfigLimit = 8192

// LabRoute and LabConfig are owned-lab inputs, not an appliance configuration API.
type LabRoute struct {
	Host          string `json:"host"`
	Backend       string `json:"backend"`
	TLSServerName string `json:"tls_server_name,omitempty"`
	TLSCAFile     string `json:"tls_ca_file,omitempty"`
}
type LabConfig struct {
	Version int        `json:"version"`
	Routes  []LabRoute `json:"routes"`
}

func labName(name string) bool {
	if len(name) > 253 || !strings.HasSuffix(name, ".test") {
		return false
	}
	for _, label := range strings.Split(name, ".") {
		if len(label) == 0 || len(label) > 63 || label[0] == '-' || label[len(label)-1] == '-' {
			return false
		}
		for _, c := range label {
			if c != '-' && (c < 'a' || c > 'z') && (c < '0' || c > '9') {
				return false
			}
		}
	}
	return true
}

// Inspect tokens first: encoding/json otherwise accepts repeated and folded keys.
func labJSONValue(d *json.Decoder, depth int) error {
	if depth > 16 {
		return errors.New("lab JSON nesting bound")
	}
	token, e := d.Token()
	if e != nil {
		return e
	}
	delim, ok := token.(json.Delim)
	if !ok {
		return nil
	}
	switch delim {
	case '{':
		seen := map[string]bool{}
		for d.More() {
			key, e := d.Token()
			if e != nil {
				return e
			}
			s, ok := key.(string)
			if !ok || seen[s] {
				return errors.New("duplicate lab JSON key")
			}
			seen[s] = true
			if e = labJSONValue(d, depth+1); e != nil {
				return e
			}
		}
	case '[':
		for d.More() {
			if e = labJSONValue(d, depth+1); e != nil {
				return e
			}
		}
	default:
		return errors.New("invalid lab JSON delimiter")
	}
	_, e = d.Token()
	return e
}
func labKeys(data []byte, allowed ...string) error {
	var values map[string]json.RawMessage
	if e := json.Unmarshal(data, &values); e != nil {
		return e
	}
	if values == nil {
		return errors.New("lab JSON object required")
	}
	for key := range values {
		found := false
		for _, name := range allowed {
			found = found || key == name
		}
		if !found {
			return errors.New("unknown lab JSON field")
		}
	}
	return nil
}

func ReadLabConfig(r io.Reader) (LabConfig, error) {
	var config LabConfig
	data, e := io.ReadAll(io.LimitReader(r, LabConfigLimit+1))
	if e != nil || len(data) > LabConfigLimit {
		return config, errors.New("lab config read/bound")
	}
	d := json.NewDecoder(bytes.NewReader(data))
	if e = labJSONValue(d, 0); e != nil {
		return config, e
	}
	if _, e = d.Token(); e != io.EOF {
		return config, errors.New("trailing lab JSON")
	}
	if e = labKeys(data, "version", "routes"); e != nil {
		return config, e
	}
	if e = json.Unmarshal(data, &config); e != nil {
		return config, e
	}
	var raw struct {
		Routes []json.RawMessage `json:"routes"`
	}
	if e = json.Unmarshal(data, &raw); e != nil {
		return config, e
	}
	for _, route := range raw.Routes {
		if e = labKeys(route, "host", "backend", "tls_server_name", "tls_ca_file"); e != nil {
			return config, e
		}
	}
	if config.Version != 1 || len(config.Routes) < 1 || len(config.Routes) > 8 {
		return config, errors.New("lab config version/route bound")
	}
	seen := map[string]bool{}
	for _, route := range config.Routes {
		if !labName(route.Host) || seen[route.Host] {
			return config, errors.New("invalid/duplicate lab host")
		}
		seen[route.Host] = true
		if _, _, e = labRouteTarget(route); e != nil {
			return config, e
		}
	}
	return config, nil
}

func ReadLabFile(path string, limit int) ([]byte, error) {
	// No symlinks or special files; this is an owned fixture, not a sender auth boundary.
	info, e := os.Lstat(path)
	if e != nil || !info.Mode().IsRegular() || info.Size() > int64(limit) {
		return nil, errors.New("lab file must be bounded regular input")
	}
	file, e := os.Open(path)
	if e != nil {
		return nil, e
	}
	defer file.Close()
	data, e := io.ReadAll(io.LimitReader(file, int64(limit)+1))
	if e != nil || len(data) > limit {
		return nil, errors.New("lab file read/bound")
	}
	return data, nil
}
func labRouteTarget(route LabRoute) (*url.URL, *tls.Config, error) {
	target, e := url.Parse(route.Backend)
	if e != nil || target == nil || target.Opaque != "" || (target.Scheme != "http" && target.Scheme != "https") || target.User != nil || target.Path != "" || target.RawQuery != "" || target.ForceQuery || target.Fragment != "" || strings.ContainsAny(route.Backend, "?#") {
		return nil, nil, errors.New("invalid lab backend URL")
	}
	address, e := netip.ParseAddrPort(target.Host)
	if e != nil || address.Addr() != netip.MustParseAddr("127.0.0.1") || address.Port() < 1024 || address.Port() == 18084 || address.Port() == 18085 || address.Port() == 18120 {
		return nil, nil, errors.New("invalid lab backend endpoint")
	}
	if target.Scheme == "http" {
		if route.TLSServerName != "" || route.TLSCAFile != "" {
			return nil, nil, errors.New("TLS fields on HTTP route")
		}
		return target, nil, nil
	}
	if !labName(route.TLSServerName) || !filepath.IsAbs(route.TLSCAFile) {
		return nil, nil, errors.New("lab HTTPS requires explicit name/CA")
	}
	data, e := ReadLabFile(route.TLSCAFile, 65536)
	if e != nil {
		return nil, nil, e
	}
	pool := x509.NewCertPool()
	if !pool.AppendCertsFromPEM(data) {
		return nil, nil, errors.New("invalid lab CA PEM")
	}
	return target, &tls.Config{RootCAs: pool, ServerName: route.TLSServerName, MinVersion: tls.VersionTLS12}, nil
}
func (c LabConfig) Profile() LabProfile {
	return LabProfile{DataAddress: "127.0.0.1:18084", HealthAddress: "127.0.0.1:18085", Ingress: netip.MustParseAddrPort("127.0.0.1:18120"), Routes: c.Routes}
}
