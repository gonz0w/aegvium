// SPDX-License-Identifier: BSD-3-Clause
package comparison

import (
	"encoding/json"
	"fmt"
	"net"

	"github.com/caddyserver/caddy/v2"
	_ "github.com/caddyserver/caddy/v2/modules/caddyhttp/reverseproxy"
	_ "github.com/caddyserver/caddy/v2/modules/filestorage"
)

// This is owned research configuration, not an appliance configuration format.
type serverFixtureConfig struct {
	listen, plain, secure, cert, key, ca, storage, apiHost string
	strict                                                 bool
}

func configuredServer(c serverFixtureConfig) ([]byte, error) {
	for _, addr := range []string{c.listen, c.plain, c.secure} {
		host, _, err := net.SplitHostPort(addr)
		if err != nil || host != "127.0.0.1" {
			return nil, fmt.Errorf("owned loopback address required")
		}
	}
	if c.apiHost != "api.test" && c.apiHost != "alt.test" {
		return nil, fmt.Errorf("owned authority required")
	}
	type object = map[string]any
	static := func(code int) object { return object{"handler": "static_response", "status_code": code} }
	route := func(host, dial, backendHost string, secure bool) object {
		transport := object{"protocol": "http", "versions": []string{"1.1"}, "dial_timeout": "1s", "response_header_timeout": "1s", "keep_alive": object{"enabled": false}}
		if secure {
			transport["tls"] = object{"server_name": "api.test", "handshake_timeout": "1s", "ca": object{"provider": "file", "pem_files": []string{c.ca}}}
		}
		return object{"match": []object{{"host": []string{host}}}, "handle": []object{
			{"handler": "waf", "load_owasp_crs": true, "directives": directivesForServer},
			{"handler": "reverse_proxy", "upstreams": []object{{"dial": dial}}, "transport": transport,
				"headers": object{"request": object{"set": object{"Host": []string{backendHost}}, "delete": []string{"Forwarded", "X-Forwarded-*", "X-Real-IP", "X-Original-URL", "X-Rewrite-URL", "Proxy-Authorization", "Proxy-Connection"}}}},
		}, "terminal": true}
	}
	routes := []object{
		{"match": []object{{"header": object{"Upgrade": []string{"*"}}}}, "handle": []object{static(501)}, "terminal": true},
		route("app.test", c.plain, "app.test", false), route(c.apiHost, c.secure, c.apiHost, true),
		{"handle": []object{static(421)}}}
	config := object{
		"admin":   object{"disabled": true, "config": object{"persist": false}},
		"storage": object{"module": "file_system", "root": c.storage},
		"apps": object{
			"tls": object{"certificates": object{"load_files": []object{{"certificate": c.cert, "key": c.key}}}},
			"http": object{"grace_period": "1s", "servers": object{"owned": object{
				"listen": []string{c.listen}, "protocols": []string{"h1"}, "automatic_https": object{"disable": true},
				"tls_connection_policies": []object{{"protocol_min": "tls1.2"}}, "strict_sni_host": c.strict,
				"read_header_timeout": "1s", "read_timeout": "2s", "write_timeout": "3s", "idle_timeout": "1s", "routes": routes,
			}}},
		},
	}
	return json.Marshal(config)
}

const directivesForServer = "Include @coraza.conf-recommended\nSecRuleEngine On\nSecRequestBodyInMemoryLimit 4096\nSecRequestBodyLimit 4096\nInclude @crs-setup.conf.example\nInclude @owasp_crs/*.conf\n" +
	`SecRule RESPONSE_HEADERS:X-Lab-Response "@streq blocked" "id:100101,phase:3,deny,status:406,nolog"` + "\n" +
	`SecRule RESPONSE_BODY "@contains aegvium-leak" "id:100102,phase:4,deny,status:406,nolog"` + "\n"

func loadConfiguredServer(c serverFixtureConfig) error {
	raw, err := configuredServer(c)
	if err != nil {
		return err
	}
	return caddy.Load(raw, true)
}
