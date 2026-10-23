# SPDX-License-Identifier: BSD-3-Clause
# Native8.0 source recipe only. Never invoked by portable validation.
PACKAGE= aegvium-0.0.0
ROOT= ${.CURDIR}/../..
WORK= ${.CURDIR}/.source-package
STAGE= ${WORK}/root
GO_BUILD_ENV= env PATH=/usr/local/bin:/usr/bin:/bin GOTOOLCHAIN=local GOPROXY=off GOSUMDB=off GOENV=off GOWORK=off GOVCS=off GOFLAGS='' GOOS=openbsd GOARCH=$$(uname -m) CGO_ENABLED=0 GOMAXPROCS=2

all:
	@echo 'Unqualified source package; commissioning and runtime entries remain closed.' >&2
	@exit 77

# No fetch, install, signing, service, credential, target-image or cleanup target.
# Run only in an independently authenticated fresh source/build environment.
source-package:
	@test "$$(uname -s)" = OpenBSD && test "$$(uname -r)" = 8.0
	@test "$$(id -u)" != 0
	@case "$$(uname -m)" in amd64|arm64) ;; *) exit 1 ;; esac
	@test "$$( ${GO_BUILD_ENV} go env GOVERSION)" = "go$$(cat '${ROOT}/.go-version')"
	@test ! -e '${WORK}'
	@umask 077; mkdir '${WORK}'
	@set -eu; set -- /usr/lib/libc.so.*; { [ "$$#" -eq 1 ] && [ -f "$$1" ] && [ ! -L "$$1" ]; } || exit 77; version=$${1##*/libc.so.}; major=$${version%%.*}; minor=$${version#*.}; { [ -n "$$major" ] && [ -n "$$minor" ] && [ "$$major" != "$$version" ]; } || exit 77; case "$$major$$minor" in *[!0-9]* ) exit 77 ;; esac; printf 'c.%s.%s\n' "$$major" "$$minor" > '${WORK}/libc.wantlib'
	install -d -m 0755 '${STAGE}/usr/local/libexec/aegvium' '${STAGE}/usr/local/share/aegvium' '${STAGE}/usr/local/share/doc/aegvium'
	${GO_BUILD_ENV} go env GOROOT > '${WORK}/build.goroot'
	${GO_BUILD_ENV} go env GOMODCACHE > '${WORK}/build.modcache'
	cd '${ROOT}' && ${GO_BUILD_ENV} go build -mod=readonly -p=2 -buildvcs=false -trimpath -tags 'aegvium_transport_source,aegvium_engine_source,no_fs_access' -o '${STAGE}/usr/local/libexec/aegvium/inspector' ./cmd/aegvium-inspector
	cd '${ROOT}' && ${GO_BUILD_ENV} go build -mod=readonly -p=2 -buildvcs=false -trimpath -tags aegvium_frontend_source -o '${STAGE}/usr/local/libexec/aegvium/frontend-owner' ./cmd/aegvium-frontend-owner
	cd '${ROOT}' && ${GO_BUILD_ENV} go build -mod=readonly -p=2 -buildvcs=false -trimpath -tags aegvium_commission_source -o '${STAGE}/usr/local/libexec/aegvium/commission' ./cmd/aegvium-commission
	cd '${ROOT}' && cc -std=c11 -Wall -Wextra -Werror -pedantic -DAEG_INSPECTOR_SOURCE -Iinternal/inspectorowner cmd/aegvium-supervisor/main.c internal/inspectorowner/controller.c internal/inspectorowner/control_frame.c internal/inspectorowner/launch_storage.c internal/inspectorowner/storage_openbsd.c internal/inspectorowner/native_construction.c internal/inspectorowner/native_openbsd.c internal/inspectorowner/launch_source_openbsd.c -o '${STAGE}/usr/local/libexec/aegvium/supervisor'
	chmod 0555 '${STAGE}/usr/local/libexec/aegvium/inspector' '${STAGE}/usr/local/libexec/aegvium/supervisor' '${STAGE}/usr/local/libexec/aegvium/frontend-owner' '${STAGE}/usr/local/libexec/aegvium/commission'
	{ set -eu; printf 'AEGBIN1\n'; for name in inspector supervisor frontend-owner; do file='${STAGE}/usr/local/libexec/aegvium/'$$name; size=$$(stat -f %z "$$file") || exit 77; limit=67108864; [ "$$name" != supervisor ] || limit=1048576; { [ "$$size" -ge 1 ] && [ "$$size" -le "$$limit" ]; } || exit 77; digest=$$(sha256 -q "$$file") || exit 77; [ "$${#digest}" -eq 64 ] || exit 77; case "$$digest" in *[!0-9a-f]*) exit 77 ;; esac; printf '%s %s %s\n' "$$name" "$$size" "$$digest"; done; } > '${STAGE}/usr/local/share/aegvium/package.images'
	chmod 0444 '${STAGE}/usr/local/share/aegvium/package.images'
	install -m 0444 '${ROOT}/LICENSE' '${STAGE}/usr/local/share/doc/aegvium/LICENSE'
	install -m 0444 '${ROOT}/internal/frontendowner/LICENSE.Vectivium' '${STAGE}/usr/local/share/doc/aegvium/LICENSE.Vectivium'
	install -m 0444 '${ROOT}/internal/frontendowner/LICENSE.x-sys' '${STAGE}/usr/local/share/doc/aegvium/LICENSE.x-sys'
	# Fixed known notice inputs, not a recursive license collector. Missing input aborts.
	install -d -m 0755 '${STAGE}/usr/local/share/doc/aegvium/licenses'
	install -m 0444 "$$(cat '${WORK}/build.goroot')/LICENSE" '${STAGE}/usr/local/share/doc/aegvium/licenses/Go.LICENSE'
	install -m 0444 "$$(cat '${WORK}/build.goroot')/PATENTS" '${STAGE}/usr/local/share/doc/aegvium/licenses/Go.PATENTS'
	install -m 0444 "$$(cat '${WORK}/build.goroot')/src/vendor/golang.org/x/crypto/LICENSE" '${STAGE}/usr/local/share/doc/aegvium/licenses/Go-vendor-x-crypto.LICENSE'
	install -m 0444 "$$(cat '${WORK}/build.goroot')/src/vendor/golang.org/x/crypto/PATENTS" '${STAGE}/usr/local/share/doc/aegvium/licenses/Go-vendor-x-crypto.PATENTS'
	install -m 0444 "$$(cat '${WORK}/build.goroot')/src/vendor/golang.org/x/net/LICENSE" '${STAGE}/usr/local/share/doc/aegvium/licenses/Go-vendor-x-net.LICENSE'
	install -m 0444 "$$(cat '${WORK}/build.goroot')/src/vendor/golang.org/x/net/PATENTS" '${STAGE}/usr/local/share/doc/aegvium/licenses/Go-vendor-x-net.PATENTS'
	install -m 0444 "$$(cat '${WORK}/build.goroot')/src/vendor/golang.org/x/sys/LICENSE" '${STAGE}/usr/local/share/doc/aegvium/licenses/Go-vendor-x-sys.LICENSE'
	install -m 0444 "$$(cat '${WORK}/build.goroot')/src/vendor/golang.org/x/sys/PATENTS" '${STAGE}/usr/local/share/doc/aegvium/licenses/Go-vendor-x-sys.PATENTS'
	install -m 0444 "$$(cat '${WORK}/build.goroot')/src/vendor/golang.org/x/text/LICENSE" '${STAGE}/usr/local/share/doc/aegvium/licenses/Go-vendor-x-text.LICENSE'
	install -m 0444 "$$(cat '${WORK}/build.goroot')/src/vendor/golang.org/x/text/PATENTS" '${STAGE}/usr/local/share/doc/aegvium/licenses/Go-vendor-x-text.PATENTS'
	install -m 0444 "$$(cat '${WORK}/build.modcache')/github.com/corazawaf/coraza-coreruleset/v4@v4.25.0/LICENSE" '${STAGE}/usr/local/share/doc/aegvium/licenses/coraza-coreruleset-v4.25.0.LICENSE'
	install -m 0444 "$$(cat '${WORK}/build.modcache')/github.com/corazawaf/coraza-coreruleset/v4@v4.25.0/rules/LICENSE" '${STAGE}/usr/local/share/doc/aegvium/licenses/coraza-coreruleset-v4.25.0.rules-LICENSE'
	install -m 0444 "$$(cat '${WORK}/build.modcache')/github.com/corazawaf/coraza/v3@v3.8.1/LICENSE" '${STAGE}/usr/local/share/doc/aegvium/licenses/coraza-v3.8.1.LICENSE'
	install -m 0444 "$$(cat '${WORK}/build.modcache')/github.com/corazawaf/libinjection-go@v0.3.3/LICENSE" '${STAGE}/usr/local/share/doc/aegvium/licenses/libinjection-go-v0.3.3.LICENSE'
	install -m 0444 "$$(cat '${WORK}/build.modcache')/github.com/goccy/go-json@v0.10.5/LICENSE" '${STAGE}/usr/local/share/doc/aegvium/licenses/go-json-v0.10.5.LICENSE'
	install -m 0444 "$$(cat '${WORK}/build.modcache')/github.com/goccy/go-yaml@v1.19.2/LICENSE" '${STAGE}/usr/local/share/doc/aegvium/licenses/go-yaml-v1.19.2.LICENSE'
	install -m 0444 "$$(cat '${WORK}/build.modcache')/github.com/gotnospirit/makeplural@v0.0.0-20180622080156-a5f48d94d976/LICENSE" '${STAGE}/usr/local/share/doc/aegvium/licenses/makeplural-a5f48d94d976.LICENSE'
	install -m 0444 "$$(cat '${WORK}/build.modcache')/github.com/gotnospirit/messageformat@v0.0.0-20221001023931-dfe49f1eb092/LICENSE" '${STAGE}/usr/local/share/doc/aegvium/licenses/messageformat-dfe49f1eb092.LICENSE'
	install -m 0444 "$$(cat '${WORK}/build.modcache')/github.com/kaptinlin/go-i18n@v0.1.4/LICENSE" '${STAGE}/usr/local/share/doc/aegvium/licenses/go-i18n-v0.1.4.LICENSE'
	install -m 0444 "$$(cat '${WORK}/build.modcache')/github.com/kaptinlin/jsonschema@v0.4.6/LICENSE" '${STAGE}/usr/local/share/doc/aegvium/licenses/jsonschema-v0.4.6.LICENSE'
	install -m 0444 "$$(cat '${WORK}/build.modcache')/github.com/petar-dambovaliev/aho-corasick@v0.0.0-20250424160509-463d218d4745/LICENSE" '${STAGE}/usr/local/share/doc/aegvium/licenses/aho-corasick-463d218d4745.LICENSE'
	install -m 0444 "$$(cat '${WORK}/build.modcache')/github.com/tidwall/gjson@v1.18.0/LICENSE" '${STAGE}/usr/local/share/doc/aegvium/licenses/gjson-v1.18.0.LICENSE'
	install -m 0444 "$$(cat '${WORK}/build.modcache')/github.com/tidwall/match@v1.1.1/LICENSE" '${STAGE}/usr/local/share/doc/aegvium/licenses/match-v1.1.1.LICENSE'
	install -m 0444 "$$(cat '${WORK}/build.modcache')/github.com/tidwall/pretty@v1.2.1/LICENSE" '${STAGE}/usr/local/share/doc/aegvium/licenses/pretty-v1.2.1.LICENSE'
	install -m 0444 "$$(cat '${WORK}/build.modcache')/github.com/valllabh/ocsf-schema-golang@v1.0.3/LICENSE" '${STAGE}/usr/local/share/doc/aegvium/licenses/ocsf-schema-golang-v1.0.3.LICENSE'
	install -m 0444 "$$(cat '${WORK}/build.modcache')/golang.org/x/net@v0.60.0/LICENSE" '${STAGE}/usr/local/share/doc/aegvium/licenses/x-net-v0.60.0.LICENSE'
	install -m 0444 "$$(cat '${WORK}/build.modcache')/golang.org/x/net@v0.60.0/PATENTS" '${STAGE}/usr/local/share/doc/aegvium/licenses/x-net-v0.60.0.PATENTS'
	install -m 0444 "$$(cat '${WORK}/build.modcache')/golang.org/x/sync@v0.23.0/LICENSE" '${STAGE}/usr/local/share/doc/aegvium/licenses/x-sync-v0.23.0.LICENSE'
	install -m 0444 "$$(cat '${WORK}/build.modcache')/golang.org/x/sync@v0.23.0/PATENTS" '${STAGE}/usr/local/share/doc/aegvium/licenses/x-sync-v0.23.0.PATENTS'
	install -m 0444 "$$(cat '${WORK}/build.modcache')/golang.org/x/sys@v0.49.0/LICENSE" '${STAGE}/usr/local/share/doc/aegvium/licenses/x-sys-v0.49.0.LICENSE'
	install -m 0444 "$$(cat '${WORK}/build.modcache')/golang.org/x/sys@v0.49.0/PATENTS" '${STAGE}/usr/local/share/doc/aegvium/licenses/x-sys-v0.49.0.PATENTS'
	install -m 0444 "$$(cat '${WORK}/build.modcache')/golang.org/x/text@v0.42.0/LICENSE" '${STAGE}/usr/local/share/doc/aegvium/licenses/x-text-v0.42.0.LICENSE'
	install -m 0444 "$$(cat '${WORK}/build.modcache')/golang.org/x/text@v0.42.0/PATENTS" '${STAGE}/usr/local/share/doc/aegvium/licenses/x-text-v0.42.0.PATENTS'
	install -m 0444 "$$(cat '${WORK}/build.modcache')/google.golang.org/protobuf@v1.36.11/LICENSE" '${STAGE}/usr/local/share/doc/aegvium/licenses/protobuf-v1.36.11.LICENSE'
	install -m 0444 "$$(cat '${WORK}/build.modcache')/google.golang.org/protobuf@v1.36.11/PATENTS" '${STAGE}/usr/local/share/doc/aegvium/licenses/protobuf-v1.36.11.PATENTS'
	install -m 0444 "$$(cat '${WORK}/build.modcache')/rsc.io/binaryregexp@v0.2.0/LICENSE" '${STAGE}/usr/local/share/doc/aegvium/licenses/binaryregexp-v0.2.0.LICENSE'
	# Separate native stock/product signature and exact recursive closure acceptance remain mandatory.
	pkg_create -B '${STAGE}' -p /usr/local -d DESCR -f PLIST -P 'net/haproxy:=:haproxy-3.2.25' -W "$$(cat '${WORK}/libc.wantlib')" -D COMMENT='Standalone WAF source candidate' -D FULLPKGPATH=local/aegvium -D PORTSDIR=/usr/ports '${WORK}/${PACKAGE}'
