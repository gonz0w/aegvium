# SPDX-License-Identifier: BSD-3-Clause
"""Pure source inventory controls; never invokes make/pkg_create/native code."""
from pathlib import Path
import unittest

ROOT = Path(__file__).resolve().parents[2]


class OpenBSDPackageTests(unittest.TestCase):
    def test_package_assets_exclude_per_instance_authority(self):
        lines = (ROOT / 'packaging/openbsd/PLIST').read_text().splitlines()
        files = [line for line in lines if line and not line.startswith('@')]
        self.assertEqual(files, [
            'libexec/aegvium/inspector', 'libexec/aegvium/supervisor',
            'libexec/aegvium/frontend-owner', 'libexec/aegvium/commission',
            'libexec/aegvium/service',
            'share/aegvium/package.images', 'share/doc/aegvium/LICENSE',
            'share/doc/aegvium/LICENSE.Vectivium', 'share/doc/aegvium/LICENSE.x-sys'] +
            ['share/doc/aegvium/licenses/' + name for name in (
                'Go.LICENSE',
                'Go.PATENTS',
                'Go-vendor-x-crypto.LICENSE',
                'Go-vendor-x-crypto.PATENTS',
                'Go-vendor-x-net.LICENSE',
                'Go-vendor-x-net.PATENTS',
                'Go-vendor-x-sys.LICENSE',
                'Go-vendor-x-sys.PATENTS',
                'Go-vendor-x-text.LICENSE',
                'Go-vendor-x-text.PATENTS',
                'coraza-coreruleset-v4.25.0.LICENSE',
                'coraza-coreruleset-v4.25.0.rules-LICENSE',
                'coraza-v3.8.1.LICENSE',
                'libinjection-go-v0.3.3.LICENSE',
                'go-json-v0.10.5.LICENSE',
                'go-yaml-v1.19.2.LICENSE',
                'makeplural-a5f48d94d976.LICENSE',
                'messageformat-dfe49f1eb092.LICENSE',
                'go-i18n-v0.1.4.LICENSE',
                'jsonschema-v0.4.6.LICENSE',
                'aho-corasick-463d218d4745.LICENSE',
                'gjson-v1.18.0.LICENSE',
                'match-v1.1.1.LICENSE',
                'pretty-v1.2.1.LICENSE',
                'ocsf-schema-golang-v1.0.3.LICENSE',
                'x-net-v0.60.0.LICENSE',
                'x-net-v0.60.0.PATENTS',
                'x-sync-v0.23.0.LICENSE',
                'x-sync-v0.23.0.PATENTS',
                'x-sys-v0.49.0.LICENSE',
                'x-sys-v0.49.0.PATENTS',
                'x-text-v0.42.0.LICENSE',
                'x-text-v0.42.0.PATENTS',
                'protobuf-v1.36.11.LICENSE',
                'protobuf-v1.36.11.PATENTS',
                'binaryregexp-v0.2.0.LICENSE',
            )])
        self.assertEqual([line for line in lines if line.startswith('@rcscript')], ['@rcscript /etc/rc.d/aegvium'])
        self.assertFalse(any(line.startswith(('@exec', '@unexec', '@newuser', '@newgroup')) for line in lines))
        self.assertFalse(any('/etc/' in line or '/var/db/' in line for line in files))

    def test_closed_commission_and_offline_native_recipe(self):
        recipe = (ROOT / 'packaging/openbsd/Makefile').read_text()
        for required in ('GOTOOLCHAIN=local', 'GOPROXY=off', 'GOSUMDB=off',
                         'GOFLAGS=\'\'', '-mod=readonly', 'test "$$(uname -r)" = 8.0',
                         "-P 'net/haproxy:=:haproxy-3.2.25'", '-B', '-p /usr/local'):
            self.assertIn(required, recipe)
        for guard in (
                '{ [ "$$#" -eq 1 ] && [ -f "$$1" ] && [ ! -L "$$1" ]; } || exit 77;',
                '{ [ -n "$$major" ] && [ -n "$$minor" ] && [ "$$major" != "$$version" ]; } || exit 77;',
                '{ [ "$$size" -ge 1 ] && [ "$$size" -le "$$limit" ]; } || exit 77;'):
            self.assertIn(guard, recipe)
        self.assertIn('go env GOROOT', recipe)
        self.assertIn('go env GOMODCACHE', recipe)
        self.assertIn('/src/vendor/golang.org/x/crypto/PATENTS', recipe)
        self.assertIn('/github.com/corazawaf/coraza-coreruleset/v4@v4.25.0/rules/LICENSE', recipe)
        self.assertIn('/golang.org/x/sys@v0.49.0/PATENTS', recipe)
        entry = (ROOT / 'cmd/aegvium-commission/source_openbsd.go').read_text()
        self.assertIn('len(os.Args) != 1', entry)
        self.assertIn('commissionplace.RunProduction()', entry)
        native = (ROOT / 'internal/commissionplace/production_openbsd.go').read_text()
        self.assertIn('const nativeProductionCommissionQualified = false', native)
        self.assertLess(native.index('if !nativeProductionCommissionQualified'), native.index('return runProduction()'))
        self.assertIn('readRoleMaterials(root, dirs, descriptor)', native)
        self.assertIn('placeFrontendFrom(root, dirs, descriptor, true)', native)
        self.assertNotIn('installBytes(root, dirs, "usr/local/libexec', native)

    def test_service_source_keeps_pending_stop_and_restart_refusal(self):
        client = (ROOT / 'internal/localcontrol/client_openbsd.go').read_text()
        self.assertIn('const nativeServiceQualified = false', client)
        rc = (ROOT / 'packaging/openbsd/aegvium.rc').read_text()
        self.assertIn('"${control}" frontend stop', rc)
        self.assertIn('"${control}" inspector stop', rc)
        self.assertIn('restart|reload) exit 1', rc)
        self.assertIn('stop) rc_stop ;;', rc)
        self.assertNotIn('start|stop|check) rc_cmd', rc)
        self.assertNotIn('pkill', rc)
        self.assertNotIn('pgrep', rc)
        self.assertNotIn('kill ', rc)
        placement = (ROOT / 'internal/commissionplace/frontend_openbsd.go').read_text()
        self.assertIn('frontend-mode', placement)
        closure = (ROOT / 'internal/commissionplace/extension_openbsd.go').read_text()
        self.assertIn('service_control.c', closure)
        self.assertIn('service_control.h', closure)


if __name__ == '__main__':
    unittest.main()
