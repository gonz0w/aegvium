# SPDX-License-Identifier: BSD-3-Clause
"""Local research regression gate; residuals never authorize appliance adoption."""
import hashlib
import json
import os
import subprocess
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]


def objects(raw):
    decoder = json.JSONDecoder()
    while raw.strip():
        item, end = decoder.raw_decode(raw.lstrip())
        yield item
        raw = raw.lstrip()[end:]


def admit(raw, expected, allowed, version):
    messages = list(objects(raw))
    if any(not isinstance(m, dict) or len(m) != 1 or
           next(iter(m)) not in {'config', 'SBOM', 'osv', 'finding', 'progress'} for m in messages):
        raise ValueError('unknown/malformed advisory message')
    configs = [m['config'] for m in messages if 'config' in m]
    inventories = [m['SBOM'] for m in messages if 'SBOM' in m]
    if len(configs) != 1 or len(inventories) != 1:
        raise ValueError('missing/duplicate scanner configuration or SBOM')
    config, inventory = configs[0], inventories[0]
    wanted = {'scanner_name': 'govulncheck', 'scanner_version': 'v1.9.0',
              'scan_level': 'symbol', 'scan_mode': 'source', 'go_version': 'go' + version,
              'db': 'https://vuln.go.dev'}
    if any(config.get(k) != v for k, v in wanted.items()) or not config.get('db_last_modified'):
        raise ValueError('scanner/database/toolchain coverage differs')
    modules = inventory.get('modules', [])
    actual = {m['path']: m.get('version', '') for m in modules}
    if (len(actual) != len(modules) or actual != expected or
            inventory.get('go_version') != 'go' + version or not inventory.get('roots')):
        raise ValueError('scanner SBOM differs from independently loaded graph')
    definitions = {m['osv']['id'] for m in messages if 'osv' in m}
    findings = {}
    for message in messages:
        if 'finding' not in message:
            continue
        finding = message['finding']
        trace = finding.get('trace', [])
        if not trace or finding.get('osv') not in definitions:
            raise ValueError('finding lacks trace or advisory definition')
        frame = trace[0]
        module = frame.get('module')
        if module not in expected or frame.get('version', '') != expected[module]:
            raise ValueError('finding module/version differs from loaded graph')
        level = 2 if frame.get('function') else 1 if frame.get('package') else 0
        exception = allowed.get(finding['osv'])
        if (not exception or module != exception['module'] or
                frame.get('version') != exception['version'] or level > exception['maximum_level']):
            raise ValueError('unreviewed advisory or increased reachability: ' + finding['osv'])
        findings[finding['osv']] = max(level, findings.get(finding['osv'], -1))
    return {'admitted': True, 'config': config, 'sbom_modules': len(actual),
            'module_ids': sorted(findings),
            'package_ids': sorted(k for k, v in findings.items() if v >= 1),
            'symbol_ids': sorted(k for k, v in findings.items() if v >= 2),
            'residuals': {k: allowed[k] for k in sorted(findings)},
            'raw_sha256': hashlib.sha256(raw.encode()).hexdigest()}


def scan(module, target, policy, work, version):
    env = {**os.environ, 'PATH': str(ROOT / '.tools/go/bin') + os.pathsep + os.environ['PATH'],
           'GOTOOLCHAIN': 'local', 'GOCACHE': str(ROOT / '.tools/go-cache'),
           'GOWORK': 'off', 'GOENV': 'off', 'GOFLAGS': '-mod=readonly',
           'GOTELEMETRY': 'off', 'CGO_ENABLED': '0'}
    if target == 'openbsd-amd64':
        env.update(GOOS='openbsd', GOARCH='amd64')
    else:
        env.pop('GOOS', None)
        env.pop('GOARCH', None)
    cwd = ROOT / 'research' / module
    output = subprocess.check_output([str(ROOT / 'tools/run-research-go.sh'), 'list',
                                      '-mod=readonly', '-test', '-deps', '-json', './...'],
                                     cwd=cwd, env=env, text=True, timeout=180)
    expected = {'stdlib': 'v' + version}
    for package in objects(output):
        identity = package.get('Module')
        if identity:
            if identity.get('Replace'):
                raise ValueError('replacement module requires separate review')
            expected[identity['Path']] = identity.get('Version', '')
    if len(expected) < 3:
        raise ValueError('inadequate loaded package graph')
    stem = module + '-' + target
    rawpath, errpath = work / (stem + '.json'), work / (stem + '.stderr')
    with rawpath.open('wb') as output, errpath.open('wb') as errors:
        result = subprocess.run([str(ROOT / '.tools/research-bin/govulncheck'), '-json', '-test', './...'],
                                cwd=cwd, env=env, stdout=output, stderr=errors, timeout=300)
    if result.returncode:
        raise RuntimeError('advisory scan failed; retained ignored logs: ' + stem)
    report = admit(rawpath.read_text(), expected, policy[module], version)
    report['graph_sha256'] = hashlib.sha256(json.dumps(expected, sort_keys=True).encode()).hexdigest()
    report['module_files'] = {name: hashlib.sha256((cwd / name).read_bytes()).hexdigest()
                              for name in ('go.mod', 'go.sum')}
    print(stem + ': ' + str(len(report['symbol_ids'])) + ' symbol IDs, ' +
          str(len(report['package_ids'])) + ' package IDs, ' + str(len(report['module_ids'])) + ' module IDs', flush=True)
    return report


def main():
    policy = json.loads((ROOT / 'research/advisory-policy.json').read_text())['modules']
    version = (ROOT / '.go-version').read_text().strip()
    work = ROOT / '.tools/research-advisories'
    work.mkdir(exist_ok=True)
    reports = {}
    for module in ('coraza', 'connector'):
        for target in ('host', 'openbsd-amd64'):
            reports[module + '/' + target] = scan(module, target, policy, work, version)
    (work / 'report.json').write_text(json.dumps({'scans': reports, 'adoption': False}, indent=2) + '\n')


if __name__ == '__main__':
    main()
