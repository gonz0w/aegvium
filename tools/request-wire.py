# SPDX-License-Identifier: BSD-3-Clause
"""Native direct/relayd request-wire admission; no log normalization."""
import hashlib
import importlib.util
import json
import re
from pathlib import Path
ROOT = Path(__file__).resolve().parents[1]
SPEC = importlib.util.spec_from_file_location('request_wire_tls', ROOT/'tools/lab-tls.py')
TLS = importlib.util.module_from_spec(SPEC); SPEC.loader.exec_module(TLS)
EXPECTED = json.loads((ROOT/'research/coraza/request-wire-expectations.json').read_text())
FINAL = 'REQUEST-WIRE-FINAL modes=2 cases=52 client_deadline_accepted=false'
MODE = 'REQUEST-WIRE-MODE client_identity=true'


def admit(text, hashes):
    result = TLS.admit(text, hashes, request_wire=True)
    rows = [json.loads(line.split('REQUEST-WIRE ',1)[1]) for line in text.splitlines() if 'REQUEST-WIRE {' in line]
    if rows != EXPECTED or any(set(row) != set(EXPECTED[0]) or any(type(row[k]) is not int for k in ('sent','status','responses','backend','trailers')) or any(type(row[k]) is not bool for k in ('verified_tls','server_closed','headers_clean','additional_byte')) for row in rows):
        raise ValueError('request wire input/framing/effects/close drift')
    if text.count(FINAL) != 1 or text.count(MODE) != 1:
        raise ValueError('request wire lifecycle/mode incomplete')
    result.update({'wire_case_count':52, 'wire_cases':rows, 'client_identity':True, 'native_program':True})
    return result


def guest_run(guest, work, binary, checker, program):
    if any(not isinstance(h,str) or not re.fullmatch('[0-9a-f]{64}',h) for h in (binary,checker,program)):
        raise ValueError('invalid native wire program identities')
    guest.require('test "$(sha256 -q /var/aegvium-lab-proxy)" = "'+program+'"')
    profile = (ROOT/'research/relayd/lab-request-wire.conf').read_bytes()
    hashes = {'engine':binary,'checker':checker,'program':program,'profile':hashlib.sha256(profile).hexdigest()}
    guest.require('set -eu; mkdir /var/aegvium-lab-request-wire; chmod 755 /var/aegvium-lab-request-wire; cat > /var/aegvium-lab-request-wire/profile.conf',data=profile)
    script = (ROOT/'tools/native/request-wire.sh').read_bytes()
    for key in hashes:
        script = script.replace((key.upper()+'_SHA256').encode(),hashes[key].encode())
    log = work/'request-wire.log'
    with log.open('wb') as output:
        reply = guest.call('sh -s',data=script,seconds=180,output=output)
    result = {'admitted':False,'hashes':hashes,'log_sha256':hashlib.sha256(log.read_bytes()).hexdigest(),'supervisor_exit':reply.returncode}
    try: result.update(admit(log.read_text(),hashes))
    except (ValueError,KeyError,TypeError) as error: result['admission_error'] = str(error)
    if reply.returncode: result['admitted'] = False
    return result
