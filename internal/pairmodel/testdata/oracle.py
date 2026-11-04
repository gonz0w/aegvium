#!/usr/bin/env python3
# SPDX-License-Identifier: BSD-3-Clause
"""Independent inert-data oracle for three reviewed private source models.

Python standard library only. Never imports/executes product code, launches a
fixture, reads credentials, contacts a network or grants runtime authority.
Expected transition decisions are literal reviewer judgments, not a validator.
This script materializes complete expected bytes once; product tests must consume
the resulting JSON literals rather than use product code to regenerate answers.
"""
from copy import deepcopy
from hashlib import sha256
import ipaddress
import json
from pathlib import Path
import struct

OUT = Path(__file__).resolve().parent


def compact(obj):
    # All object member names here are ASCII. There are no floating point values.
    # Python's non-ASCII JSON preserves U+2028/2029 and <>& and minimally escapes
    # the reviewed JSON string alphabet; no Unicode normalization is performed.
    return json.dumps(obj, ensure_ascii=False, sort_keys=True,
                      separators=(",", ":"), allow_nan=False).encode("utf-8")


def literal_input(obj):
    return json.dumps(obj, ensure_ascii=False, separators=(",", ":"))


def identity(raw, prefix):
    return "sha256:" + sha256(prefix + raw).hexdigest()


def json_vector(name, obj, normalizer, prefix, notes):
    raw = compact(normalizer(obj))
    return {"id": name, "expected": "accept", "notes": notes,
            "input_json": literal_input(obj),
            "canonical_utf8": raw.decode("utf-8"), "canonical_hex": raw.hex(),
            "canonical_byte_length": len(raw), "revision": identity(raw, prefix)}


def normalize_policy(obj):
    x = deepcopy(obj)
    x["zones"].sort(key=lambda z: z["id"])
    x["services"].sort(key=lambda s: s["id"])
    for z in x["zones"]:
        z["interfaces"].sort()
        z["networks"].sort()
    for rule in x["rules"]:
        rule["source"]["cidrs"].sort()
        rule["destination"]["cidrs"].sort()
    x["management_path"]["source_cidrs"].sort()
    # Rule order, display text, already-sorted ranges/types are never repaired.
    return x


def policy_base():
    return {"version": 1, "profile": "openbsd-7.9-routed-static-v1",
            "zones": [
                {"id": "wan", "name": "Transit", "scope": "transit",
                 "interfaces": ["em0"],
                 "networks": ["2001:db8:2::/64", "198.51.100.0/24"]},
                {"id": "lan", "name": 'Caf\u00e9 <>& \u2028\u2029 \U0001f642 "quoted" \\',
                 "scope": "local", "interfaces": ["em2", "em1"],
                 "networks": ["2001:db8:1::/64", "192.0.2.0/24"]}],
            "services": [
                {"id": "web", "name": "Web", "protocol": "tcp",
                 "ports": [{"first": 443, "last": 443},
                           {"first": 8443, "last": 8443}], "icmp_types": []},
                {"id": "echo", "name": "Echo reply type zero", "protocol": "icmp",
                 "ports": [], "icmp_types": [0, 8]}],
            "rules": [
                {"id": "allow-first", "name": "First", "enabled": True,
                 "action": "allow", "family": "ipv4",
                 "source": {"zone_id": "wan", "cidrs": ["0.0.0.0/0"]},
                 "destination": {"zone_id": "lan", "cidrs": ["192.0.2.5/32"]},
                 "service_id": "echo", "log": "bounded"},
                {"id": "deny-second", "name": "Second", "enabled": True,
                 "action": "deny", "family": "ipv4",
                 "source": {"zone_id": "wan", "cidrs": ["0.0.0.0/0"]},
                 "destination": {"zone_id": "lan", "cidrs": ["192.0.2.5/32"]},
                 "service_id": "echo", "log": "none"}],
            "translations": [],
            "management_path": {"zone_id": "lan", "family": "ipv4",
                "source_cidrs": ["192.0.2.11/32", "192.0.2.10/32"],
                "destination_address": "192.0.2.1", "destination_port": 22,
                "transport_profile": "fresh-authenticated-path-v1"}}


def maximum_policy():
    x = policy_base()
    zid = lambda i: "z" + "0" * 31 if i == 0 else f"z{i:02d}"
    sid = lambda i: "s" + "0" * 31 if i == 0 else f"s{i:03d}"
    x["zones"] = [{"id": zid(i), "name": "Z" * 128 if i == 0 else f"Zone {i}",
        "scope": "local", "interfaces": [f"em{i * 4 + j}" for j in range(4)],
        "networks": ([f"10.0.{j}.0/24" for j in range(64)] if i == 0
                     else [f"10.{i}.0.0/16"])} for i in range(16)]
    x["services"] = [{"id": sid(i), "name": "S" * 128 if i == 0 else f"Service {i}",
        "protocol": "tcp", "ports": ([{"first": p, "last": p}
            for p in list(range(1, 62, 2)) + [65535]] if i == 0 else
            [{"first": 443, "last": 443}]), "icmp_types": []} for i in range(256)]
    x["services"][1].update(protocol="icmp", ports=[], icmp_types=list(range(32)))
    x["rules"] = [{"id": f"r{i:03d}", "name": "R" * 128 if i == 0 else f"Rule {i}",
        "enabled": i != 511, "action": "allow" if i % 2 == 0 else "deny",
        "family": "ipv4", "source": {"zone_id": zid(0), "cidrs":
            [f"10.0.0.{j}/32" for j in range(1, 65)] if i == 0 else ["10.0.0.1/32"]},
        "destination": {"zone_id": zid(1), "cidrs":
            [f"10.1.0.{j}/32" for j in range(1, 65)] if i == 0 else ["10.1.0.1/32"]},
        "service_id": sid(1 if i == 1 else i % 256), "log": "none"}
        for i in range(512)]
    x["management_path"] = {"zone_id": zid(0), "family": "ipv4",
        "source_cidrs": [f"10.0.0.{j}/32" for j in range(1, 65)],
        "destination_address": "10.0.0.254", "destination_port": 65535,
        "transport_profile": "fresh-authenticated-path-v1"}
    return x


def arxwall():
    prefix = b"arxwall-policy-v1\n"
    vectors = []
    add = lambda name, obj, note: vectors.append(json_vector(
        name, obj, normalize_policy, prefix, note))
    base = policy_base()
    add("unicode-zero-and-rule-order", base,
        "ICMP numeric zero; raw UTF-8 U+2028/U+2029/<>&, quote/backslash; two ordered conflicting rules. Unbound intent only.")
    p = deepcopy(base)
    p["zones"].reverse()
    p["services"].reverse()
    for z in p["zones"]:
        z["interfaces"].reverse()
        z["networks"].reverse()
    p["management_path"]["source_cidrs"].reverse()
    p = dict(reversed(list(p.items())))
    add("equivalent-set-and-member-permutation", p, "Same exact canonical bytes/revision as first vector.")
    vectors[-1]["input_json"] = json.dumps(p, ensure_ascii=True, indent=2)
    p = deepcopy(base)
    p["rules"].reverse()
    add("semantic-rule-order-change", p, "Rule order changes identity; no runtime traffic claim.")
    p = deepcopy(base)
    p["zones"][1]["name"] = p["zones"][1]["name"].replace("\u00e9", "e\u0301")
    add("unicode-decomposed-is-distinct", p, "No NFC/NFD normalization: canonically equivalent display glyphs retain distinct bytes/revisions.")
    p = deepcopy(base)
    p["zones"] = [p["zones"][1]]
    p["rules"] = []
    p["services"] = []
    p["management_path"].update(family="ipv6", source_cidrs=["2001:db8:1::10/128"],
        destination_address="2001:db8:1::1", destination_port=65535)
    add("ipv6-management-empty-services-and-rules", p, "Declared IPv6 membership only; empty optional collections retained.")
    p = deepcopy(base)
    p["services"] = [{"id": "echo6", "name": "ICMP6 numeric bounds", "protocol": "icmp6", "ports": [], "icmp_types": [0, 255]}]
    for r in p["rules"]:
        r.update(family="ipv6", service_id="echo6")
        r["source"]["cidrs"] = ["::/0"]
        r["destination"]["cidrs"] = ["2001:db8:1::5/128"]
    add("ipv6-rule-and-service-family", p, "Matching IPv6 rule/service/CIDR families; ICMP type 0 and 255.")
    p = deepcopy(base)
    p["management_path"].update(zone_id="wan", source_cidrs=["203.0.113.0/24"],
                                destination_address="203.0.113.254")
    add("transit-management-is-unbound-intent", p, "Remote transit source and destination outside connected networks are accepted structural intent; actual gateway/reachability proof remains absent.")
    m = maximum_policy()
    add("maximum-shaped-collections", m,
        "16 zones, 64 interfaces, 256 services, 512 ordered rules; 64-prefix lists; 32 ranges and 32 ICMP types; 32-byte IDs/128-byte displays/port 65535. Not every nested list simultaneously maximal; total remains <=256 KiB.")
    assert len(literal_input(m).encode()) <= 256 * 1024
    rejects = []
    def reject(name, mutate, reason):
        p = deepcopy(base)
        mutate(p)
        rejects.append({"id": name, "expected": "reject", "reason": reason,
                        "input_json": literal_input(p)})
    reject("nonempty-translation-is-unsupported", lambda p: p["translations"].append({
        "id": "nat", "kind": "source-nat-ipv4", "source_zone_id": "lan",
        "source_cidrs": ["192.0.2.0/24"], "egress_zone_id": "wan",
        "translated_address": "198.51.100.1"}), "Unsupported nonempty translation; never remove and accept.")
    reject("unsorted-ranges-not-repaired", lambda p: p["services"][0]["ports"].reverse(), "Input ranges must already be sorted.")
    reject("local-endpoint-outside-zone", lambda p: p["rules"][0]["destination"].update(cidrs=["203.0.113.5/32"]), "Declared local containment violation.")
    reject("management-port-zero", lambda p: p["management_path"].update(destination_port=0), "Management port 1..65535.")
    reject("cross-zone-overlap", lambda p: p["zones"][0].update(networks=["192.0.2.0/25"]), "Distinct zones overlap.")
    rejects.extend([
        {"id": "duplicate-member", "expected": "reject", "reason": "Duplicate root key.",
         "input_json": literal_input(base).replace('"version":1', '"version":1,"version":1', 1)},
        {"id": "negative-zero", "expected": "reject", "reason": "Numeric -0 is not an unsigned integer literal.",
         "input_json": literal_input(base).replace('"icmp_types":[0,8]', '"icmp_types":[-0,8]', 1)},
        {"id": "unpaired-surrogate", "expected": "reject", "reason": "Never repair malformed Unicode.",
         "input_json": literal_input(base).replace('"name":"Transit"', '"name":"\\ud800"', 1)}])
    assert vectors[0]["revision"] == vectors[1]["revision"]
    assert len({v["revision"] for v in (vectors[0], vectors[2], vectors[3])}) == 3
    return {"format": "independent-private-model-goldens-v1", "model": "P-M01/1",
        "authority": "inert unbound filtering intent; no native/apply/PF/topology proof",
        "hash_prefix_hex": prefix.hex(), "valid": vectors, "invalid": rejects,
        "relations": [{"left": vectors[0]["id"], "right": v["id"],
            "equal_canonical": i == 1, "equal_revision": i == 1}
            for i, v in enumerate(vectors[1:4], 1)]}


def normalize_records(obj):
    x = deepcopy(obj)
    x["zones"].sort(key=lambda z: z["id"])
    x["records"].sort(key=lambda r: r["id"])
    return x


def records_base():
    ext = {"kind": "external", "source": "lease-feed-07"}
    manual = {"kind": "manual", "source": ""}
    def record(rid, zone, name, typ, value, ttl, owner):
        return {"id": rid, "zone_id": zone, "name": name, "type": typ,
                "value": value, "ttl": ttl, "owner": deepcopy(owner)}
    return {"version": 1, "zones": [
        {"id": "v6", "name": "8.b.d.0.1.0.0.2.ip6.arpa.", "kind": "reverse-ipv6"},
        {"id": "lan", "name": "home.arpa.", "kind": "forward"},
        {"id": "v4", "name": "2.0.192.in-addr.arpa.", "kind": "reverse-ipv4"}],
        "records": [
            record("ptr6", "v6", ipaddress.ip_address("2001:db8::10").reverse_pointer + ".", "PTR", "host.home.arpa.", 86400, ext),
            record("manual6", "lan", "desk.home.arpa.", "AAAA", "2001:db8::20", 300, manual),
            record("host4", "lan", "host.home.arpa.", "A", "192.0.2.10", 1, ext),
            record("ptr4", "v4", "10.2.0.192.in-addr.arpa.", "PTR", "host.home.arpa.", 1, ext),
            record("host6", "lan", "host.home.arpa.", "AAAA", "2001:db8::10", 86400, ext),
            record("manual4", "lan", "desk.home.arpa.", "A", "192.0.2.20", 300, manual)]}


def nomvium():
    prefix = b"nomvium-record-draft-v1\n"
    vectors, transitions = [], []
    add = lambda name, obj, note: vectors.append(json_vector(
        name, obj, normalize_records, prefix, note))
    base = records_base()
    add("mixed-forward-reverse-and-provenance", base,
        "A/AAAA/PTR, literal complete v4/v6 owners, TTL 1/86400, opaque lease-feed-07 provenance; no lease or DHCP authority.")
    p = deepcopy(base)
    p["zones"].reverse()
    p["records"].reverse()
    add("equivalent-set-permutation", dict(reversed(list(p.items()))), "Identical canonical bytes/revision.")
    transitions.append({"old": vectors[0]["id"], "next": vectors[1]["id"], "expected": "accept", "reason": "All semantic facts unchanged."})
    def transition(name, mutate, outcome, reason):
        p = deepcopy(base)
        mutate(p)
        add(name, p, "Valid catalog; transition result is independently specified below.")
        transitions.append({"old": vectors[0]["id"], "next": name,
                            "expected": outcome, "reason": reason})
    manual = {"id": "new-manual", "zone_id": "lan", "name": "new.home.arpa.",
              "type": "A", "value": "192.0.2.30", "ttl": 86400,
              "owner": {"kind": "manual", "source": ""}}
    transition("manual-add", lambda p: p["records"].append(deepcopy(manual)), "accept", "Manual add in unchanged zone and unowned name.")
    transition("manual-delete", lambda p: p.update(records=[r for r in p["records"] if not r["id"].startswith("manual")]), "accept", "Only manual records removed.")
    transition("manual-update", lambda p: next(r for r in p["records"] if r["id"] == "manual4").update(value="192.0.2.21", ttl=301), "accept", "Manual RDATA/TTL replacement; different record types need not share TTL.")
    transition("external-ttl-change", lambda p: next(r for r in p["records"] if r["id"] == "host4").update(ttl=2), "reject", "Externally owned record changed under its ID.")
    transition("external-delete", lambda p: p.update(records=[r for r in p["records"] if r["id"] != "host4"]), "reject", "Old external record must survive under same ID.")
    transition("external-source-relabel", lambda p: [r["owner"].update(source="lease-feed-08") for r in p["records"] if r["owner"]["kind"] == "external"], "reject", "Opaque source identifier fidelity is semantic.")
    transition("external-re-id", lambda p: next(r for r in p["records"] if r["id"] == "host4").update(id="new-host4"), "reject", "Same data under a different ID is not preservation.")
    def new_external(p):
        r = deepcopy(manual)
        r["owner"] = {"kind": "external", "source": "lease-feed-07"}
        p["records"].append(r)
    transition("new-external", new_external, "reject", "Manual change cannot create external provenance.")
    transition("manual-takeover-of-external-name", lambda p: [r.update(owner={"kind": "manual", "source": ""}) for r in p["records"] if r["zone_id"] == "lan" and r["name"] == "host.home.arpa."], "reject", "Removing/recreating an external name as manual does not erase protection.")
    def rename_zone(p):
        next(z for z in p["zones"] if z["id"] == "lan")["id"] = "renamed"
        for r in p["records"]:
            if r["zone_id"] == "lan":
                r["zone_id"] = "renamed"
    transition("zone-identity-change", rename_zone, "reject", "Zone identities must remain identical.")
    transition("zone-add", lambda p: p["zones"].append({"id": "extra", "name": "other.arpa.", "kind": "forward"}), "reject", "Valid extra zone is outside manual-change zone-set constraint.")
    def numeric_local_intent(p):
        for rid, typ, value in [("local4", "A", "127.0.0.1"), ("local6", "AAAA", "fe80::1")]:
            r = deepcopy(manual)
            r.update(id=rid, name="local.home.arpa.", type=typ, value=value, ttl=300)
            p["records"].append(r)
    transition("loopback-and-link-local-intent", numeric_local_intent, "accept", "Canonical numeric loopback/link-local unicast is allowed as draft intent; no address use or scope discovery occurs.")
    add("empty-record-catalog", {"version": 1, "zones": [{"id": "lan", "name": "home.arpa.", "kind": "forward"}], "records": []}, "Records may be empty; zone intent remains explicit.")
    add("reverse-minimum-zone-prefix-no-forward-synthesis", {"version": 1,
        "zones": [{"id": "reverse", "name": "1.in-addr.arpa.", "kind": "reverse-ipv4"}],
        "records": [{"id": "ptr", "zone_id": "reverse", "name": "4.3.2.1.in-addr.arpa.", "type": "PTR", "value": "outside.example.test.", "ttl": 1, "owner": {"kind": "manual", "source": ""}}]}, "One reverse octet zone; complete four-octet owner; target need not exist in catalog.")
    rejects = []
    def reject(name, mutate, reason):
        p = deepcopy(base)
        mutate(p)
        rejects.append({"id": name, "expected": "reject", "reason": reason, "input_json": literal_input(p)})
    for value, name in [(0, "ttl-zero"), (86401, "ttl-cap-plus-one")]:
        reject(name, lambda p, value=value: p["records"][2].update(ttl=value), "TTL outside 1..86400.")
    reject("mixed-owner-at-name", lambda p: p["records"][2].update(owner={"kind": "manual", "source": ""}), "All records at a zone/name have one owner.")
    reject("duplicate-rdata", lambda p: p["records"].append(dict(deepcopy(p["records"][2]), id="copy")), "RRset duplicate RDATA rejects, distinct ID does not help.")
    reject("mapped-v6", lambda p: p["records"][4].update(value="::ffff:192.0.2.10"), "Mapped IPv6 is excluded.")
    reject("limited-broadcast", lambda p: p["records"][2].update(value="255.255.255.255"), "Limited broadcast is not unicast.")
    reject("incomplete-ptr-owner", lambda p: p["records"][3].update(name="2.0.192.in-addr.arpa."), "PTR owner must encode a complete address.")
    reject("zero-zones", lambda p: p.update(zones=[], records=[]), "At least one declared zone is required.")
    assert vectors[0]["revision"] == vectors[1]["revision"]
    return {"format": "independent-private-model-goldens-v1", "model": "R-M01/1",
        "authority": "supplied in-memory intent/provenance and structural manual-change constraint only",
        "hash_prefix_hex": prefix.hex(), "valid": vectors, "invalid": rejects,
        "manual_changes": transitions,
        "transition_oracle": "Expected outcomes are literal independent design judgments; no Go code or future production authority provider is consulted."}


LIMITS = [4096, 5120, 2048, 4096, 4096]


def descriptor_bytes(model):
    b = bytearray(b"AGPAIR1\n")
    b.extend(model["generation"].encode("ascii"))
    b.extend(b"M2-H1/1")
    b.extend(struct.pack(">B", len(model["routes"])))
    offsets = {"route_count": 47, "routes": []}
    for r in model["routes"]:
        pos = {"start": len(b)}
        def field(text, width, name):
            raw = text.encode("ascii")
            pos[name + "_length"] = len(b)
            b.extend(struct.pack(">B" if width == 1 else ">H", len(raw)))
            pos[name] = len(b)
            b.extend(raw)
        field(r["id"], 1, "id")
        field(r["public_dns"], 2, "public_dns")
        pos["public_port"] = len(b)
        b.extend(struct.pack(">H", r["public_port"]))
        pos["policy_pin"] = len(b)
        b.extend(r["policy_pin"].encode("ascii"))
        pos["peer_count"] = len(b)
        b.extend(struct.pack(">B", len(r["frontend_peers"])))
        for i, peer in enumerate(r["frontend_peers"]):
            field(peer, 2, f"peer_{i}")
        field(r["inspector_address"], 1, "inspector_address")
        pos["inspector_port"] = len(b)
        b.extend(struct.pack(">H", r["inspector_port"]))
        field(r["inspector_dns"], 2, "inspector_dns")
        pos["inspector_server_trust_digest"] = len(b)
        b.extend(bytes.fromhex(r["inspector_server_trust_digest_hex"]))
        pos["frontend_client_trust_digest"] = len(b)
        b.extend(bytes.fromhex(r["frontend_client_trust_digest_hex"]))
        pos["end"] = len(b)
        offsets["routes"].append(pos)
    offsets["fixed_limits"] = len(b)
    b.extend(struct.pack(">IIIII", *LIMITS))
    offsets["requests"] = len(b)
    b.extend(struct.pack(">BB", 4, 8))
    offsets["data_sockets"] = len(b) - 1
    return bytes(b), offsets


def route(rid="app_primary", public="app.example.test", address="192.0.2.10"):
    return {"id": rid, "public_dns": public, "public_port": 443,
        "policy_pin": "01" * 32,
        "frontend_peers": ["front-a.internal.test", "front-b.internal.test"],
        "inspector_address": address, "inspector_port": 8443,
        "inspector_dns": "inspect.internal.test",
        "inspector_server_trust_digest_hex": bytes(range(32)).hex(),
        "frontend_client_trust_digest_hex": bytes(range(255, 223, -1)).hex()}


def dns_of_length(n, seed):
    # Every generated label begins/ends with a lower-case letter, <=63 bytes.
    # Use 63-byte labels, avoid a leftover empty/one-byte separator remainder.
    labels = []
    remaining = n
    while remaining > 63:
        take = 62 if remaining == 64 else 63
        labels.append(seed + "a" * (take - 1))
        remaining -= take + 1
    labels.append(seed + "a" * (remaining - 1))
    value = ".".join(labels)
    assert len(value) == n and all(1 <= len(x) <= 63 for x in value.split("."))
    return value


def aegvium():
    vectors, rejects = [], []
    def add(name, model, expected="accept", reason=""):
        raw, offsets = descriptor_bytes(model)
        row = {"id": name, "expected": expected, "notes": reason,
            "fields": deepcopy(model), "descriptor_hex": raw.hex(),
            "byte_length": len(raw), "sha256": sha256(raw).hexdigest(),
            "offsets": offsets}
        (vectors if expected == "accept" else rejects).append(row)
        return row
    base = {"generation": "0123456789abcdef0123456789abcdef", "routes": [route()]}
    add("one-route-ipv4-two-peers", base, reason="Complete binary descriptor including opaque raw trust bytes, ASCII pin, magic/contract/fixed trailer.")
    ipv6 = route("api_v6", "api.example.test", "2001:db8::20")
    ipv6.update(public_port=65535, inspector_port=1, policy_pin="f0" * 32,
        frontend_peers=["f.internal.test"], inspector_dns="inspect6.internal.test",
        inspector_server_trust_digest_hex="00" * 32,
        frontend_client_trust_digest_hex="ff" * 32)
    add("one-route-ipv6-port-extremes", {"generation": "f" * 32, "routes": [ipv6]}, reason="Opaque all-zero trust digest is data, never proof of an actual anchor.")
    two = {"generation": base["generation"], "routes": [ipv6, route()]}
    add("two-routes-sorted-v4-v6", two)
    minimal_route = route("a", "a", "::1")
    minimal_route.update(public_port=1, policy_pin="0" * 64, frontend_peers=["a"],
        inspector_port=1, inspector_dns="a", inspector_server_trust_digest_hex="00" * 32,
        frontend_client_trust_digest_hex="00" * 32)
    minimum = add("minimum-reachable-complete-descriptor", {"generation": "0" * 32, "routes": [minimal_route]}, reason="Existing M2-C01 DNS grammar permits one-label names; ::1 is canonical numeric unicast. Zero generation is lexically valid, not fresh.")
    # Header 48 + minimum route 148 + fixed trailer 22 = 218.
    assert minimum["byte_length"] == 218
    long_routes = []
    for i in range(3):
        r = route(chr(97 + i) * 32, dns_of_length(253, chr(109 + i)),
                  "2001:db8:1111:2222:3333:4444:5555:6666")
        r.update(frontend_peers=[dns_of_length(253, c) for c in "abcdefgh"],
                 inspector_dns=dns_of_length(253, "z"), public_port=65535)
        long_routes.append(r)
    large = {"generation": base["generation"], "routes": long_routes}
    excess = len(descriptor_bytes(large)[0]) - 8192
    for i in range(8):
        cut = min(excess, 252)
        long_routes[0]["frontend_peers"][i] = dns_of_length(253 - cut, "abcdefgh"[i])
        excess -= cut
        if excess == 0:
            break
    assert excess == 0 and len(descriptor_bytes(large)[0]) == 8192
    boundary = add("exact-8192-reachable", large, reason="Three routes, eight peers each; global cap dominates individual maxima; complete valid grammar exactly 8192 bytes.")
    plus = deepcopy(large)
    peer = plus["routes"][0]["frontend_peers"][0]
    plus["routes"][0]["frontend_peers"][0] = dns_of_length(len(peer) + 1, "a")
    assert len(descriptor_bytes(plus)[0]) == 8193
    add("8193-structurally-valid-cap-plus-one", plus, "reject", "One-byte over total cap; all individual field lengths and grammar remain valid.")
    p = deepcopy(two)
    p["routes"].reverse()
    add("route-order-not-repaired", p, "reject", "Routes must arrive sorted by ID.")
    p = deepcopy(base)
    p["routes"][0]["frontend_peers"].reverse()
    add("peer-order-not-repaired", p, "reject", "Peers must arrive sorted uniquely.")
    p = deepcopy(two)
    p["routes"][1].update(public_dns=p["routes"][0]["public_dns"], public_port=p["routes"][0]["public_port"])
    add("duplicate-public-authority", p, "reject", "Distinct IDs do not permit duplicate public DNS/port authority.")
    for name, key, value in [("inspector-port-zero", "inspector_port", 0),
        ("public-port-zero", "public_port", 0), ("hyphen-route-id", "id", "app-primary"),
        ("dns-trailing-dot", "public_dns", "app.example.test."),
        ("mapped-inspector-address", "inspector_address", "::ffff:192.0.2.10")]:
        p = deepcopy(base)
        p["routes"][0][key] = value
        add(name, p, "reject", "Explicit scoped grammar violation.")
    raw = bytes.fromhex(vectors[0]["descriptor_hex"])
    modified = bytearray(raw)
    offset = vectors[0]["offsets"]["fixed_limits"]
    modified[offset:offset + 4] = struct.pack(">I", 4097)
    for name, data, reason in [
        ("changed-fixed-u32", bytes(modified), "Fixed public_headers must be 4096."),
        ("trailing-byte", raw + b"\x00", "No trailing field/padding."),
        ("truncated-last-byte", raw[:-1], "Complete fixed trailer required.")]:
        rejects.append({"id": name, "expected": "reject", "notes": reason,
            "descriptor_hex": data.hex(), "byte_length": len(data),
            "sha256": sha256(data).hexdigest()})
    return {"format": "independent-private-model-goldens-v1", "model": "A01a-P/1",
        "authority": "inert complete-byte equality only; no TLS/cert/freshness/readiness/backend authority",
        "magic_hex": b"AGPAIR1\n".hex(), "contract_hex": b"M2-H1/1".hex(),
        "fixed_trailer_hex": struct.pack(">IIIIIBB", *LIMITS, 4, 8).hex(),
        "hash_domain": "Complete descriptor bytes; no added prefix.",
        "valid": vectors, "invalid": rejects,
        "equality_oracles": [{"left": vectors[0]["id"], "right": vectors[0]["id"], "equal": True},
            {"left": vectors[0]["id"], "right": vectors[1]["id"], "equal": False},
            {"left": vectors[0]["id"], "right": vectors[2]["id"], "equal": False}],
        "truncation_oracle": {"source": vectors[0]["id"], "proper_prefix_lengths": [0, len(raw) - 1],
            "range_semantics": "Every integer in this inclusive range rejects; includes all interior offsets."}}


def main():
    for name, build in [("arxwall", arxwall), ("nomvium", nomvium), ("aegvium", aegvium)]:
        obj = build()
        # Artifact envelope uses escaped Unicode; canonical_hex/decoded UTF-8
        # values specify the exact expected model bytes independently of envelope.
        data = (json.dumps(obj, ensure_ascii=True, indent=2) + "\n").encode()
        target = OUT / (name + ".json")
        target.write_bytes(data)
        print(json.dumps({"artifact": str(target), "bytes": len(data),
            "sha256": sha256(data).hexdigest(), "accepted": len(obj["valid"]),
            "rejected": len(obj["invalid"])}))


if __name__ == "__main__":
    main()
