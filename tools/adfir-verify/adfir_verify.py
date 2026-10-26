#!/usr/bin/env python3
"""adfir-verify: an independent verifier for .adfir evidence packages.

Written from docs/adfir-spec.md, not from AgentDFIR's source, with the
Python 3 standard library only, so that a package's integrity can be
checked without trusting -- or even having -- the tool that produced it.

It checks, per the specification's "Integrity verification" section:

  1. every path listed in SHA256SUMS hashes to its recorded SHA-256;
  2. the sealed zone holds nothing SHA256SUMS does not cover;
  3. every acquired manifest artifact's plaintext (codec decoded, chunks
     concatenated) hashes to its artifact_id, and each stored unit to its
     stored_sha256;
  4. both hash chains (collection.jsonl, chain-of-custody.jsonl);
  5. SEAL.sig, an ed25519 signature over the SHA-256 of SHA256SUMS, with
     a pure-Python RFC 8032 implementation (no third-party package);

and, from the "Rounds" section, that each archived seal is the one the
next round recorded as prev_seal_sha256, that its archived signature
verifies, and that no blob an earlier round sealed has changed.

From spec 0.2.2 it also checks the optional analysis files when a package
holds them (they are derived data, outside the seal, but a reader relies
on them): detections/analysis-manifest.json (shape, and its
findings_fingerprint recomputed from detections/findings.json),
normalized/lineage.json (the action graph: every edge joins nodes the
graph holds and cites a source; a correlated edge cites its telemetry
witness; from 0.2.2 a CORROBORATED edge cites one or says why not), and
reports/findings.stix.json (STIX 2.1 required properties, ids,
timestamps, references). Given a production set (production-manifest.json
and no SHA256SUMS) it checks every listed file and the manifest's ed25519
signature.

Usage: adfir_verify.py [--json] [--pubkey HEX] [--stix FILE] PACKAGE_OR_PRODUCTION_DIR
Exit status: 0 verified, 1 problems found, 2 usage or unreadable package.
"""

import argparse
import hashlib
import json
import os
import re
import sys
import zlib

__version__ = "1.1.0"
SPEC_VERSION = "0.2.2"

ZERO = "0" * 64
MAX_SMALL_FILE = 256 << 20  # SHA256SUMS, case.json, a manifest, a chain
READ_CHUNK = 1 << 20


# --------------------------------------------------------------- ed25519
# RFC 8032 section 6 (reference implementation), verification only.

_P = 2 ** 255 - 19
_Q = 2 ** 252 + 27742317777372353535851937790883648493


def _inv(x):
    return pow(x, _P - 2, _P)


_D = -121665 * _inv(121666) % _P
_SQRT_M1 = pow(2, (_P - 1) // 4, _P)


def _add(a, b):
    p1 = (a[1] - a[0]) * (b[1] - b[0]) % _P
    p2 = (a[1] + a[0]) * (b[1] + b[0]) % _P
    c = 2 * a[3] * b[3] * _D % _P
    d = 2 * a[2] * b[2] % _P
    e, f, g, h = p2 - p1, d - c, d + c, p2 + p1
    return (e * f % _P, g * h % _P, f * g % _P, e * h % _P)


def _mul(s, pt):
    acc = (0, 1, 1, 0)
    while s > 0:
        if s & 1:
            acc = _add(acc, pt)
        pt = _add(pt, pt)
        s >>= 1
    return acc


def _equal(a, b):
    return (a[0] * b[2] - b[0] * a[2]) % _P == 0 and (a[1] * b[2] - b[1] * a[2]) % _P == 0


def _recover_x(y, sign):
    if y >= _P:
        return None
    x2 = (y * y - 1) * _inv(_D * y * y + 1) % _P
    if x2 == 0:
        return None if sign else 0
    x = pow(x2, (_P + 3) // 8, _P)
    if (x * x - x2) % _P != 0:
        x = x * _SQRT_M1 % _P
    if (x * x - x2) % _P != 0:
        return None
    if (x & 1) != sign:
        x = _P - x
    return x


def _decompress(b):
    if len(b) != 32:
        return None
    y = int.from_bytes(b, "little")
    sign = y >> 255
    y &= (1 << 255) - 1
    x = _recover_x(y, sign)
    if x is None:
        return None
    return (x, y, 1, x * y % _P)


_GY = 4 * _inv(5) % _P
_GX = _recover_x(_GY, 0)
_G = (_GX, _GY, 1, _GX * _GY % _P)


def ed25519_verify(public, msg, sig):
    """True when sig is a valid ed25519 signature of msg by public."""
    if len(public) != 32 or len(sig) != 64:
        return False
    a = _decompress(public)
    r = _decompress(sig[:32])
    if a is None or r is None:
        return False
    s = int.from_bytes(sig[32:], "little")
    if s >= _Q:
        return False
    h = int.from_bytes(hashlib.sha512(sig[:32] + public + msg).digest(), "little") % _Q
    return _equal(_mul(s, _G), _add(r, _mul(h, a)))


# --------------------------------------------------------------- helpers

def sha256_file(path):
    h = hashlib.sha256()
    with open(path, "rb") as f:
        while True:
            b = f.read(READ_CHUNK)
            if not b:
                break
            h.update(b)
    return h.hexdigest()


def read_small(path):
    size = os.path.getsize(path)
    if size > MAX_SMALL_FILE:
        raise ValueError("%s is %d bytes, over the %d-byte bound" % (path, size, MAX_SMALL_FILE))
    with open(path, "rb") as f:
        return f.read()


def is_hex64(s):
    return isinstance(s, str) and len(s) == 64 and all(c in "0123456789abcdef" for c in s)


def safe_rel(rel):
    """A SHA256SUMS path must be relative, '/'-separated and stay inside."""
    if not rel or rel.startswith("/") or "\\" in rel or "\x00" in rel:
        return False
    parts = rel.split("/")
    return all(p not in ("", ".", "..") for p in parts) and ":" not in parts[0]


def parse_sums(data, where, problems):
    """SHA256SUMS: one '<sha256 hex>  <relative path>' per LF-terminated line."""
    out = {}
    try:
        text = data.decode("utf-8")
    except UnicodeDecodeError:
        problems.append("%s: not UTF-8" % where)
        return out
    for n, line in enumerate(text.split("\n"), 1):
        if line == "":
            continue
        digest, sep, rel = line.partition("  ")
        if not sep or not is_hex64(digest):
            problems.append("%s line %d: malformed: %r" % (where, n, line[:120]))
            continue
        if not safe_rel(rel):
            problems.append("%s line %d: path outside the package: %r" % (where, n, rel))
            continue
        if rel in out:
            problems.append("%s line %d: %s listed twice" % (where, n, rel))
        out[rel] = digest
    return out


def parse_sig(data):
    """SEAL.sig: 'key: value' lines (algorithm, sha256sums_digest, signature, public_key)."""
    fields = {}
    for line in data.decode("utf-8", "replace").splitlines():
        k, sep, v = line.partition(":")
        if sep:
            fields[k.strip()] = v.strip()
    return fields


def check_sig(sig_path, sums_path, pubkey):
    """Returns (present, valid, public_key_hex, reason)."""
    if not os.path.exists(sig_path):
        return False, False, "", ""
    f = parse_sig(read_small(sig_path))
    try:
        sig = bytes.fromhex(f.get("signature", ""))
        pub = bytes.fromhex(f.get("public_key", ""))
    except ValueError:
        return True, False, "", "malformed signature file"
    if f.get("algorithm", "ed25519") != "ed25519" or len(pub) != 32 or len(sig) != 64:
        return True, False, f.get("public_key", ""), "malformed signature file"
    if pubkey and pubkey.lower() != pub.hex():
        return True, False, pub.hex(), "public key does not match the pinned key"
    digest = hashlib.sha256(read_small(sums_path)).digest()
    if not ed25519_verify(pub, digest, sig):
        return True, False, pub.hex(), "signature does not match the seal"
    return True, True, pub.hex(), ""


# --------------------------------------------------------------- checks

class Result:
    def __init__(self):
        self.problems = []
        self.notes = []
        self.counts = {"files_checked": 0, "artifacts_verified": 0, "collection_records": 0,
                       "custody_records": 0, "rounds": 0, "archived_seals": 0}
        self.signature = "none"
        self.analysis_problems = []
        self.analysis_checked = []


def check_chain(pkg, name, res):
    path = os.path.join(pkg, name)
    try:
        data = read_small(path)
    except (OSError, ValueError) as e:
        res.problems.append("%s: unreadable: %s" % (name, e))
        return 0
    expect = ZERO
    n = 0
    lines = data.split(b"\n")
    if lines and lines[-1] == b"":
        lines.pop()
    for raw in lines:
        try:
            rec = json.loads(raw)
        except ValueError:
            res.problems.append("%s: record %d is not JSON" % (name, n))
            return n
        if not isinstance(rec, dict) or rec.get("prev") != expect:
            res.problems.append("%s: chain broken at record %d" % (name, n))
            return n
        if rec.get("seq") != n:
            res.problems.append("%s: record %d has seq %r" % (name, n, rec.get("seq")))
            return n
        expect = hashlib.sha256(raw).hexdigest()
        n += 1
    return n


def read_manifest(pkg, res):
    """manifest.jsonl (0.2: header line, then one record per line) or
    manifest.json (0.1: an object with an 'artifacts' array)."""
    jl = os.path.join(pkg, "manifest.jsonl")
    if os.path.exists(jl):
        records = []
        data = read_small(jl)
        lines = [l for l in data.split(b"\n") if l.strip()]
        if not lines:
            res.problems.append("manifest.jsonl: empty")
            return None
        for i, l in enumerate(lines):
            try:
                v = json.loads(l)
            except ValueError:
                res.problems.append("manifest.jsonl: line %d is not JSON" % (i + 1))
                return None
            if i > 0:
                records.append(v)
        return records
    js = os.path.join(pkg, "manifest.json")
    if os.path.exists(js):
        try:
            v = json.loads(read_small(js))
        except ValueError:
            res.problems.append("manifest.json: not JSON")
            return None
        return v.get("artifacts") or []
    res.problems.append("no manifest")
    return None


def read_unit(pkg, uid, codec, size, stored_sha, res, label):
    """Plaintext of one stored unit, bounded by its recorded size."""
    name = uid + (".gz" if codec == "gzip" else "")
    path = os.path.join(pkg, "raw", name)
    if not is_hex64(uid):
        res.problems.append("%s: malformed content address %r" % (label, uid))
        return None
    if codec not in ("", "none", "gzip", None):
        res.problems.append("%s: unknown codec %r" % (label, codec))
        return None
    try:
        stored = read_small(path) if os.path.getsize(path) <= MAX_SMALL_FILE else None
    except OSError:
        res.problems.append("%s: blob missing: raw/%s" % (label, name))
        return None
    if stored is None:
        res.notes.append("%s: blob over %d bytes, content not re-derived" % (label, MAX_SMALL_FILE))
        return None
    if stored_sha and hashlib.sha256(stored).hexdigest() != stored_sha:
        res.problems.append("%s: raw/%s does not match its stored_sha256" % (label, name))
    if codec != "gzip":
        return stored
    try:
        # Bounded by the recorded size (the spec requires it), or by the
        # small-file bound when a record has none.
        limit = size if isinstance(size, int) and size >= 0 else MAX_SMALL_FILE
        d = zlib.decompressobj(16 + zlib.MAX_WBITS)
        out = d.decompress(stored, limit + 1)
        if len(out) > limit:
            res.problems.append("%s: raw/%s decompresses past its recorded size" % (label, name))
            return None
        if not d.eof:
            res.problems.append("%s: raw/%s is a truncated gzip stream" % (label, name))
            return None
        return out
    except zlib.error as e:
        res.problems.append("%s: raw/%s is not valid gzip: %s" % (label, name, e))
        return None


def check_artifacts(pkg, records, res):
    seen = set()
    for i, a in enumerate(records):
        if not isinstance(a, dict):
            res.problems.append("manifest record %d is not an object" % i)
            continue
        if a.get("status") != "OK" or not a.get("artifact_id"):
            continue
        aid = a["artifact_id"]
        label = a.get("logical_path") or aid
        if aid in seen:
            continue
        seen.add(aid)
        size = a.get("size")
        chunks = a.get("chunks") or []
        if chunks:
            h, total, ok = hashlib.sha256(), 0, True
            for c in chunks:
                b = read_unit(pkg, c.get("id", ""), c.get("codec", ""), c.get("size"), c.get("stored_sha256", ""), res, label)
                if b is None:
                    ok = False
                    break
                if c.get("size") is not None and len(b) != c.get("size"):
                    res.problems.append("%s: chunk %s is %d bytes, recorded %d" % (label, c.get("id", "")[:12], len(b), c.get("size")))
                    ok = False
                    break
                if hashlib.sha256(b).hexdigest() != c.get("id"):
                    res.problems.append("%s: chunk %s content-address mismatch" % (label, c.get("id", "")[:12]))
                    ok = False
                    break
                h.update(b)
                total += len(b)
            if not ok:
                continue
            digest = h.hexdigest()
        else:
            b = read_unit(pkg, aid, a.get("codec", ""), size, a.get("stored_sha256", ""), res, label)
            if b is None:
                continue
            digest, total = hashlib.sha256(b).hexdigest(), len(b)
        if digest != aid:
            res.problems.append("%s: content-address mismatch" % label)
        elif size not in (None, 0) and total != size:
            res.problems.append("%s: size mismatch: recorded %d, stored %d" % (label, size, total))
        else:
            res.counts["artifacts_verified"] += 1


SEALED_FILES = ("case.json", "manifest.jsonl", "manifest.json", "collection.jsonl", "chain-of-custody.jsonl")


def verify(pkg, pubkey=""):
    res = Result()
    sums_path = os.path.join(pkg, "SHA256SUMS")
    try:
        listed = parse_sums(read_small(sums_path), "SHA256SUMS", res.problems)
    except (OSError, ValueError) as e:
        raise SystemExit("cannot read SHA256SUMS: %s" % e)

    # 1. every listed file
    for rel in sorted(listed):
        path = os.path.join(pkg, *rel.split("/"))
        try:
            got = sha256_file(path)
        except OSError:
            res.problems.append("%s: listed in SHA256SUMS but unreadable or missing" % rel)
            continue
        res.counts["files_checked"] += 1
        if got != listed[rel]:
            res.problems.append("%s: hash mismatch" % rel)

    # 2. coverage: required files, and nothing unlisted in the sealed zone
    for req in ("case.json", "collection.jsonl", "chain-of-custody.jsonl"):
        if req not in listed:
            res.problems.append("SHA256SUMS does not cover %s" % req)
    if "manifest.jsonl" not in listed and "manifest.json" not in listed:
        res.problems.append("SHA256SUMS covers no manifest")
    for name in SEALED_FILES:
        if name not in listed and os.path.lexists(os.path.join(pkg, name)):
            res.problems.append("%s: present but not covered by SHA256SUMS" % name)
    for d in ("raw", "seals"):
        dpath = os.path.join(pkg, d)
        if os.path.isdir(dpath):
            for name in sorted(os.listdir(dpath)):
                if d + "/" + name not in listed:
                    res.problems.append("%s/%s: present but not covered by SHA256SUMS" % (d, name))

    # 3. content addresses
    try:
        records = read_manifest(pkg, res)
    except (OSError, ValueError) as e:
        res.problems.append("manifest unreadable: %s" % e)
        records = None
    if records is not None:
        check_artifacts(pkg, records, res)

    # 4. hash chains
    res.counts["collection_records"] = check_chain(pkg, "collection.jsonl", res)
    res.counts["custody_records"] = check_chain(pkg, "chain-of-custody.jsonl", res)

    # Rounds: case.json says which key each round was sealed for and the
    # seal it replaced.
    rounds = []
    try:
        case = json.loads(read_small(os.path.join(pkg, "case.json")))
        rounds = case.get("rounds") or []
    except (OSError, ValueError) as e:
        res.problems.append("case.json unreadable: %s" % e)
        case = None
    res.counts["rounds"] = max(len(rounds), 1)
    signer_of = {r.get("round"): r.get("signer", "") for r in rounds if isinstance(r, dict)}
    current = listed
    for r in rounds:
        if not isinstance(r, dict) or not r.get("prev_seal_sha256"):
            continue
        n = r.get("round", 0) - 1
        arch = os.path.join(pkg, "seals", "SHA256SUMS.%d" % n)
        if not os.path.exists(arch):
            res.problems.append("round %d replaced a seal that is not archived as seals/SHA256SUMS.%d" % (n + 1, n))
            continue
        res.counts["archived_seals"] += 1
        if sha256_file(arch) != r["prev_seal_sha256"]:
            res.problems.append("seals/SHA256SUMS.%d is not the seal round %d recorded as replaced" % (n, n + 1))
            continue
        old = parse_sums(read_small(arch), "seals/SHA256SUMS.%d" % n, res.problems)
        for rel, digest in old.items():
            if rel.startswith("raw/") and current.get(rel) != digest:
                res.problems.append("%s: sealed by round %d, changed or dropped since" % (rel, n))
        asig = os.path.join(pkg, "seals", "SEAL.sig.%d" % n)
        if os.path.exists(asig):
            present, valid, _, reason = check_sig(asig, arch, "")
            if not valid:
                if signer_of.get(n):
                    res.problems.append("seals/SEAL.sig.%d: %s" % (n, reason))
                else:
                    res.notes.append("seals/SEAL.sig.%d does not verify (%s); no round recorded a signer for it, so it predates signed rounds and is not trusted" % (n, reason))

    # 5. signature
    present, valid, pub, reason = check_sig(os.path.join(pkg, "SEAL.sig"), sums_path, pubkey)
    last_signer = ""
    if rounds and isinstance(rounds[-1], dict):
        last_signer = rounds[-1].get("signer", "") or ""
    if present and valid:
        res.signature = "valid (ed25519, key %s)" % pub[:16]
        if last_signer and last_signer != pub and not pubkey:
            res.notes.append("SEAL.sig is by key %s, not the key %s the last round recorded (re-signed; pin --pubkey to require the recorded key)" % (pub[:16], last_signer[:16]))
    elif present:
        res.signature = "INVALID"
        res.problems.append("SEAL.sig: %s" % reason)
    elif pubkey:
        res.problems.append("SEAL.sig: missing, but a signer key was pinned")
    elif case is None:
        res.problems.append("SEAL.sig: missing, and case.json is unreadable, so whether the package was signed cannot be determined")
    elif last_signer:
        res.problems.append("SEAL.sig: missing, but the last round was sealed for key %s" % last_signer[:16])
    return res


# --------------------------------------------------------------- 0.2.2: analysis files

MAX_OVERLAY = 1 << 30  # decompressed bound for an overlay file
STATES = {"", "REQUESTED", "REPORTED", "OBSERVED", "PARTIALLY_CORROBORATED", "CORROBORATED", "CONTRADICTED", "UNKNOWN"}
FINDINGS_ALGORITHM = "adfir-findings-sha256/1"
MANIFEST_SCHEMA = "agentdfir.analysis-manifest/1"


def read_overlay(pkg, rel):
    """An overlay file in either form (<name>.gz preferred), or None."""
    path = os.path.join(pkg, *rel.split("/"))
    if os.path.exists(path + ".gz"):
        stored = read_small(path + ".gz")
        d = zlib.decompressobj(16 + zlib.MAX_WBITS)
        out = d.decompress(stored, MAX_OVERLAY + 1)
        if len(out) > MAX_OVERLAY or not d.eof:
            raise ValueError("%s.gz: over the decompression bound or truncated" % rel)
        return out
    if os.path.exists(path):
        return read_small(path)
    return None


def _ns(b):
    return str(len(b)).encode() + b":" + b + b","


def findings_fingerprint(findings):
    """adfir-findings-sha256/1 (spec 0.2.2): per finding, a netstring of
    rule_id, severity, status, endpoint_corroboration, session_id and
    agent_id, then of the number of evidence_refs, then of each reference
    sorted bytewise; entries sorted bytewise, each hashed as a netstring."""
    entries = []
    for f in findings:
        if not isinstance(f, dict):
            raise ValueError("a finding is not an object")
        e = b"".join(_ns(str(f.get(k) or "").encode("utf-8")) for k in
                     ("rule_id", "severity", "status", "endpoint_corroboration", "session_id", "agent_id"))
        refs = sorted((r.encode("utf-8") for r in (f.get("evidence_refs") or [])))
        e += _ns(str(len(refs)).encode()) + b"".join(_ns(r) for r in refs)
        entries.append(e)
    h = hashlib.sha256()
    for e in sorted(entries):
        h.update(_ns(e))
    return "sha256:" + h.hexdigest()


def check_analysis_manifest(man_bytes, findings_bytes, seal_sha, problems, notes):
    P = lambda m: problems.append("analysis-manifest.json: " + m)
    try:
        m = json.loads(man_bytes)
    except ValueError as e:
        P("not JSON: %s" % e)
        return
    if not isinstance(m, dict):
        P("not an object")
        return
    if m.get("schema") != MANIFEST_SCHEMA:
        P("schema %r, want %r" % (m.get("schema"), MANIFEST_SCHEMA))
    for k in ("adfir_spec", "analyzed_utc", "findings_fingerprint"):
        if not isinstance(m.get(k), str):
            P("missing string %s" % k)
    tool = m.get("tool")
    if not isinstance(tool, dict):
        P("missing object tool")
    else:
        for k in ("name", "version", "analysis_fingerprint"):
            if not tool.get(k):
                P("tool.%s missing" % k)
    rs = m.get("rule_set")
    if not isinstance(rs, dict):
        P("missing object rule_set")
    else:
        if not rs.get("builtin_fingerprint"):
            P("rule_set.builtin_fingerprint missing")
        if not isinstance(rs.get("packs"), list):
            P("rule_set.packs is not an array")
        else:
            for i, p in enumerate(rs["packs"]):
                if not isinstance(p, dict):
                    P("rule_set.packs[%d] is not an object" % i)
                elif p.get("sha256") and not is_hex64(p["sha256"]):
                    P("rule_set.packs[%d].sha256 is not a SHA-256" % i)
    inp = m.get("input")
    if not isinstance(inp, dict):
        P("missing object input")
    if not isinstance(m.get("options"), dict):
        P("missing object options")
    fs = m.get("findings")
    if not isinstance(fs, dict):
        P("missing object findings")
        return
    fp = m.get("findings_fingerprint") or ""
    if not re.match(r"^sha256:[0-9a-f]{64}$", fp):
        P("findings_fingerprint %r is not sha256:<64 hex>" % fp)
    if fs.get("algorithm") != FINDINGS_ALGORITHM:
        P("findings.algorithm %r is not one this verifier implements" % fs.get("algorithm"))
        return
    if findings_bytes is None:
        P("detections/findings.json is missing, so the fingerprint cannot be checked")
        return
    try:
        findings = json.loads(findings_bytes)
        if findings is None:
            findings = []
        if not isinstance(findings, list):
            raise ValueError("not an array")
        got = findings_fingerprint(findings)
    except ValueError as e:
        P("detections/findings.json is not an array of findings: %s" % e)
        return
    if fs.get("count") != len(findings):
        P("findings.count %r, but findings.json holds %d" % (fs.get("count"), len(findings)))
    if got != fp:
        P("findings_fingerprint %s does not match detections/findings.json (recomputed %s)" % (fp, got))
    if seal_sha and isinstance(inp, dict) and inp.get("seal_sha256") != seal_sha:
        notes.append("analysis-manifest.json: made on a different seal than the package carries now (a later round)")


def _spec_at_least(have, want):
    def parts(v):
        out = []
        for x in v.split("."):
            try:
                out.append(int(x))
            except ValueError:
                out.append(0)
        return out
    h, w = parts(have), parts(want)
    h += [0] * (len(w) - len(h))
    return h[:len(w)] >= w


def check_action_graph(data, problems, notes):
    P = lambda m: problems.append("lineage.json: " + m)
    try:
        g = json.loads(data)
    except ValueError as e:
        P("not JSON: %s" % e)
        return
    if not isinstance(g, dict):
        P("not an object")
        return
    if not str(g.get("schema", "")).startswith("agentdfir.lineage/"):
        P("schema %r is not agentdfir.lineage/*" % g.get("schema"))
    strict = isinstance(g.get("adfir_spec"), str) and _spec_at_least(g["adfir_spec"], "0.2.2")
    nodes, edges = g.get("nodes"), g.get("edges")
    if not isinstance(nodes, list) or not isinstance(edges, list):
        P("nodes or edges is not an array")
        return
    ids = set()
    for i, n in enumerate(nodes):
        if not isinstance(n, dict) or not isinstance(n.get("id"), str) or not n["id"]:
            P("nodes[%d] has no id" % i)
            continue
        if n["id"] in ids:
            P("node %r is listed twice" % n["id"])
        ids.add(n["id"])
        if not n.get("kind"):
            P("node %r has no kind" % n["id"])
        if n.get("evidence_state", "") not in STATES:
            P("node %r has evidence_state %r" % (n["id"], n.get("evidence_state")))
    bad_edges = 0
    for i, e in enumerate(edges):
        if bad_edges >= 50:
            P("more problems in edges not listed")
            break
        before = len(problems)
        if not isinstance(e, dict):
            P("edges[%d] is not an object" % i)
            bad_edges += 1
            continue
        label = "edge %d (%s -> %s)" % (i, e.get("from"), e.get("to"))
        for end in ("from", "to"):
            if e.get(end) not in ids:
                P("%s: %s-node %r is not in the graph" % (label, end, e.get(end)))
        if not e.get("relation"):
            P("%s: no relation" % label)
        if not isinstance(e.get("basis"), str):
            P("%s: no basis" % label)
        state = e.get("evidence_state", "")
        if state not in STATES:
            P("%s: evidence_state %r" % (label, state))
        refs = e.get("source_refs")
        if not isinstance(refs, list) or not refs:
            P("%s: no source reference" % label)
            refs = []
        telemetry = record = False
        for j, r in enumerate(refs):
            if not isinstance(r, dict):
                P("%s: source_refs[%d] is not an object" % (label, j))
                continue
            if not (r.get("telemetry_ref") or r.get("artifact_id") or r.get("event_id")):
                P("%s: source_refs[%d] names no artifact, event or telemetry record" % (label, j))
            telemetry = telemetry or bool(r.get("telemetry_ref"))
            record = record or bool(r.get("artifact_id") or r.get("event_id"))
        lim = e.get("limitations")
        if lim is not None and (not isinstance(lim, list) or not all(isinstance(x, str) for x in lim)):
            P("%s: limitations is not an array of strings" % label)
        if "confidence" in e and not (telemetry and record):
            P("%s: a correlated edge must cite both the agent record and the telemetry record" % label)
        if strict and state == "CORROBORATED" and not telemetry and not lim:
            P("%s: CORROBORATED with no telemetry reference and no limitation saying why" % label)
        if len(problems) > before:
            bad_edges += 1
    if not strict:
        notes.append("lineage.json does not declare adfir_spec 0.2.2; the per-edge CORROBORATED rule was not applied")


STIX_ID = re.compile(r"^([a-z0-9][a-z0-9-]*[a-z0-9])--[0-9a-f]{8}-[0-9a-f]{4}-[1-8][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$")
STIX_TS = re.compile(r"^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(\.\d+)?Z$")
STIX_SDO = {"identity": ["name"], "indicator": ["pattern", "pattern_type", "valid_from"], "note": ["content", "object_refs"],
            "report": ["name", "published", "object_refs"],
            "observed-data": ["first_observed", "last_observed", "number_observed", "object_refs"],
            "relationship": ["relationship_type", "source_ref", "target_ref"], "sighting": ["sighting_of_ref"],
            "attack-pattern": ["name"]}
STIX_SCO = {"domain-name": ["value"], "ipv4-addr": ["value"], "ipv6-addr": ["value"], "url": ["value"], "file": []}
# uuid5(uuid5(NAMESPACE_URL, "https://efij.github.io/AgentDFIR/stix"), "identity|agentdfir")
STIX_TOOL_IDENTITY_NAME = "identity|agentdfir"
STIX_NAMESPACE_URL = "https://efij.github.io/AgentDFIR/stix"


def stix_tool_identity():
    import uuid
    return "identity--" + str(uuid.uuid5(uuid.uuid5(uuid.NAMESPACE_URL, STIX_NAMESPACE_URL), STIX_TOOL_IDENTITY_NAME))


def _ts_key(s):
    # Comparable form of a STIX timestamp: seconds, then the fraction.
    main, _, frac = s[:-1].partition(".")
    return main, frac.ljust(9, "0")


def check_stix(data, problems, notes):
    P = lambda m: problems.append("STIX: " + m)
    try:
        b = json.loads(data)
    except ValueError as e:
        P("not JSON: %s" % e)
        return
    if not isinstance(b, dict):
        P("not an object")
        return
    if b.get("type") != "bundle":
        P("type %r, want bundle" % b.get("type"))
    if not (isinstance(b.get("id"), str) and STIX_ID.match(b["id"]) and b["id"].startswith("bundle--")):
        P("bundle id %r is not bundle--<uuid>" % b.get("id"))
    objs = b.get("objects")
    if not isinstance(objs, list):
        P("objects is not an array")
        return
    ids, refs, unknown = set(), [], {}
    for i, o in enumerate(objs):
        if not isinstance(o, dict):
            P("objects[%d] is not an object" % i)
            continue
        typ, oid = o.get("type"), o.get("id")
        label = "objects[%d] (%s)" % (i, oid)
        if not isinstance(typ, str) or not re.match(r"^[a-z0-9][a-z0-9-]{1,248}[a-z0-9]$", typ):
            P("%s: type %r is not a STIX type name" % (label, typ))
            continue
        m = STIX_ID.match(oid) if isinstance(oid, str) else None
        if not m or m.group(1) != typ:
            P("%s: id is not %s--<uuid>" % (label, typ))
        if oid in ids:
            P("%s: id used twice" % label)
        ids.add(oid)
        if o.get("spec_version") != "2.1":
            P("%s: spec_version %r, want 2.1" % (label, o.get("spec_version")))
        if typ in STIX_SDO:
            c, mo = o.get("created"), o.get("modified")
            for k, v in (("created", c), ("modified", mo)):
                if not (isinstance(v, str) and STIX_TS.match(v)):
                    P("%s: %s %r is not a STIX timestamp" % (label, k, v))
            if isinstance(c, str) and isinstance(mo, str) and STIX_TS.match(c) and STIX_TS.match(mo) and _ts_key(mo) < _ts_key(c):
                P("%s: modified is before created" % label)
            for k in STIX_SDO[typ]:
                if k not in o:
                    P("%s: missing required property %s" % (label, k))
        elif typ in STIX_SCO:
            for k in STIX_SCO[typ]:
                if not o.get(k):
                    P("%s: missing required property %s" % (label, k))
            if typ == "file" and not o.get("hashes") and not o.get("name"):
                P("%s: a file needs hashes or name" % label)
        else:
            unknown[typ] = unknown.get(typ, 0) + 1
        for k in ("created", "modified", "valid_from", "valid_until", "published", "first_observed", "last_observed"):
            if k in o and not (isinstance(o[k], str) and STIX_TS.match(o[k])):
                P("%s: %s %r is not a STIX timestamp" % (label, k, o[k]))
        if typ == "observed-data":
            n = o.get("number_observed")
            if not isinstance(n, int) or isinstance(n, bool) or not 1 <= n <= 999999999:
                P("%s: number_observed %r is not in 1..999999999" % (label, n))
            fo, lo = o.get("first_observed"), o.get("last_observed")
            if isinstance(fo, str) and isinstance(lo, str) and STIX_TS.match(fo) and STIX_TS.match(lo) and _ts_key(lo) < _ts_key(fo):
                P("%s: last_observed is before first_observed" % label)
        if typ == "indicator" and o.get("pattern_type") == "stix":
            pat = o.get("pattern") or ""
            if not (pat.startswith("[") and pat.endswith("]")):
                P("%s: a stix pattern must be [ ... ]" % label)
        if "external_references" in o:
            er = o["external_references"]
            if not isinstance(er, list):
                P("%s: external_references is not an array" % label)
            else:
                for j, x in enumerate(er):
                    if not isinstance(x, dict) or not x.get("source_name"):
                        P("%s: external_references[%d] has no source_name" % (label, j))
        for k in sorted(o):
            if k.endswith("_ref"):
                refs.append((oid, k, o[k]))
            elif k.endswith("_refs"):
                if not isinstance(o[k], list):
                    P("%s: %s is not an array" % (label, k))
                    continue
                if k == "object_refs" and not o[k]:
                    P("%s: object_refs is empty" % label)
                for x in o[k]:
                    refs.append((oid, k, x))
    for src, prop, to in refs:
        if not (isinstance(to, str) and STIX_ID.match(to)):
            P("%s: %s %r is not a STIX id" % (src, prop, to))
        elif to not in ids:
            P("%s: %s %s does not resolve inside the bundle" % (src, prop, to))
    for t in sorted(unknown):
        notes.append("STIX: %d object(s) of type %s not checked beyond id and spec_version" % (unknown[t], t))


def check_overlay(pkg, res, stix_file=None):
    """The 0.2.2 analysis files, when present. Problems go to
    res.analysis_problems; what was checked to res.analysis_checked."""
    seal = ""
    try:
        seal = sha256_file(os.path.join(pkg, "SHA256SUMS"))
    except OSError:
        pass
    try:
        man = read_overlay(pkg, "detections/analysis-manifest.json")
        if man is not None:
            res.analysis_checked.append("detections/analysis-manifest.json")
            check_analysis_manifest(man, read_overlay(pkg, "detections/findings.json"), seal, res.analysis_problems, res.notes)
    except (OSError, ValueError) as e:
        res.analysis_problems.append("analysis-manifest.json: unreadable: %s" % e)
    try:
        g = read_overlay(pkg, "normalized/lineage.json")
        if g is not None:
            res.analysis_checked.append("normalized/lineage.json")
            check_action_graph(g, res.analysis_problems, res.notes)
    except (OSError, ValueError) as e:
        res.analysis_problems.append("lineage.json: unreadable: %s" % e)
    try:
        if stix_file:
            res.analysis_checked.append(stix_file)
            check_stix(read_small(stix_file), res.analysis_problems, res.notes)
        else:
            s = read_overlay(pkg, "reports/findings.stix.json")
            if s is not None:
                if stix_tool_identity().encode() not in s:
                    res.notes.append("reports/findings.stix.json predates 0.2.2 (no AgentDFIR tool identity); not checked (use --stix to force)")
                else:
                    res.analysis_checked.append("reports/findings.stix.json")
                    check_stix(s, res.analysis_problems, res.notes)
    except (OSError, ValueError) as e:
        res.analysis_problems.append("STIX: unreadable: %s" % e)


# --------------------------------------------------------------- production sets

def verify_production(d, pubkey=""):
    """A production set: every file production-manifest.json lists hashes
    to its SHA-256 and size, nothing else is present, and
    production-manifest.json.sig (when present) is an ed25519 signature
    over the manifest's SHA-256."""
    res = Result()
    res.counts = {"files_checked": 0}
    mp = os.path.join(d, "production-manifest.json")
    try:
        m = json.loads(read_small(mp))
    except (OSError, ValueError) as e:
        raise SystemExit("cannot read production-manifest.json: %s" % e)
    if m.get("schema") != "agentdfir.production/1":
        res.problems.append("production-manifest.json: schema %r" % m.get("schema"))
    listed = {"production-manifest.json", "production-manifest.csv", "production-manifest.json.sig"}
    for f in m.get("files") or []:
        rel = f.get("path", "") if isinstance(f, dict) else ""
        if not safe_rel(rel):
            res.problems.append("%r: path outside the production" % rel)
            continue
        if rel in listed:
            res.problems.append("%s: listed twice" % rel)
        listed.add(rel)
        path = os.path.join(d, *rel.split("/"))
        try:
            got, size = sha256_file(path), os.path.getsize(path)
        except OSError:
            res.problems.append("%s: listed but unreadable or missing" % rel)
            continue
        res.counts["files_checked"] += 1
        if got != f.get("sha256") or size != f.get("size"):
            res.problems.append("%s: does not match the manifest" % rel)
    for root, _, files in os.walk(d):
        for name in sorted(files):
            rel = os.path.relpath(os.path.join(root, name), d).replace(os.sep, "/")
            if rel not in listed:
                res.problems.append("%s: present but not listed in the manifest" % rel)
    sp = mp + ".sig"
    if os.path.exists(sp):
        f = parse_sig(read_small(sp))
        try:
            sig, pub = bytes.fromhex(f.get("signature", "")), bytes.fromhex(f.get("public_key", ""))
        except ValueError:
            sig, pub = b"", b""
        digest = hashlib.sha256(read_small(mp)).digest()
        if f.get("algorithm", "ed25519") != "ed25519" or len(sig) != 64 or len(pub) != 32:
            res.signature = "INVALID"
            res.problems.append("production-manifest.json.sig: malformed")
        elif pubkey and pubkey.lower() != pub.hex():
            res.signature = "INVALID"
            res.problems.append("production-manifest.json.sig: not by the pinned key")
        elif f.get("file_sha256") and f["file_sha256"] != digest.hex():
            res.signature = "INVALID"
            res.problems.append("production-manifest.json.sig: file_sha256 does not match the manifest")
        elif not ed25519_verify(pub, digest, sig):
            res.signature = "INVALID"
            res.problems.append("production-manifest.json.sig: signature does not match the manifest")
        else:
            res.signature = "valid (ed25519, key %s)" % pub.hex()[:16]
    elif pubkey:
        res.problems.append("production-manifest.json.sig: missing, but a signer key was pinned")
    else:
        res.notes.append("the production is unsigned")
    return res


def main(argv=None):
    ap = argparse.ArgumentParser(description="Independent verifier for .adfir evidence packages (spec %s)." % SPEC_VERSION)
    ap.add_argument("package", help="package directory")
    ap.add_argument("--json", action="store_true", help="print a JSON result")
    ap.add_argument("--pubkey", default="", help="require SEAL.sig (or a production's signature) to be by this hex ed25519 public key")
    ap.add_argument("--stix", default="", help="also check this STIX 2.1 bundle (spec 0.2.2 shape)")
    ap.add_argument("--version", action="version", version="adfir-verify %s (spec %s)" % (__version__, SPEC_VERSION))
    args = ap.parse_args(argv)
    if not os.path.isdir(args.package):
        print("not a package directory: %s" % args.package, file=sys.stderr)
        return 2
    production = os.path.exists(os.path.join(args.package, "production-manifest.json")) and \
        not os.path.exists(os.path.join(args.package, "SHA256SUMS"))
    try:
        if production:
            res = verify_production(args.package, args.pubkey)
            if args.stix:
                res.analysis_checked.append(args.stix)
                check_stix(read_small(args.stix), res.analysis_problems, res.notes)
        else:
            res = verify(args.package, args.pubkey)
            check_overlay(args.package, res, args.stix or None)
    except SystemExit as e:
        print(str(e), file=sys.stderr)
        return 2
    integrity = "FAILED" if res.problems else "VERIFIED"
    analysis = "FAILED" if res.analysis_problems else ("VERIFIED" if res.analysis_checked else "NOT_PRESENT")
    all_problems = res.problems + res.analysis_problems
    verdict = "FAILED" if all_problems else "VERIFIED"
    if args.json:
        json.dump({"verifier": "adfir-verify %s" % __version__, "spec": SPEC_VERSION, "verdict": verdict,
                   "kind": "production" if production else "package",
                   "integrity_verdict": integrity, "analysis_verdict": analysis, "analysis_checked": res.analysis_checked,
                   "analysis_problems": res.analysis_problems,
                   "signature": res.signature, "counts": res.counts, "problems": all_problems, "notes": res.notes},
                  sys.stdout, indent=2, sort_keys=True)
        sys.stdout.write("\n")
    else:
        print("adfir-verify %s (spec %s): %s" % (__version__, SPEC_VERSION, args.package))
        for k in sorted(res.counts):
            print("  %-20s %d" % (k, res.counts[k]))
        print("  %-20s %s" % ("signature", res.signature))
        if res.analysis_checked:
            print("  %-20s %s (%s)" % ("analysis files", analysis, ", ".join(res.analysis_checked)))
        for n in res.notes:
            print("  note: %s" % n)
        if all_problems:
            print("FAILED -- %d problem(s):" % len(all_problems))
            for p in all_problems:
                print("  - %s" % p)
        else:
            print("VERIFIED -- no modifications detected")
    return 1 if all_problems else 0


if __name__ == "__main__":
    sys.exit(main())
