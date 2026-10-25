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

Usage: adfir_verify.py [--json] [--pubkey HEX] PACKAGE_DIR
Exit status: 0 verified, 1 problems found, 2 usage or unreadable package.
"""

import argparse
import hashlib
import json
import os
import sys
import zlib

__version__ = "1.0.0"
SPEC_VERSION = "0.2"

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


def main(argv=None):
    ap = argparse.ArgumentParser(description="Independent verifier for .adfir evidence packages (spec %s)." % SPEC_VERSION)
    ap.add_argument("package", help="package directory")
    ap.add_argument("--json", action="store_true", help="print a JSON result")
    ap.add_argument("--pubkey", default="", help="require SEAL.sig to be signed by this hex ed25519 public key")
    ap.add_argument("--version", action="version", version="adfir-verify %s (spec %s)" % (__version__, SPEC_VERSION))
    args = ap.parse_args(argv)
    if not os.path.isdir(args.package):
        print("not a package directory: %s" % args.package, file=sys.stderr)
        return 2
    try:
        res = verify(args.package, args.pubkey)
    except SystemExit as e:
        print(str(e), file=sys.stderr)
        return 2
    verdict = "FAILED" if res.problems else "VERIFIED"
    if args.json:
        json.dump({"verifier": "adfir-verify %s" % __version__, "spec": SPEC_VERSION, "verdict": verdict,
                   "signature": res.signature, "counts": res.counts, "problems": res.problems, "notes": res.notes},
                  sys.stdout, indent=2, sort_keys=True)
        sys.stdout.write("\n")
    else:
        print("adfir-verify %s (spec %s): %s" % (__version__, SPEC_VERSION, args.package))
        for k in sorted(res.counts):
            print("  %-20s %d" % (k, res.counts[k]))
        print("  %-20s %s" % ("signature", res.signature))
        for n in res.notes:
            print("  note: %s" % n)
        if res.problems:
            print("FAILED -- %d problem(s):" % len(res.problems))
            for p in res.problems:
                print("  - %s" % p)
        else:
            print("VERIFIED -- no modifications detected")
    return 1 if res.problems else 0


if __name__ == "__main__":
    sys.exit(main())
