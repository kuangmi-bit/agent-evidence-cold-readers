#!/usr/bin/env python3
"""Second wave of input_pic probes: the thin places in the text (member types the
contract never constrains, JCS numeric edge, surrogate escapes, directory-vs-file)."""
import base64
import copy
import json
import os
import shutil
import subprocess
import sys
from pathlib import Path

AEV = os.environ.get("AEV_REPO", "/tmp/aev")
sys.path.insert(0, os.path.join(AEV, "packaging"))
HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE))
sys.path.insert(0, str(HERE.parent))

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from agent_evidence_vectors.refundconnected import Admission, RunDir, Streams, case_ctx_store, jcs, judge_case, sha_hex
import seams  # reuse Ctx / run_mine / WORK

WORK = seams.WORK
KEY = "kid_probe_1"


def resign(c, att):
    return c.resign(att, KEY)


def re_prop(c, fn):
    p = c.prop()
    fn(p)
    c.put_prop(p)


def re_att(c, fn):
    p = c.prop()
    att = json.loads(p["evidence"][0]["payload"])
    out = fn(att)
    att = out if out is not None else att
    # rewrite payload with an explicit integer token for the JCS edge case
    if "_raw_payload" in att:
        raw = att.pop("_raw_payload")
        priv_key = None
        c.resign(att, KEY)  # signs JCS(att) and writes canonical payload
        p = c.prop()
        p["evidence"][0]["payload"] = raw
        c.put_prop(p)
        return
    resign(c, att)


if not (WORK / "cases" / "j01").exists():
    WORK.parent.mkdir(parents=True, exist_ok=True)
    shutil.copytree(seams.SRC, WORK)

rows = []


def case(name, fn):
    d = WORK / "cases" / name
    if d.exists():
        shutil.rmtree(d)
    shutil.copytree(WORK / "cases" / "j01", d)
    c = seams.Ctx(d)
    fn(c)
    mine = seams.run_mine(d)
    case_ctx_store.clear()
    run = RunDir(WORK)
    try:
        theirs = judge_case(run, name, Admission(run), Streams(run), None)["input_pic"]
    except Exception as e:  # noqa: BLE001
        theirs = "ERR:" + type(e).__name__ + ":" + str(e)[:60]
    rows.append((name, mine, theirs, "SAME" if mine == theirs else "**DIFF**"))


# m39 entry.id missing
case("m39-entry-id-missing", lambda c: re_prop(c, lambda p: p["evidence"][0].pop("id", None)))

# m40 entry.id not a string, provenance mirrors it
def m40(c):
    p = c.prop()
    e = p["evidence"][0]
    e["id"] = 12345
    att = json.loads(e["payload"])
    att["provenance_ids"] = [12345]
    c.put_prop(p)
    resign(c, att)
case("m40-entry-id-int", m40)

# m41 uppercase hex trusted key
def m41(c):
    t = c.trust()
    kid = c.prop()["evidence"][0]["key_id"]
    t["trusted_keys"][kid] = t["trusted_keys"][kid].upper()
    c.put_trust(t)
case("m41-pubkey-uppercase", m41)

# m42 negative zero amount
case("m42-amount-neg-zero", lambda c: re_prop(c, lambda p: p["action"]["args"].__setitem__("amount_minor", 0)))

# m43 proposal carries an extra member the layer does not read (refs refreshed)
def m43(c):
    p = c.prop()
    p["protocol"] = "pic/0.9"
    c.put_prop(p)
    v = c.ver()
    v["proposal_file_ref"] = "sha256:" + sha_hex(c.prop_p.read_bytes())
    c.put_ver(v)
case("m43-proposal-extra", m43)

# m44 expires_at is null (never type-checked at this layer)
def m44(c):
    p = c.prop()
    att = json.loads(p["evidence"][0]["payload"])
    att["expires_at"] = None
    c.put_prop(p)
    resign(c, att)
case("m44-expires-null", m44)

# m45 expires_at is a huge integer -> JCS / ES6 number formatting
def m45(c):
    p = c.prop()
    entry = p["evidence"][0]
    att = json.loads(entry["payload"])
    att["expires_at"] = 10 ** 21
    # rebuild the payload text with the integer token, then sign the canonical form
    c.resign(att, KEY)
    p = c.prop()
    txt = p["evidence"][0]["payload"].replace("1000000000000000000000", "1e21")
    # sign whatever form we are probing: JCS(att) is what the contract names
    priv = Ed25519PrivateKey.generate()
    pub = priv.public_key().public_bytes(
        encoding=serialization.Encoding.Raw, format=serialization.PublicFormat.Raw
    ).hex()
    t = c.trust()
    t["trusted_keys"][KEY] = pub
    c.put_trust(t)
    p = c.prop()
    e = p["evidence"][0]
    e["key_id"] = e["signer"] = KEY
    e["payload"] = txt
    e["signature"] = base64.b64encode(priv.sign(txt.encode())).decode()
    c.put_prop(p)
    v = c.ver()
    v["proposal_file_ref"] = "sha256:" + sha_hex(c.prop_p.read_bytes())
    v["pic_trust_file_ref"] = "sha256:" + sha_hex(c.trust_p.read_bytes())
    c.put_ver(v)
case("m45-expires-1e21", m45)

# m46 claim text with a quote + backslash in decision_id (canonical escaping)
def m46(c):
    p = c.prop()
    claims = copy.deepcopy(p["claims"])
    claim = json.loads(claims[0]["text"])
    claim["decision_id"] = 'a"b\\c'
    claims[0]["text"] = json.dumps(claim, separators=(",", ":"), sort_keys=True)
    c.resign_with_claims(KEY, claims)
case("m46-decision-id-escapes", m46)

# m47 lone surrogate escape in the claim text
def m47(c):
    p = c.prop()
    claims = copy.deepcopy(p["claims"])
    claim = json.loads(claims[0]["text"])
    claim["decision_id"] = "dec" + "\ud800"
    claims[0]["text"] = json.dumps(claim, separators=(",", ":"), sort_keys=True)
    c.resign_with_claims(KEY, claims)
case("m47-lone-surrogate", m47)

# m48 the eleventh file is a directory, not a file
def m48(c):
    p = c.d / "inputs/decision-evidence.json"
    p.unlink()
    p.mkdir()
case("m48-path-is-dir", m48)

# m49 trusted key entry as object with public_key plus extra members
def m49(c):
    t = c.trust()
    kid = c.prop()["evidence"][0]["key_id"]
    key = t["trusted_keys"][kid]
    t["trusted_keys"][kid] = {"public_key": key, "alg": "ed25519", "note": "extra"}
    c.put_trust(t)
case("m49-key-object-extra", m49)

# m50 result.evaluated_at absent type: null (never checked here)
def m50(c):
    v = c.ver()
    v["evaluated_at"] = None
    c.put_ver(v)
case("m50-evaluated-at-null", m50)

# m51 base64 signature with wrong padding ("AAA")
def m51(c):
    p = c.prop()
    p["evidence"][0]["signature"] = p["evidence"][0]["signature"].rstrip("=")
    c.put_prop(p)
case("m51-sig-no-padding", m51)

# m52 duplicate member inside the payload JSON text
def m52(c):
    p = c.prop()
    e = p["evidence"][0]
    e["payload"] = e["payload"].replace('{"alg"', '{"alg"', 1)
    e["payload"] = e["payload"][:-1] + ',"tool":"refund"}'
    c.put_prop(p)
case("m52-payload-dup-member", m52)

w = max(len(r[0]) for r in rows)
print(f'{"variant".ljust(w)}  {"cold read":44s} {"packaged":44s} flag')
for name, mine, theirs, flag in rows:
    print(f"{name.ljust(w)}  {mine:44s} {theirs:44s} {flag}")
d = [r for r in rows if r[3] == "**DIFF**"]
print(f"\n{len(rows)} variants, {len(d)} disagreements")
